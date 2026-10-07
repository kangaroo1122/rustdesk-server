//! Server-side KX v0/v1, wire-compatible with the 1.5.0 client.
use crate::protocol::rendezvous::{KeyExchange, KxParams};
use hbb_common::{
    anyhow::anyhow,
    bail,
    bytes::Bytes,
    protobuf::Message,
    sodiumoxide::crypto::{box_, generichash, secretbox, sign},
    tcp::Encrypt,
    ResultType,
};

pub struct Handshake {
    pk: box_::PublicKey,
    sk: box_::SecretKey,
}

impl Handshake {
    pub fn new() -> Self {
        let (mut pk, sk) = box_::gen_keypair();
        // Signed marker: new clients require signed negotiation parameters. X25519 ignores it.
        pk.0[31] |= 0x80;
        Self { pk, sk }
    }

    pub fn offer(&self, signing_key: &sign::SecretKey) -> ResultType<KeyExchange> {
        let params = KxParams {
            pk: Bytes::copy_from_slice(&self.pk.0),
            version: 1,
            ..Default::default()
        };
        let mut signed = b"rdkx-params".to_vec();
        signed.extend(params.write_to_bytes()?);
        Ok(KeyExchange {
            keys: vec![sign::sign(&self.pk.0, signing_key).into()],
            version: 1,
            signed_params: sign::sign(&signed, signing_key).into(),
            ..Default::default()
        })
    }

    /// Independent send/receive counters must survive moving the sink into the routing table.
    pub fn accept(&self, response: &KeyExchange) -> ResultType<(Encrypt, Encrypt)> {
        if response.keys.len() != 2 || response.version > 1 {
            bail!("Invalid key exchange response");
        }
        let key = Encrypt::decode(&response.keys[1], &response.keys[0], &self.sk)?;
        if response.version == 0 {
            return Ok((Encrypt::new(key.clone()), Encrypt::new(key)));
        }
        let derive = |direction| derive_key(&key, direction, &response.keys[0], &self.pk.0);

        Ok((Encrypt::new(derive(2)?), Encrypt::new(derive(1)?)))
    }
}

fn derive_key(
    key: &secretbox::Key,
    direction: u8,
    initiator: &[u8],
    responder: &[u8],
) -> ResultType<secretbox::Key> {
    let mut hash = generichash::State::new(Some(32), Some(&key.0))
        .map_err(|_| anyhow!("Key derivation failed"))?;
    for part in [
        b"rdkx-spl".as_slice(),
        &[direction],
        &1_u32.to_le_bytes(),
        &1_u32.to_le_bytes(),
        initiator,
        responder,
    ] {
        hash.update(part)
            .map_err(|_| anyhow!("Key derivation failed"))?;
    }
    let digest = hash
        .finalize()
        .map_err(|_| anyhow!("Key derivation failed"))?;
    secretbox::Key::from_slice(digest.as_ref()).ok_or_else(|| anyhow!("Invalid derived key"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hbb_common::bytes::BytesMut;

    pub(crate) fn client_response(
        offer: &KeyExchange,
        signing_pk: &sign::PublicKey,
        version: u32,
    ) -> (KeyExchange, Encrypt, Encrypt) {
        let signed_pk = sign::verify(&offer.keys[0], signing_pk).unwrap();
        let pk = box_::PublicKey::from_slice(&signed_pk).unwrap();
        let signed = sign::verify(&offer.signed_params, signing_pk).unwrap();
        let params =
            KxParams::parse_from_bytes(signed.strip_prefix(b"rdkx-params").unwrap()).unwrap();
        assert_eq!(params.pk.as_ref(), signed_pk);
        assert_eq!(params.version, offer.version);
        let (client_pk, client_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(&key.0, &box_::Nonce([0; 24]), &pk, &client_sk);
        let (send, recv) = if version == 0 {
            (key.clone(), key.clone())
        } else {
            (
                derive_key(&key, 1, &client_pk.0, &signed_pk).unwrap(),
                derive_key(&key, 2, &client_pk.0, &signed_pk).unwrap(),
            )
        };
        (
            KeyExchange {
                keys: vec![client_pk.0.to_vec().into(), sealed.into()],
                version,
                ..Default::default()
            },
            Encrypt::new(send),
            Encrypt::new(recv),
        )
    }

    #[test]
    fn matches_upstream_150_wire_vectors() {
        let key = secretbox::Key([0x11; 32]);
        let hex = |bytes: &[u8]| hbb_common::sodiumoxide::hex::encode(bytes);
        assert_eq!(
            hex(&Encrypt::new(key.clone()).enc(b"hello")),
            "3b768f827fdcc4af555b9e42533be6611e2c333481"
        );
        assert_eq!(
            hex(&derive_key(&key, 1, &[0x22; 32], &[0x33; 32]).unwrap().0),
            "c189ec6e1935c0751cfc85a0f075405cae507d7925bb19687caf56cbb54e0ecf"
        );
        assert_eq!(
            hex(&derive_key(&key, 2, &[0x22; 32], &[0x33; 32]).unwrap().0),
            "8a62648e9195cb10ea900c0a24d2a166c1e982347a2dc6833c3e756bf5715d36"
        );
    }

    #[test]
    fn accepts_old_and_new_clients_rejects_malformed_handshakes() {
        let (pk, sk) = sign::gen_keypair();
        let handshake = Handshake::new();
        let offer = handshake.offer(&sk).unwrap();
        for version in [0, 1] {
            let (response, mut tx, mut rx) = client_response(&offer, &pk, version);
            let (mut server_tx, mut server_rx) = handshake.accept(&response).unwrap();
            let mut request = BytesMut::from(tx.enc(b"request").as_slice());
            server_rx.dec(&mut request).unwrap();
            assert_eq!(request.as_ref(), b"request");
            let mut response = BytesMut::from(server_tx.enc(b"response").as_slice());
            rx.dec(&mut response).unwrap();
            assert_eq!(response.as_ref(), b"response");
        }
        let (mut response, _, _) = client_response(&offer, &pk, 0);
        response.version = 2;
        assert!(handshake.accept(&response).is_err());
        response.version = 0;
        response.keys[0] = Bytes::from_static(b"short");
        assert!(handshake.accept(&response).is_err());
        response.keys.clear();
        assert!(handshake.accept(&response).is_err());
    }
}
