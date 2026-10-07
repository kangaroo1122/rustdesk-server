use crate::common::*;
use crate::database;
use crate::protocol::rendezvous::*;
use hbb_common::{
    bytes::Bytes,
    log,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

const REGISTRY_RECENT_SECONDS: u64 = 30;

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Debug, Serialize)]
pub(crate) struct RegistryPeerView {
    pub(crate) id: String,
    pub(crate) guid: String,
    pub(crate) uuid: String,
    pub(crate) public_key: Option<String>,
    pub(crate) public_key_fingerprint: String,
    pub(crate) register_ip: String,
    pub(crate) created_at: String,
    pub(crate) status: Option<i64>,
    pub(crate) note: Option<String>,
    pub(crate) in_memory: bool,
    pub(crate) registered_recently: bool,
    pub(crate) last_register_seconds: Option<u64>,
    pub(crate) memory_socket_addr: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistryPeerList {
    pub(crate) total: u64,
    pub(crate) page: u32,
    pub(crate) page_size: u32,
    pub(crate) list: Vec<RegistryPeerView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegistryStats {
    pub(crate) total: u64,
    pub(crate) in_memory: u64,
    pub(crate) registered_recently: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistryDeleteError {
    NotFound,
    IdentityMismatch,
    RecentlyActive,
    Database,
}

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    change_id_lock: Arc<Mutex<()>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    #[cfg(test)]
    pub(crate) fn with_database(db: database::Database) -> Self {
        Self {
            map: Default::default(),
            change_id_lock: Default::default(),
            db,
        }
    }

    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            change_id_lock: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        let _guard = self.change_id_lock.lock().await;
        // Recheck after admission/network waits and serialize with rename/delete.
        let current = self.map.read().await.get(&id).cloned();
        if !current.is_some_and(|current| Arc::ptr_eq(&current, &peer)) {
            return register_pk_response::Result::UUID_MISMATCH;
        }
        let (mut info, mut guid) = {
            let r = peer.read().await;
            if !r.uuid.is_empty() && (r.uuid != uuid || (r.info.ip != ip && r.pk != pk)) {
                return register_pk_response::Result::UUID_MISMATCH;
            }
            (r.info.clone(), r.guid.clone())
        };
        info.ip = ip;
        let info_str = serde_json::to_string(&info).unwrap_or_default();
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Ok(value) => guid = value,
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
            }
        } else if let Err(err) = self.db.update_pk(&guid, &pk, &info_str).await {
            log::error!("db.update_pk failed: {}", err);
            return register_pk_response::Result::SERVER_ERROR;
        }
        // Publish only persisted identities; a failed write must never register an online peer.
        let mut w = peer.write().await;
        w.guid = guid;
        w.socket_addr = addr;
        w.uuid = uuid;
        w.pk = pk;
        w.last_reg_time = Instant::now();
        w.info = info;
        register_pk_response::Result::OK
    }

    pub(crate) async fn change_id(
        &self,
        old_id: &str,
        new_id: &str,
        uuid: &[u8],
    ) -> register_pk_response::Result {
        let _guard = self.change_id_lock.lock().await;

        let old = match self.db.get_peer(old_id).await {
            Ok(Some(peer)) => peer,
            Ok(None) => {
                return match self.db.get_peer(new_id).await {
                    Ok(Some(peer)) if peer.uuid == uuid => register_pk_response::Result::OK,
                    Ok(Some(_)) => register_pk_response::Result::ID_EXISTS,
                    Ok(None) => register_pk_response::Result::UUID_MISMATCH,
                    Err(err) => {
                        log::error!("db.get_peer failed while retrying id change: {}", err);
                        register_pk_response::Result::SERVER_ERROR
                    }
                };
            }
            Err(err) => {
                log::error!("db.get_peer failed while changing id: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
        };
        if old.uuid != uuid {
            return register_pk_response::Result::UUID_MISMATCH;
        }
        if old_id == new_id {
            return register_pk_response::Result::OK;
        }

        match self.db.get_peer(new_id).await {
            Ok(Some(_)) => return register_pk_response::Result::ID_EXISTS,
            Ok(None) => {}
            Err(err) => {
                log::error!("db.get_peer failed while checking new id: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
        }
        if self.map.read().await.contains_key(new_id) {
            return register_pk_response::Result::ID_EXISTS;
        }

        match self.db.change_id(&old.guid, old_id, new_id).await {
            Ok(true) => {}
            Ok(false) => return register_pk_response::Result::UUID_MISMATCH,
            Err(err) => {
                if matches!(self.db.get_peer(new_id).await, Ok(Some(_))) {
                    return register_pk_response::Result::ID_EXISTS;
                }
                log::error!("db.change_id failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
        }

        let mut map = self.map.write().await;
        let peer = map.remove(old_id).unwrap_or_else(|| {
            Arc::new(RwLock::new(Peer {
                guid: old.guid,
                uuid: old.uuid.into(),
                pk: old.pk.into(),
                info: serde_json::from_str::<PeerInfo>(&old.info).unwrap_or_default(),
                ..Default::default()
            }))
        });
        map.insert(new_id.to_owned(), peer);
        log::info!("Peer id changed from {} to {}", old_id, new_id);
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        }
        let _guard = self.change_id_lock.lock().await;
        if let Some(peer) = self.map.read().await.get(id).cloned() {
            return Some(peer);
        }
        if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    pub(crate) async fn update_registration_addr(
        &self,
        id: &str,
        socket_addr: SocketAddr,
    ) -> (bool, Option<String>) {
        let _guard = self.change_id_lock.lock().await;
        let Some(old) = self.map.read().await.get(id).cloned() else {
            return (true, None);
        };
        let mut old = old.write().await;
        let ip = socket_addr.ip();
        let ip_change = if old.socket_addr.port() != 0 {
            ip != old.socket_addr.ip()
        } else {
            ip.to_string() != old.info.ip
        } && !ip.is_loopback();
        let request_pk = old.pk.is_empty() || ip_change;
        if !request_pk {
            old.socket_addr = socket_addr;
            old.last_reg_time = Instant::now();
        }
        let old_addr = if ip_change && old.reg_pk.0 <= 2 {
            Some(if old.socket_addr.port() == 0 {
                old.info.ip.clone()
            } else {
                old.socket_addr.to_string()
            })
        } else {
            None
        };
        (request_pk, old_addr)
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    pub(crate) async fn list_registry_peers(
        &self,
        page: u32,
        page_size: u32,
        keyword: &str,
    ) -> ResultType<RegistryPeerList> {
        let total = self.db.count_registry_peers(keyword).await?;
        let records = self
            .db
            .list_registry_peers(page, page_size, keyword)
            .await?;
        let mut list = Vec::with_capacity(records.len());
        for record in records {
            list.push(self.registry_peer_view(record, false).await);
        }
        Ok(RegistryPeerList {
            total,
            page,
            page_size,
            list,
        })
    }

    pub(crate) async fn registry_peer_detail(
        &self,
        id: &str,
    ) -> ResultType<Option<RegistryPeerView>> {
        match self.db.get_registry_peer(id).await? {
            Some(record) => Ok(Some(self.registry_peer_view(record, true).await)),
            None => Ok(None),
        }
    }

    pub(crate) async fn registry_stats(&self) -> ResultType<RegistryStats> {
        let total = self.db.count_registry_peers("").await?;
        let peers: Vec<LockPeer> = self.map.read().await.values().cloned().collect();
        let mut registered_recently = 0;
        for peer in &peers {
            if peer.read().await.last_reg_time.elapsed().as_secs() < REGISTRY_RECENT_SECONDS {
                registered_recently += 1;
            }
        }
        Ok(RegistryStats {
            total,
            in_memory: peers.len() as u64,
            registered_recently,
        })
    }

    pub(crate) async fn delete_registry_peer(
        &self,
        id: &str,
        uuid: &[u8],
        public_key_fingerprint: &str,
        force: bool,
    ) -> Result<(), RegistryDeleteError> {
        let _guard = self.change_id_lock.lock().await;
        let record = self
            .db
            .get_registry_peer(id)
            .await
            .map_err(|err| {
                log::error!("db.get_registry_peer failed while deleting {id}: {err}");
                RegistryDeleteError::Database
            })?
            .ok_or(RegistryDeleteError::NotFound)?;
        if record.uuid != uuid || public_key_fingerprint_of(&record.pk) != public_key_fingerprint {
            return Err(RegistryDeleteError::IdentityMismatch);
        }
        if !force {
            if let Some(peer) = self.map.read().await.get(id).cloned() {
                if peer.read().await.last_reg_time.elapsed().as_secs() < REGISTRY_RECENT_SECONDS {
                    return Err(RegistryDeleteError::RecentlyActive);
                }
            }
        }
        let deleted = self
            .db
            .delete_registry_peer(&record.guid, id, &record.uuid, &record.pk)
            .await
            .map_err(|err| {
                log::error!("db.delete_registry_peer failed for {id}: {err}");
                RegistryDeleteError::Database
            })?;
        if !deleted {
            return Err(RegistryDeleteError::IdentityMismatch);
        }
        self.map.write().await.remove(id);
        log::info!("Peer {id} deleted from registry");
        Ok(())
    }

    async fn registry_peer_view(
        &self,
        record: database::RegistryPeer,
        include_public_key: bool,
    ) -> RegistryPeerView {
        let memory = self.map.read().await.get(&record.id).cloned();
        let (in_memory, registered_recently, last_register_seconds, memory_socket_addr) =
            if let Some(peer) = memory {
                let peer = peer.read().await;
                let seconds = peer.last_reg_time.elapsed().as_secs();
                let socket_addr =
                    (peer.socket_addr.port() != 0).then(|| peer.socket_addr.to_string());
                (
                    true,
                    seconds < REGISTRY_RECENT_SECONDS,
                    Some(seconds),
                    socket_addr,
                )
            } else {
                (false, false, None, None)
            };
        let info = serde_json::from_str::<PeerInfo>(&record.info).unwrap_or_default();
        RegistryPeerView {
            id: record.id,
            guid: base64::encode(record.guid),
            uuid: base64::encode(record.uuid),
            public_key: include_public_key.then(|| base64::encode(&record.pk)),
            public_key_fingerprint: public_key_fingerprint_of(&record.pk),
            register_ip: info.ip,
            created_at: sqlite_datetime_to_rfc3339(&record.created_at),
            status: record.status,
            note: record.note,
            in_memory,
            registered_recently,
            last_register_seconds,
            memory_socket_addr,
        }
    }
}

fn public_key_fingerprint_of(public_key: &[u8]) -> String {
    let digest = hbb_common::sodiumoxide::crypto::hash::sha256::hash(public_key);
    format!("SHA256:{}", base64::encode(digest.0).trim_end_matches('='))
}

fn sqlite_datetime_to_rfc3339(value: &str) -> String {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .map(|value| {
            value
                .and_utc()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    #[tokio::test]
    async fn concurrent_registration_persists_one_identity_and_failed_write_stays_offline() {
        let path = std::env::temp_dir().join(format!(
            "hbbs-registration-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = database::Database::new(path.to_str().unwrap())
            .await
            .unwrap();
        let mut pm = PeerMap::with_database(db);
        let peer = pm.get_or("race123").await;
        let mut other = pm.clone();
        let addr = "127.0.0.1:21116".parse().unwrap();
        let (a, b) = tokio::join!(
            pm.update_pk(
                "race123".into(),
                peer.clone(),
                addr,
                Bytes::from_static(b"uuid-a"),
                Bytes::from_static(b"key-a"),
                "127.0.0.1".into()
            ),
            other.update_pk(
                "race123".into(),
                peer.clone(),
                addr,
                Bytes::from_static(b"uuid-b"),
                Bytes::from_static(b"key-b"),
                "127.0.0.1".into()
            )
        );
        assert!(matches!(
            (a, b),
            (
                register_pk_response::Result::OK,
                register_pk_response::Result::UUID_MISMATCH
            ) | (
                register_pk_response::Result::UUID_MISMATCH,
                register_pk_response::Result::OK
            )
        ));
        let persisted = pm.db.get_peer("race123").await.unwrap().unwrap();
        assert_eq!(peer.read().await.uuid.as_ref(), persisted.uuid.as_slice());
        assert_eq!(peer.read().await.pk.as_ref(), persisted.pk.as_slice());
        let pending = pm.get_or("conflict123").await;
        pm.db
            .insert_peer("conflict123", b"owner", b"owner-key", "{}")
            .await
            .unwrap();
        assert_eq!(
            pm.update_pk(
                "conflict123".into(),
                pending.clone(),
                addr,
                Bytes::from_static(b"intruder"),
                Bytes::from_static(b"new-key"),
                "127.0.0.1".into()
            )
            .await,
            register_pk_response::Result::SERVER_ERROR
        );
        assert!(pending.read().await.uuid.is_empty());
        assert_eq!(pending.read().await.socket_addr.port(), 0);
        drop(peer);
        drop(pending);
        drop(pm);
        drop(other);
        let reopened = PeerMap::with_database(
            database::Database::new(path.to_str().unwrap())
                .await
                .unwrap(),
        );
        let peer = reopened.get("race123").await.unwrap();
        assert_eq!(peer.read().await.uuid.as_ref(), persisted.uuid.as_slice());
        assert!(!reopened.update_registration_addr("race123", addr).await.0);
        assert_eq!(peer.read().await.socket_addr, addr);
        assert_eq!(
            reopened
                .db
                .get_peer("conflict123")
                .await
                .unwrap()
                .unwrap()
                .uuid,
            b"owner"
        );
        drop(peer);
        drop(reopened);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn change_id_checks_identity_and_preserves_peer() {
        run_change_id_checks_identity_and_preserves_peer();
    }

    #[test]
    fn registry_lists_and_deletes_without_loading_peers() {
        run_registry_lists_and_deletes_without_loading_peers();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_change_id_checks_identity_and_preserves_peer() {
        let path =
            std::env::temp_dir().join(format!("rustdesk-server-{}.sqlite3", uuid::Uuid::new_v4()));
        let path_str = path.to_string_lossy().to_string();
        let db = database::Database::new(&path_str).await.unwrap();
        let uuid = b"device-uuid";
        let pk = b"device-public-key";
        db.insert_peer("123456789", uuid, pk, "{}").await.unwrap();
        db.insert_peer("taken-id", b"other-uuid", b"other-key", "{}")
            .await
            .unwrap();
        let pm = PeerMap {
            map: Default::default(),
            change_id_lock: Default::default(),
            db,
        };

        assert_eq!(
            pm.change_id("123456789", "macbook-pro", b"wrong-uuid")
                .await,
            register_pk_response::Result::UUID_MISMATCH
        );
        assert_eq!(
            pm.change_id("123456789", "taken-id", uuid).await,
            register_pk_response::Result::ID_EXISTS
        );

        let old_peer = pm.get("123456789").await.unwrap();
        old_peer.write().await.socket_addr = "127.0.0.1:21116".parse().unwrap();
        assert_eq!(
            pm.change_id("123456789", "macbook-pro", uuid).await,
            register_pk_response::Result::OK
        );
        assert!(pm.get_in_memory("123456789").await.is_none());
        let renamed_peer = pm.get_in_memory("macbook-pro").await.unwrap();
        assert!(Arc::ptr_eq(&old_peer, &renamed_peer));
        assert_eq!(
            renamed_peer.read().await.socket_addr,
            "127.0.0.1:21116".parse().unwrap()
        );

        let stored = pm.db.get_peer("macbook-pro").await.unwrap().unwrap();
        assert_eq!(stored.uuid, uuid);
        assert_eq!(stored.pk, pk);
        assert!(pm.db.get_peer("123456789").await.unwrap().is_none());
        assert_eq!(
            pm.change_id("123456789", "macbook-pro", uuid).await,
            register_pk_response::Result::OK
        );

        drop(renamed_peer);
        drop(old_peer);
        drop(pm);
        let reopened = database::Database::new(&path_str).await.unwrap();
        assert!(reopened.get_peer("123456789").await.unwrap().is_none());
        assert_eq!(
            reopened.get_peer("macbook-pro").await.unwrap().unwrap().pk,
            pk
        );
        drop(reopened);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::main(flavor = "current_thread")]
    async fn run_registry_lists_and_deletes_without_loading_peers() {
        let path = std::env::temp_dir().join(format!(
            "rustdesk-server-registry-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let path_str = path.to_string_lossy().to_string();
        let db = database::Database::new(&path_str).await.unwrap();
        let uuid = b"device-uuid";
        let pk = b"device-public-key";
        db.insert_peer("mac%book", uuid, pk, r#"{"ip":"192.0.2.10"}"#)
            .await
            .unwrap();
        db.insert_peer("other-device", b"other-uuid", b"other-key", "{}")
            .await
            .unwrap();
        let pm = PeerMap {
            map: Default::default(),
            change_id_lock: Default::default(),
            db,
        };

        let list = pm.list_registry_peers(1, 50, "%").await.unwrap();
        assert_eq!(list.total, 1);
        assert_eq!(list.list[0].id, "mac%book");
        assert_eq!(list.list[0].register_ip, "192.0.2.10");
        assert!(!list.list[0].in_memory);
        assert!(pm.map.read().await.is_empty());

        let detail = pm.registry_peer_detail("mac%book").await.unwrap().unwrap();
        assert_eq!(detail.public_key, Some(base64::encode(pk)));
        assert_eq!(detail.uuid, base64::encode(uuid));
        assert_eq!(
            pm.delete_registry_peer(
                "mac%book",
                b"wrong-uuid",
                &detail.public_key_fingerprint,
                true,
            )
            .await,
            Err(RegistryDeleteError::IdentityMismatch)
        );
        pm.delete_registry_peer("mac%book", uuid, &detail.public_key_fingerprint, true)
            .await
            .unwrap();
        assert!(pm.registry_peer_detail("mac%book").await.unwrap().is_none());
        assert!(pm.get("mac%book").await.is_none());

        drop(pm);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
