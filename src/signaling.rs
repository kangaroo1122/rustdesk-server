//! Bounded, short-lived ICE routes. Only an accepted punch request creates a route.
use hbb_common::{anyhow::anyhow, bail, ResultType};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

pub const MAX_SIGNAL_BYTES: usize = 64 * 1024;
const MAX_ROUTES: usize = 4096;
const MAX_CANDIDATES: usize = 256;
const ROUTE_TTL: Duration = Duration::from_secs(60);

pub fn offer_session(offer: &str) -> ResultType<String> {
    if offer.len() > 48 * 1024 {
        bail!("SDP offer too large");
    }
    let encoded = offer
        .strip_prefix("webrtc://")
        .ok_or_else(|| anyhow!("Invalid SDP envelope"))?;
    let value: serde_json::Value = serde_json::from_slice(&base64::decode(encoded)?)?;
    if value["type"] != "offer" {
        bail!("Expected SDP offer");
    }
    let sdp = value["sdp"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing SDP"))?;
    let key = sdp
        .lines()
        .find_map(|line| line.trim_end().strip_prefix("a=fingerprint:"))
        .filter(|key| !key.is_empty() && key.len() <= 256)
        .ok_or_else(|| anyhow!("Missing SDP fingerprint"))?;
    Ok(key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_bind_both_directions_and_expire() {
        let a = "127.0.0.1:1000".parse().unwrap();
        let b = "127.0.0.2:2000".parse().unwrap();
        let stranger = "127.0.0.3:3000".parse().unwrap();
        let mut routes = Routes::default();
        routes
            .insert(a, "peer".into(), b, "session".into())
            .unwrap();
        assert_eq!(
            routes.candidate(a, a, "peer", "session", "candidate"),
            Some(b)
        );
        assert_eq!(routes.candidate(b, a, "", "session", "candidate"), Some(a));
        assert_eq!(
            routes.candidate(a, a, "other", "session", "candidate"),
            None
        );
        assert_eq!(
            routes.candidate(stranger, a, "", "session", "candidate"),
            None
        );
        assert_eq!(routes.candidate(b, a, "", "wrong", "candidate"), None);
        for _ in 1..MAX_CANDIDATES {
            assert!(routes.candidate(b, a, "", "session", "candidate").is_some());
        }
        assert!(routes.candidate(b, a, "", "session", "candidate").is_none());
        routes.0.get_mut(&a).unwrap().created = Instant::now() - ROUTE_TTL;
        assert!(!routes.has(&a));
        assert!(!routes.answer_allowed(&a, b));
        assert!(routes
            .candidate(a, a, "peer", "session", "candidate")
            .is_none());
        routes.remove(&a);
        routes
            .insert(a, "peer".into(), b, "new-session".into())
            .unwrap();
        assert!(routes.candidate(b, a, "", "session", "candidate").is_none());
    }

    #[test]
    fn bounded_offer_envelope() {
        let offer = format!(
            "webrtc://{}",
            base64::encode(r#"{"type":"offer","sdp":"v=0\r\na=fingerprint:sha-256 AA:BB\r\n"}"#)
        );
        assert_eq!(offer_session(&offer).unwrap(), "sha-256 AA:BB");
        assert!(offer_session("webrtc://invalid").is_err());
        assert!(offer_session(&"x".repeat(49 * 1024)).is_err());
        assert!(offer_session(&format!(
            "webrtc://{}",
            base64::encode(r#"{"type":"answer","sdp":""}"#)
        ))
        .is_err());
    }
}

struct Route {
    peer_id: String,
    peer_addr: SocketAddr,
    session: String,
    created: Instant,
    counts: [usize; 2],
}

#[derive(Default)]
pub struct Routes(HashMap<SocketAddr, Route>);

impl Routes {
    pub fn insert(
        &mut self,
        controller: SocketAddr,
        peer_id: String,
        peer_addr: SocketAddr,
        session: String,
    ) -> ResultType<()> {
        self.0
            .retain(|_, route| route.created.elapsed() < ROUTE_TTL);
        if self.0.len() >= MAX_ROUTES
            || self.0.contains_key(&controller)
            || self
                .0
                .keys()
                .filter(|addr| addr.ip() == controller.ip())
                .count()
                >= 32
        {
            bail!("Signaling route limit or duplicate request");
        }
        self.0.insert(
            controller,
            Route {
                peer_id,
                peer_addr,
                session,
                created: Instant::now(),
                counts: [0, 0],
            },
        );
        Ok(())
    }

    pub fn remove(&mut self, controller: &SocketAddr) {
        self.0.remove(controller);
    }

    pub fn has(&self, controller: &SocketAddr) -> bool {
        self.0
            .get(controller)
            .is_some_and(|r| r.created.elapsed() < ROUTE_TTL)
    }

    pub fn answer_allowed(&self, controller: &SocketAddr, from: SocketAddr) -> bool {
        self.0
            .get(controller)
            .is_some_and(|r| r.created.elapsed() < ROUTE_TTL && r.peer_addr.ip() == from.ip())
    }

    pub fn candidate(
        &mut self,
        from: SocketAddr,
        controller: SocketAddr,
        id: &str,
        session: &str,
        candidate: &str,
    ) -> Option<SocketAddr> {
        if candidate.is_empty() || candidate.len() > 8192 || session.len() > 256 {
            return None;
        }
        let route = self.0.get_mut(&controller)?;
        if route.created.elapsed() >= ROUTE_TTL || session != route.session {
            return None;
        }
        let direction = if !id.is_empty() {
            if from != controller || id != route.peer_id {
                return None;
            }
            0
        } else {
            if from.ip() != route.peer_addr.ip() {
                return None;
            }
            1
        };
        if route.counts[direction] >= MAX_CANDIDATES {
            return None;
        }
        route.counts[direction] += 1;
        Some(if direction == 0 {
            route.peer_addr
        } else {
            controller
        })
    }
}
