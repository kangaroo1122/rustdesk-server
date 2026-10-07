mod rendezvous_server;
pub use rendezvous_server::*;
pub mod common;
mod database;
pub mod jwt;
mod peer;
mod version;

mod handshake;
mod signaling;
mod protocol {
    include!(concat!(env!("OUT_DIR"), "/server_protos/mod.rs"));
}

mod api_bridge;
