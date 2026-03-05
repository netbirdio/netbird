use serde::Serialize;
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub ip: String,
    pub pub_key: String,
    pub fqdn: String,
    pub conn_status: String,
    pub conn_status_update: String,
    pub relayed: bool,
    pub relay_address: String,
    pub latency_ms: f64,
    pub bytes_rx: i64,
    pub bytes_tx: i64,
    pub rosenpass_enabled: bool,
    pub networks: Vec<String>,
    pub last_handshake: String,
    pub local_ice_type: String,
    pub remote_ice_type: String,
    pub local_endpoint: String,
    pub remote_endpoint: String,
}

fn format_timestamp(ts: &Option<prost_types::Timestamp>) -> String {
    match ts {
        Some(t) => {
            // Simple RFC3339-like formatting
            let secs = t.seconds;
            let nanos = t.nanos;
            format!("{}:{}", secs, nanos)
        }
        None => String::new(),
    }
}

#[tauri::command]
pub async fn get_peers(state: State<'_, AppState>) -> Result<Vec<PeerInfo>, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .status(proto::StatusRequest {
            get_full_peer_status: true,
            should_run_probes: false,
            wait_for_ready: None,
        })
        .await
        .map_err(|e| format!("status rpc: {}", e))?
        .into_inner();

    let peers = match resp.full_status {
        Some(ref full) => &full.peers,
        None => return Ok(vec![]),
    };

    let result: Vec<PeerInfo> = peers
        .iter()
        .map(|p| {
            let latency_ms = p
                .latency
                .as_ref()
                .map(|d| d.seconds as f64 * 1000.0 + d.nanos as f64 / 1_000_000.0)
                .unwrap_or(0.0);

            PeerInfo {
                ip: p.ip.clone(),
                pub_key: p.pub_key.clone(),
                fqdn: p.fqdn.clone(),
                conn_status: p.conn_status.clone(),
                conn_status_update: format_timestamp(&p.conn_status_update),
                relayed: p.relayed,
                relay_address: p.relay_address.clone(),
                latency_ms,
                bytes_rx: p.bytes_rx,
                bytes_tx: p.bytes_tx,
                rosenpass_enabled: p.rosenpass_enabled,
                networks: p.networks.clone(),
                last_handshake: format_timestamp(&p.last_wireguard_handshake),
                local_ice_type: p.local_ice_candidate_type.clone(),
                remote_ice_type: p.remote_ice_candidate_type.clone(),
                local_endpoint: p.local_ice_candidate_endpoint.clone(),
                remote_endpoint: p.remote_ice_candidate_endpoint.clone(),
            }
        })
        .collect();

    Ok(result)
}
