use serde::Serialize;
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    pub status: String,
    pub ip: String,
    pub public_key: String,
    pub fqdn: String,
    pub connected_peers: usize,
}

#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<StatusInfo, String> {
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

    let mut info = StatusInfo {
        status: resp.status,
        ip: String::new(),
        public_key: String::new(),
        fqdn: String::new(),
        connected_peers: 0,
    };

    if let Some(ref full) = resp.full_status {
        if let Some(ref lp) = full.local_peer_state {
            info.ip = lp.ip.clone();
            info.public_key = lp.pub_key.clone();
            info.fqdn = lp.fqdn.clone();
        }
        info.connected_peers = full.peers.len();
    }

    Ok(info)
}

#[tauri::command]
pub async fn connect(state: State<'_, AppState>) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .up(proto::UpRequest {
            profile_name: None,
            username: None,
            auto_update: None,
        })
        .await
        .map_err(|e| format!("connect: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .down(proto::DownRequest {})
        .await
        .map_err(|e| format!("disconnect: {}", e))?;
    Ok(())
}
