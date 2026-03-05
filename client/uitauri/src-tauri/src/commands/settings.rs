use serde::{Deserialize, Serialize};
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigInfo {
    pub management_url: String,
    pub admin_url: String,
    pub pre_shared_key: String,
    pub interface_name: String,
    pub wireguard_port: i64,
    pub disable_auto_connect: bool,
    pub server_ssh_allowed: bool,
    pub rosenpass_enabled: bool,
    pub rosenpass_permissive: bool,
    pub lazy_connection_enabled: bool,
    pub block_inbound: bool,
    pub disable_notifications: bool,
}

#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<ConfigInfo, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .get_config(proto::GetConfigRequest {
            profile_name: String::new(),
            username: String::new(),
        })
        .await
        .map_err(|e| format!("get config rpc: {}", e))?
        .into_inner();

    Ok(ConfigInfo {
        management_url: resp.management_url,
        admin_url: resp.admin_url,
        pre_shared_key: resp.pre_shared_key,
        interface_name: resp.interface_name,
        wireguard_port: resp.wireguard_port,
        disable_auto_connect: resp.disable_auto_connect,
        server_ssh_allowed: resp.server_ssh_allowed,
        rosenpass_enabled: resp.rosenpass_enabled,
        rosenpass_permissive: resp.rosenpass_permissive,
        lazy_connection_enabled: resp.lazy_connection_enabled,
        block_inbound: resp.block_inbound,
        disable_notifications: resp.disable_notifications,
    })
}

#[tauri::command]
pub async fn set_config(state: State<'_, AppState>, cfg: ConfigInfo) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    let req = proto::SetConfigRequest {
        username: String::new(),
        profile_name: String::new(),
        management_url: cfg.management_url,
        admin_url: cfg.admin_url,
        rosenpass_enabled: Some(cfg.rosenpass_enabled),
        interface_name: Some(cfg.interface_name),
        wireguard_port: Some(cfg.wireguard_port),
        optional_pre_shared_key: Some(cfg.pre_shared_key),
        disable_auto_connect: Some(cfg.disable_auto_connect),
        server_ssh_allowed: Some(cfg.server_ssh_allowed),
        rosenpass_permissive: Some(cfg.rosenpass_permissive),
        disable_notifications: Some(cfg.disable_notifications),
        lazy_connection_enabled: Some(cfg.lazy_connection_enabled),
        block_inbound: Some(cfg.block_inbound),
        // Fields we don't expose in the UI:
        network_monitor: None,
        disable_client_routes: None,
        disable_server_routes: None,
        disable_dns: None,
        disable_firewall: None,
        block_lan_access: None,
        nat_external_i_ps: vec![],
        clean_nat_external_i_ps: false,
        custom_dns_address: vec![],
        extra_i_face_blacklist: vec![],
        dns_labels: vec![],
        clean_dns_labels: false,
        dns_route_interval: None,
        mtu: None,
        enable_ssh_root: None,
        enable_sshsftp: None,
        enable_ssh_local_port_forwarding: None,
        enable_ssh_remote_port_forwarding: None,
        disable_ssh_auth: None,
        ssh_jwt_cache_ttl: None,
    };
    client
        .set_config(req)
        .await
        .map_err(|e| format!("set config: {}", e))?;
    Ok(())
}

// Toggle helpers - each fetches config, modifies one field, and saves.

#[tauri::command]
pub async fn toggle_ssh(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.server_ssh_allowed = enabled;
    set_config(state, cfg).await
}

#[tauri::command]
pub async fn toggle_auto_connect(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.disable_auto_connect = !enabled;
    set_config(state, cfg).await
}

#[tauri::command]
pub async fn toggle_rosenpass(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.rosenpass_enabled = enabled;
    set_config(state, cfg).await
}

#[tauri::command]
pub async fn toggle_lazy_conn(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.lazy_connection_enabled = enabled;
    set_config(state, cfg).await
}

#[tauri::command]
pub async fn toggle_block_inbound(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.block_inbound = enabled;
    set_config(state, cfg).await
}

#[tauri::command]
pub async fn toggle_notifications(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let mut cfg = get_config(state.clone()).await?;
    cfg.disable_notifications = !enabled;
    set_config(state, cfg).await
}
