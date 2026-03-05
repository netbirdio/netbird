use std::collections::HashMap;

use serde::Serialize;
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    pub id: String,
    pub range: String,
    pub domains: Vec<String>,
    pub selected: bool,
    #[serde(rename = "resolvedIPs")]
    pub resolved_ips: HashMap<String, Vec<String>>,
}

fn network_from_proto(r: &proto::Network) -> NetworkInfo {
    let mut resolved = HashMap::new();
    for (domain, ip_list) in &r.resolved_i_ps {
        resolved.insert(domain.clone(), ip_list.ips.clone());
    }
    NetworkInfo {
        id: r.id.clone(),
        range: r.range.clone(),
        domains: r.domains.clone(),
        selected: r.selected,
        resolved_ips: resolved,
    }
}

async fn fetch_networks(state: &State<'_, AppState>) -> Result<Vec<NetworkInfo>, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .list_networks(proto::ListNetworksRequest {})
        .await
        .map_err(|e| format!("list networks rpc: {}", e))?
        .into_inner();

    let mut routes: Vec<NetworkInfo> = resp.routes.iter().map(network_from_proto).collect();
    routes.sort_by(|a, b| a.id.to_lowercase().cmp(&b.id.to_lowercase()));
    Ok(routes)
}

#[tauri::command]
pub async fn list_networks(state: State<'_, AppState>) -> Result<Vec<NetworkInfo>, String> {
    fetch_networks(&state).await
}

#[tauri::command]
pub async fn list_overlapping_networks(
    state: State<'_, AppState>,
) -> Result<Vec<NetworkInfo>, String> {
    let all = fetch_networks(&state).await?;
    let mut by_range: HashMap<String, Vec<NetworkInfo>> = HashMap::new();
    for r in all {
        if !r.domains.is_empty() {
            continue;
        }
        by_range.entry(r.range.clone()).or_default().push(r);
    }
    let mut result = Vec::new();
    for group in by_range.values() {
        if group.len() > 1 {
            result.extend(group.iter().cloned());
        }
    }
    Ok(result)
}

#[tauri::command]
pub async fn list_exit_nodes(state: State<'_, AppState>) -> Result<Vec<NetworkInfo>, String> {
    let all = fetch_networks(&state).await?;
    Ok(all.into_iter().filter(|r| r.range == "0.0.0.0/0").collect())
}

#[tauri::command]
pub async fn select_network(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .select_networks(proto::SelectNetworksRequest {
            network_i_ds: vec![id],
            append: true,
            all: false,
        })
        .await
        .map_err(|e| format!("select network: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn deselect_network(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .deselect_networks(proto::SelectNetworksRequest {
            network_i_ds: vec![id],
            append: false,
            all: false,
        })
        .await
        .map_err(|e| format!("deselect network: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn select_networks(state: State<'_, AppState>, ids: Vec<String>) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .select_networks(proto::SelectNetworksRequest {
            network_i_ds: ids,
            append: true,
            all: false,
        })
        .await
        .map_err(|e| format!("select networks: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn deselect_networks(
    state: State<'_, AppState>,
    ids: Vec<String>,
) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .deselect_networks(proto::SelectNetworksRequest {
            network_i_ds: ids,
            append: false,
            all: false,
        })
        .await
        .map_err(|e| format!("deselect networks: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn select_all_networks(state: State<'_, AppState>) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .select_networks(proto::SelectNetworksRequest {
            network_i_ds: vec![],
            append: false,
            all: true,
        })
        .await
        .map_err(|e| format!("select all networks: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn deselect_all_networks(state: State<'_, AppState>) -> Result<(), String> {
    let mut client = state.grpc.get_client().await?;
    client
        .deselect_networks(proto::SelectNetworksRequest {
            network_i_ds: vec![],
            append: false,
            all: true,
        })
        .await
        .map_err(|e| format!("deselect all networks: {}", e))?;
    Ok(())
}
