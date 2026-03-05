use serde::Serialize;
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileInfo {
    pub name: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveProfileInfo {
    pub profile_name: String,
    pub username: String,
    pub email: String,
}

fn current_username() -> Result<String, String> {
    #[cfg(unix)]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| "could not determine current user".to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME")
            .map_err(|_| "could not determine current user".to_string())
    }
}

#[tauri::command]
pub async fn list_profiles(state: State<'_, AppState>) -> Result<Vec<ProfileInfo>, String> {
    let username = current_username()?;
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .list_profiles(proto::ListProfilesRequest { username })
        .await
        .map_err(|e| format!("list profiles rpc: {}", e))?
        .into_inner();

    Ok(resp
        .profiles
        .iter()
        .map(|p| ProfileInfo {
            name: p.name.clone(),
            is_active: p.is_active,
        })
        .collect())
}

#[tauri::command]
pub async fn get_active_profile(state: State<'_, AppState>) -> Result<ActiveProfileInfo, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .get_active_profile(proto::GetActiveProfileRequest {})
        .await
        .map_err(|e| format!("get active profile rpc: {}", e))?
        .into_inner();

    Ok(ActiveProfileInfo {
        profile_name: resp.profile_name,
        username: resp.username,
        email: String::new(),
    })
}

#[tauri::command]
pub async fn switch_profile(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<(), String> {
    let username = current_username()?;
    let mut client = state.grpc.get_client().await?;
    client
        .switch_profile(proto::SwitchProfileRequest {
            profile_name: Some(profile_name),
            username: Some(username),
        })
        .await
        .map_err(|e| format!("switch profile: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn add_profile(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<(), String> {
    let username = current_username()?;
    let mut client = state.grpc.get_client().await?;
    client
        .add_profile(proto::AddProfileRequest {
            profile_name,
            username,
        })
        .await
        .map_err(|e| format!("add profile: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn remove_profile(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<(), String> {
    let username = current_username()?;
    let mut client = state.grpc.get_client().await?;
    client
        .remove_profile(proto::RemoveProfileRequest {
            profile_name,
            username,
        })
        .await
        .map_err(|e| format!("remove profile: {}", e))?;
    Ok(())
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>, profile_name: String) -> Result<(), String> {
    let username = current_username()?;
    let mut client = state.grpc.get_client().await?;
    client
        .logout(proto::LogoutRequest {
            profile_name: Some(profile_name),
            username: Some(username),
        })
        .await
        .map_err(|e| format!("logout: {}", e))?;
    Ok(())
}
