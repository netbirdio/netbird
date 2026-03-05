use serde::Serialize;
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallerResult {
    pub success: bool,
    pub error_msg: String,
}

#[tauri::command]
pub async fn trigger_update() -> Result<(), String> {
    // Stub - same as the Go implementation
    Ok(())
}

#[tauri::command]
pub async fn get_installer_result(state: State<'_, AppState>) -> Result<InstallerResult, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .get_installer_result(proto::InstallerResultRequest {})
        .await;

    match resp {
        Ok(r) => {
            let inner = r.into_inner();
            Ok(InstallerResult {
                success: inner.success,
                error_msg: inner.error_msg,
            })
        }
        Err(_) => {
            // Daemon may have restarted during update - treat as success
            Ok(InstallerResult {
                success: true,
                error_msg: String::new(),
            })
        }
    }
}
