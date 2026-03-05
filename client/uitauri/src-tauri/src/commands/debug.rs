use serde::{Deserialize, Serialize};
use tauri::State;

use crate::proto;
use crate::state::AppState;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugBundleParams {
    pub anonymize: bool,
    pub system_info: bool,
    pub upload: bool,
    pub upload_url: String,
    pub run_duration_mins: u32,
    pub enable_persistence: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugBundleResult {
    pub local_path: String,
    pub uploaded_key: String,
    pub upload_failure_reason: String,
}

#[tauri::command]
pub async fn create_debug_bundle(
    state: State<'_, AppState>,
    params: DebugBundleParams,
) -> Result<DebugBundleResult, String> {
    let mut client = state.grpc.get_client().await?;

    // If run_duration_mins > 0, do the full debug cycle
    if params.run_duration_mins > 0 {
        configure_for_debug(&mut client, &params).await?;
    }

    let upload_url = if params.upload && !params.upload_url.is_empty() {
        params.upload_url.clone()
    } else {
        String::new()
    };

    let resp = client
        .debug_bundle(proto::DebugBundleRequest {
            anonymize: params.anonymize,
            system_info: params.system_info,
            upload_url: upload_url,
            log_file_count: 0,
        })
        .await
        .map_err(|e| format!("create debug bundle: {}", e))?
        .into_inner();

    Ok(DebugBundleResult {
        local_path: resp.path,
        uploaded_key: resp.uploaded_key,
        upload_failure_reason: resp.upload_failure_reason,
    })
}

async fn configure_for_debug(
    client: &mut proto::daemon_service_client::DaemonServiceClient<tonic::transport::Channel>,
    params: &DebugBundleParams,
) -> Result<(), String> {
    // Get current status
    let status_resp = client
        .status(proto::StatusRequest {
            get_full_peer_status: false,
            should_run_probes: false,
            wait_for_ready: None,
        })
        .await
        .map_err(|e| format!("get status: {}", e))?
        .into_inner();

    let was_connected =
        status_resp.status == "Connected" || status_resp.status == "Connecting";

    // Get current log level
    let log_resp = client
        .get_log_level(proto::GetLogLevelRequest {})
        .await
        .map_err(|e| format!("get log level: {}", e))?
        .into_inner();
    let original_level = log_resp.level;

    // Set trace log level
    client
        .set_log_level(proto::SetLogLevelRequest {
            level: proto::LogLevel::Trace.into(),
        })
        .await
        .map_err(|e| format!("set log level: {}", e))?;

    // Bring down then up
    let _ = client.down(proto::DownRequest {}).await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    if params.enable_persistence {
        let _ = client
            .set_sync_response_persistence(proto::SetSyncResponsePersistenceRequest {
                enabled: true,
            })
            .await;
    }

    client
        .up(proto::UpRequest {
            profile_name: None,
            username: None,
            auto_update: None,
        })
        .await
        .map_err(|e| format!("bring service up: {}", e))?;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let _ = client
        .start_cpu_profile(proto::StartCpuProfileRequest {})
        .await;

    // Wait for collection duration
    let duration = std::time::Duration::from_secs(params.run_duration_mins as u64 * 60);
    tokio::time::sleep(duration).await;

    let _ = client
        .stop_cpu_profile(proto::StopCpuProfileRequest {})
        .await;

    // Restore original state
    if !was_connected {
        let _ = client.down(proto::DownRequest {}).await;
    }

    if original_level < proto::LogLevel::Trace as i32 {
        let _ = client
            .set_log_level(proto::SetLogLevelRequest {
                level: original_level,
            })
            .await;
    }

    Ok(())
}

#[tauri::command]
pub async fn get_log_level(state: State<'_, AppState>) -> Result<String, String> {
    let mut client = state.grpc.get_client().await?;
    let resp = client
        .get_log_level(proto::GetLogLevelRequest {})
        .await
        .map_err(|e| format!("get log level rpc: {}", e))?
        .into_inner();

    let level_name = match proto::LogLevel::try_from(resp.level) {
        Ok(proto::LogLevel::Trace) => "TRACE",
        Ok(proto::LogLevel::Debug) => "DEBUG",
        Ok(proto::LogLevel::Info) => "INFO",
        Ok(proto::LogLevel::Warn) => "WARN",
        Ok(proto::LogLevel::Error) => "ERROR",
        Ok(proto::LogLevel::Fatal) => "FATAL",
        Ok(proto::LogLevel::Panic) => "PANIC",
        _ => "UNKNOWN",
    };
    Ok(level_name.to_string())
}

#[tauri::command]
pub async fn set_log_level(state: State<'_, AppState>, level: String) -> Result<(), String> {
    let proto_level = match level.as_str() {
        "TRACE" => proto::LogLevel::Trace,
        "DEBUG" => proto::LogLevel::Debug,
        "INFO" => proto::LogLevel::Info,
        "WARN" | "WARNING" => proto::LogLevel::Warn,
        "ERROR" => proto::LogLevel::Error,
        _ => proto::LogLevel::Info,
    };

    let mut client = state.grpc.get_client().await?;
    client
        .set_log_level(proto::SetLogLevelRequest {
            level: proto_level.into(),
        })
        .await
        .map_err(|e| format!("set log level rpc: {}", e))?;
    Ok(())
}
