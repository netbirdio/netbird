use crate::grpc::GrpcClient;

/// Application state shared across all Tauri commands.
pub struct AppState {
    pub grpc: GrpcClient,
}
