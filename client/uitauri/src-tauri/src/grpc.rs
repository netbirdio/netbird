use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::proto::daemon_service_client::DaemonServiceClient;

/// GrpcClient manages a persistent gRPC connection to the NetBird daemon.
#[derive(Clone)]
pub struct GrpcClient {
    addr: String,
    client: Arc<Mutex<Option<DaemonServiceClient<Channel>>>>,
}

impl GrpcClient {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            client: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a cached DaemonServiceClient, creating the connection on first use.
    /// If the connection fails or was previously dropped, a new connection is attempted.
    pub async fn get_client(&self) -> Result<DaemonServiceClient<Channel>, String> {
        let mut guard = self.client.lock().await;
        if let Some(ref client) = *guard {
            return Ok(client.clone());
        }

        let channel = self.connect().await?;
        let client = DaemonServiceClient::new(channel);
        *guard = Some(client.clone());
        log::info!("gRPC connection established to {}", self.addr);
        Ok(client)
    }

    /// Clears the cached client so the next call to get_client will reconnect.
    pub async fn reset(&self) {
        let mut guard = self.client.lock().await;
        *guard = None;
    }

    async fn connect(&self) -> Result<Channel, String> {
        let addr = &self.addr;

        #[cfg(unix)]
        if addr.starts_with("unix://") {
            return self.connect_unix(addr).await;
        }

        // TCP connection
        let target = if addr.starts_with("tcp://") {
            addr.strip_prefix("tcp://").unwrap_or(addr)
        } else {
            addr.as_str()
        };

        let uri = format!("http://{}", target);
        Endpoint::from_shared(uri)
            .map_err(|e| format!("invalid endpoint: {}", e))?
            .connect()
            .await
            .map_err(|e| format!("connect tcp: {}", e))
    }

    #[cfg(unix)]
    async fn connect_unix(&self, addr: &str) -> Result<Channel, String> {
        let path = addr
            .strip_prefix("unix://")
            .unwrap_or(addr)
            .to_string();

        // tonic requires a valid URI even for UDS; the actual connection
        // is made by the connector below, so the URI authority is ignored.
        let channel = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| format!("invalid endpoint: {}", e))?
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| format!("connect unix: {}", e))?;

        Ok(channel)
    }

    /// Close the connection (drop the cached client).
    pub async fn close(&self) {
        let mut guard = self.client.lock().await;
        *guard = None;
    }
}

/// Returns the default daemon address for the current platform.
pub fn default_daemon_addr() -> String {
    if cfg!(windows) {
        "tcp://127.0.0.1:41731".to_string()
    } else {
        "unix:///var/run/netbird.sock".to_string()
    }
}
