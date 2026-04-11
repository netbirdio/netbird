use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::Duration;

/// Named pipe path for communicating with the NetBird agent.
const PIPE_NAME: &str = r"\\.\pipe\netbird-rdp-auth";

/// Maximum response size from the agent.
const MAX_RESPONSE_SIZE: usize = 4096;

/// Timeout for named pipe operations.
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);

/// Request sent to the NetBird agent via named pipe.
#[derive(Serialize)]
pub struct PipeRequest {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Response received from the NetBird agent via named pipe.
#[derive(Deserialize, Debug, Clone)]
pub struct PipeResponse {
    pub found: bool,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub os_user: String,
    #[serde(default)]
    pub domain: String,
}

/// Client for communicating with the NetBird agent's named pipe server.
pub struct NamedPipeClient;

impl NamedPipeClient {
    /// Query the NetBird agent for a pending RDP session matching the given remote IP.
    pub fn query_pending(remote_ip: &str) -> Result<PipeResponse, PipeError> {
        let request = PipeRequest {
            action: "query_pending".to_string(),
            remote_ip: Some(remote_ip.to_string()),
            session_id: None,
        };
        Self::send_request(&request)
    }

    /// Tell the NetBird agent to consume (mark as used) a pending session.
    pub fn consume_session(session_id: &str) -> Result<PipeResponse, PipeError> {
        let request = PipeRequest {
            action: "consume".to_string(),
            remote_ip: None,
            session_id: Some(session_id.to_string()),
        };
        Self::send_request(&request)
    }

    fn send_request(request: &PipeRequest) -> Result<PipeResponse, PipeError> {
        let request_data =
            serde_json::to_vec(request).map_err(|e| PipeError::Serialization(e.to_string()))?;

        // Open named pipe (CreateFile in Windows)
        let mut pipe = Self::open_pipe()?;

        // Write request
        pipe.write_all(&request_data)
            .map_err(|e| PipeError::Write(e.to_string()))?;

        // Shutdown write side to signal end of request
        // For named pipes on Windows, we rely on the message boundary
        pipe.flush()
            .map_err(|e| PipeError::Write(e.to_string()))?;

        // Read response
        let mut response_data = vec![0u8; MAX_RESPONSE_SIZE];
        let n = pipe
            .read(&mut response_data)
            .map_err(|e| PipeError::Read(e.to_string()))?;

        let response: PipeResponse = serde_json::from_slice(&response_data[..n])
            .map_err(|e| PipeError::Deserialization(e.to_string()))?;

        Ok(response)
    }

    fn open_pipe() -> Result<std::fs::File, PipeError> {
        // On Windows, named pipes are opened like files
        use std::fs::OpenOptions;

        // Try to open the pipe with a brief retry for PIPE_BUSY
        for attempt in 0..3 {
            match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
                Ok(file) => return Ok(file),
                Err(e) => {
                    if attempt < 2 {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    return Err(PipeError::Connect(format!(
                        "failed to open pipe {}: {}",
                        PIPE_NAME, e
                    )));
                }
            }
        }

        Err(PipeError::Connect("exhausted pipe connection attempts".to_string()))
    }
}

/// Errors that can occur during named pipe communication.
#[derive(Debug)]
pub enum PipeError {
    Connect(String),
    Write(String),
    Read(String),
    Serialization(String),
    Deserialization(String),
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeError::Connect(e) => write!(f, "pipe connect: {}", e),
            PipeError::Write(e) => write!(f, "pipe write: {}", e),
            PipeError::Read(e) => write!(f, "pipe read: {}", e),
            PipeError::Serialization(e) => write!(f, "pipe serialization: {}", e),
            PipeError::Deserialization(e) => write!(f, "pipe deserialization: {}", e),
        }
    }
}

impl std::error::Error for PipeError {}
