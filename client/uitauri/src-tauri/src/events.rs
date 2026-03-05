use std::time::Duration;

use tauri::{AppHandle, Emitter};

use crate::grpc::GrpcClient;
use crate::proto;

/// Start the daemon event subscription loop with exponential backoff.
pub fn start_event_subscription(app: AppHandle, grpc: GrpcClient) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(10);

        loop {
            match stream_events(&app, &grpc).await {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    log::warn!("event stream ended: {}", e);
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    });
}

async fn stream_events(app: &AppHandle, grpc: &GrpcClient) -> Result<(), String> {
    let mut client = grpc.get_client().await?;
    let mut stream = client
        .subscribe_events(proto::SubscribeRequest {})
        .await
        .map_err(|e| format!("subscribe events: {}", e))?
        .into_inner();

    log::info!("subscribed to daemon events");

    while let Some(event) = stream
        .message()
        .await
        .map_err(|e| format!("receive event: {}", e))?
    {
        handle_event(app, &event);
    }

    log::info!("event stream ended");
    Ok(())
}

fn handle_event(app: &AppHandle, event: &proto::SystemEvent) {
    // Send desktop notification for events with user_message
    if !event.user_message.is_empty() {
        let title = get_event_title(event);
        let mut body = event.user_message.clone();
        if let Some(id) = event.metadata.get("id") {
            body.push_str(&format!(" ID: {}", id));
        }

        if let Err(e) = notify_rust::Notification::new()
            .summary(&title)
            .body(&body)
            .appname("NetBird")
            .show()
        {
            log::debug!("notification failed: {}", e);
        }
    }

    // Emit to frontend
    let _ = app.emit("daemon-event", &event.user_message);
}

fn get_event_title(event: &proto::SystemEvent) -> String {
    let prefix = match proto::system_event::Severity::try_from(event.severity) {
        Ok(proto::system_event::Severity::Critical) => "Critical",
        Ok(proto::system_event::Severity::Error) => "Error",
        Ok(proto::system_event::Severity::Warning) => "Warning",
        _ => "Info",
    };

    let category = match proto::system_event::Category::try_from(event.category) {
        Ok(proto::system_event::Category::Dns) => "DNS",
        Ok(proto::system_event::Category::Network) => "Network",
        Ok(proto::system_event::Category::Authentication) => "Authentication",
        Ok(proto::system_event::Category::Connectivity) => "Connectivity",
        _ => "System",
    };

    format!("{}: {}", prefix, category)
}
