// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod events;
mod grpc;
mod proto;
mod state;
mod tray;

use tauri::Manager;

use grpc::{default_daemon_addr, GrpcClient};
use state::AppState;

fn main() {
    env_logger::init();

    // Linux WebKit workaround
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    let daemon_addr =
        std::env::var("NETBIRD_DAEMON_ADDR").unwrap_or_else(|_| default_daemon_addr());

    log::info!("NetBird UI starting, daemon address: {}", daemon_addr);

    let grpc_client = GrpcClient::new(daemon_addr.clone());

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Focus existing window when second instance is launched
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        .manage(AppState {
            grpc: grpc_client.clone(),
        })
        .invoke_handler(tauri::generate_handler![
            // Connection
            commands::connection::get_status,
            commands::connection::connect,
            commands::connection::disconnect,
            // Settings
            commands::settings::get_config,
            commands::settings::set_config,
            commands::settings::toggle_ssh,
            commands::settings::toggle_auto_connect,
            commands::settings::toggle_rosenpass,
            commands::settings::toggle_lazy_conn,
            commands::settings::toggle_block_inbound,
            commands::settings::toggle_notifications,
            // Network
            commands::network::list_networks,
            commands::network::list_overlapping_networks,
            commands::network::list_exit_nodes,
            commands::network::select_network,
            commands::network::deselect_network,
            commands::network::select_networks,
            commands::network::deselect_networks,
            commands::network::select_all_networks,
            commands::network::deselect_all_networks,
            // Peers
            commands::peers::get_peers,
            // Profile
            commands::profile::list_profiles,
            commands::profile::get_active_profile,
            commands::profile::switch_profile,
            commands::profile::add_profile,
            commands::profile::remove_profile,
            commands::profile::logout,
            // Debug
            commands::debug::create_debug_bundle,
            commands::debug::get_log_level,
            commands::debug::set_log_level,
            // Update
            commands::update::trigger_update,
            commands::update::get_installer_result,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Setup system tray
            if let Err(e) = tray::setup_tray(&handle) {
                log::error!("tray setup failed: {}", e);
            }

            // Start daemon event subscription
            events::start_event_subscription(handle, grpc_client);

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide instead of quit when user closes the window
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error running tauri application");
}
