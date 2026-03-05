use std::sync::Arc;
use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{CheckMenuItem, CheckMenuItemBuilder, MenuBuilder, MenuItem, MenuItemBuilder, SubmenuBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex;

use crate::commands::connection::StatusInfo;
use crate::grpc::GrpcClient;
use crate::proto;
use crate::state::AppState;

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(5);

// Icon bytes embedded at compile time
const ICON_DISCONNECTED: &[u8] = include_bytes!("../icons/netbird-systemtray-disconnected.png");
const ICON_CONNECTED: &[u8] = include_bytes!("../icons/netbird-systemtray-connected.png");
const ICON_CONNECTING: &[u8] = include_bytes!("../icons/netbird-systemtray-connecting.png");
const ICON_ERROR: &[u8] = include_bytes!("../icons/netbird-systemtray-error.png");

fn icon_for_status(status: &str) -> &'static [u8] {
    match status {
        "Connected" => ICON_CONNECTED,
        "Connecting" => ICON_CONNECTING,
        "Disconnected" | "" => ICON_DISCONNECTED,
        _ => ICON_ERROR,
    }
}

/// Holds references to menu items we need to update at runtime.
pub struct TrayMenuItems {
    pub status_item: MenuItem<tauri::Wry>,
    pub ssh_item: CheckMenuItem<tauri::Wry>,
    pub auto_connect_item: CheckMenuItem<tauri::Wry>,
    pub rosenpass_item: CheckMenuItem<tauri::Wry>,
    pub lazy_conn_item: CheckMenuItem<tauri::Wry>,
    pub block_inbound_item: CheckMenuItem<tauri::Wry>,
    pub notifications_item: CheckMenuItem<tauri::Wry>,
}

pub type SharedTrayMenuItems = Arc<Mutex<Option<TrayMenuItems>>>;

pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let grpc = app.state::<AppState>().grpc.clone();

    // Build the tray menu
    let status_item = MenuItemBuilder::with_id("status", "Status: Disconnected")
        .enabled(false)
        .build(app)?;

    let connect_item = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
    let disconnect_item = MenuItemBuilder::with_id("disconnect", "Disconnect").build(app)?;

    let ssh_item = CheckMenuItemBuilder::with_id("toggle_ssh", "Allow SSH connections")
        .checked(false)
        .build(app)?;
    let auto_connect_item =
        CheckMenuItemBuilder::with_id("toggle_auto_connect", "Connect automatically when service starts")
            .checked(false)
            .build(app)?;
    let rosenpass_item =
        CheckMenuItemBuilder::with_id("toggle_rosenpass", "Enable post-quantum security via Rosenpass")
            .checked(false)
            .build(app)?;
    let lazy_conn_item =
        CheckMenuItemBuilder::with_id("toggle_lazy_conn", "[Experimental] Enable lazy connections")
            .checked(false)
            .build(app)?;
    let block_inbound_item =
        CheckMenuItemBuilder::with_id("toggle_block_inbound", "Block inbound connections")
            .checked(false)
            .build(app)?;
    let notifications_item =
        CheckMenuItemBuilder::with_id("toggle_notifications", "Enable notifications")
            .checked(true)
            .build(app)?;

    // Exit node submenu
    let exit_node_menu = SubmenuBuilder::with_id(app, "exit_node", "Exit Node")
        .item(
            &MenuItemBuilder::with_id("no_exit_nodes", "No exit nodes")
                .enabled(false)
                .build(app)?,
        )
        .build()?;

    // Navigation items
    let nav_status = MenuItemBuilder::with_id("nav_status", "Status").build(app)?;
    let nav_settings = MenuItemBuilder::with_id("nav_settings", "Settings").build(app)?;
    let nav_peers = MenuItemBuilder::with_id("nav_peers", "Peers").build(app)?;
    let nav_networks = MenuItemBuilder::with_id("nav_networks", "Networks").build(app)?;
    let nav_profiles = MenuItemBuilder::with_id("nav_profiles", "Profiles").build(app)?;
    let nav_debug = MenuItemBuilder::with_id("nav_debug", "Debug").build(app)?;
    let nav_update = MenuItemBuilder::with_id("nav_update", "Update").build(app)?;

    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&status_item)
        .separator()
        .item(&connect_item)
        .item(&disconnect_item)
        .separator()
        .item(&ssh_item)
        .item(&auto_connect_item)
        .item(&rosenpass_item)
        .item(&lazy_conn_item)
        .item(&block_inbound_item)
        .item(&notifications_item)
        .separator()
        .item(&exit_node_menu)
        .separator()
        .item(&nav_status)
        .item(&nav_settings)
        .item(&nav_peers)
        .item(&nav_networks)
        .item(&nav_profiles)
        .item(&nav_debug)
        .item(&nav_update)
        .separator()
        .item(&quit_item)
        .build()?;

    // Store menu item references for runtime updates
    let menu_items: SharedTrayMenuItems = Arc::new(Mutex::new(Some(TrayMenuItems {
        status_item,
        ssh_item: ssh_item.clone(),
        auto_connect_item: auto_connect_item.clone(),
        rosenpass_item: rosenpass_item.clone(),
        lazy_conn_item: lazy_conn_item.clone(),
        block_inbound_item: block_inbound_item.clone(),
        notifications_item: notifications_item.clone(),
    })));
    app.manage(menu_items.clone());

    let _tray = TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(ICON_DISCONNECTED)?)
        .icon_as_template(cfg!(target_os = "macos"))
        .menu(&menu)
        .on_menu_event({
            let app_handle = app.clone();
            let grpc = grpc.clone();
            move |_app, event| {
                let id = event.id().as_ref();
                let app_handle = app_handle.clone();
                let grpc = grpc.clone();

                match id {
                    "connect" => {
                        tauri::async_runtime::spawn(async move {
                            let mut client = match grpc.get_client().await {
                                Ok(c) => c,
                                Err(e) => {
                                    log::error!("connect: {}", e);
                                    return;
                                }
                            };
                            if let Err(e) = client
                                .up(proto::UpRequest {
                                    profile_name: None,
                                    username: None,
                                    auto_update: None,
                                })
                                .await
                            {
                                log::error!("connect: {}", e);
                            }
                        });
                    }
                    "disconnect" => {
                        tauri::async_runtime::spawn(async move {
                            let mut client = match grpc.get_client().await {
                                Ok(c) => c,
                                Err(e) => {
                                    log::error!("disconnect: {}", e);
                                    return;
                                }
                            };
                            if let Err(e) = client.down(proto::DownRequest {}).await {
                                log::error!("disconnect: {}", e);
                            }
                        });
                    }
                    "toggle_ssh" | "toggle_auto_connect" | "toggle_rosenpass"
                    | "toggle_lazy_conn" | "toggle_block_inbound" | "toggle_notifications" => {
                        let toggle_id = id.to_string();
                        tauri::async_runtime::spawn(async move {
                            handle_toggle(&app_handle, &grpc, &toggle_id).await;
                        });
                    }
                    s if s.starts_with("nav_") => {
                        let path = match s {
                            "nav_status" => "/",
                            "nav_settings" => "/settings",
                            "nav_peers" => "/peers",
                            "nav_networks" => "/networks",
                            "nav_profiles" => "/profiles",
                            "nav_debug" => "/debug",
                            "nav_update" => "/update",
                            _ => return,
                        };
                        let _ = app_handle.emit("navigate", path);
                        if let Some(win) = app_handle.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "quit" => {
                        app_handle.exit(0);
                    }
                    _ => {}
                }
            }
        })
        .build(app)?;

    // Refresh toggle states
    let app_handle = app.clone();
    let grpc_clone = grpc.clone();
    tauri::async_runtime::spawn(async move {
        refresh_toggle_states(&app_handle, &grpc_clone).await;
    });

    // Start status polling
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        poll_status(app_handle, grpc).await;
    });

    Ok(())
}

async fn poll_status(app: AppHandle, grpc: GrpcClient) {
    loop {
        tokio::time::sleep(STATUS_POLL_INTERVAL).await;

        let mut client = match grpc.get_client().await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("pollStatus: {}", e);
                grpc.reset().await;
                continue;
            }
        };

        let resp = match client
            .status(proto::StatusRequest {
                get_full_peer_status: true,
                should_run_probes: false,
                wait_for_ready: None,
            })
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => {
                log::warn!("pollStatus: status rpc: {}", e);
                grpc.reset().await;
                continue;
            }
        };

        let mut info = StatusInfo {
            status: resp.status.clone(),
            ip: String::new(),
            public_key: String::new(),
            fqdn: String::new(),
            connected_peers: 0,
        };

        if let Some(ref full) = resp.full_status {
            if let Some(ref lp) = full.local_peer_state {
                info.ip = lp.ip.clone();
                info.public_key = lp.pub_key.clone();
                info.fqdn = lp.fqdn.clone();
            }
            info.connected_peers = full.peers.len();
        }

        // Update tray label
        let label = if info.ip.is_empty() {
            format!("Status: {}", info.status)
        } else {
            format!("Status: {} ({})", info.status, info.ip)
        };

        // Update tray menu status label via stored reference
        let menu_items = app.state::<SharedTrayMenuItems>();
        if let Some(ref items) = *menu_items.lock().await {
            let _ = items.status_item.set_text(&label);
        }

        // Update tray icon
        if let Some(tray) = app.tray_by_id("main") {
            let icon_bytes = icon_for_status(&info.status);
            if let Ok(icon) = Image::from_bytes(icon_bytes) {
                let _ = tray.set_icon(Some(icon));
            }
        }

        // Emit status-changed event to frontend
        let _ = app.emit("status-changed", &info);
    }
}

async fn handle_toggle(app: &AppHandle, grpc: &GrpcClient, toggle_id: &str) {
    let mut client = match grpc.get_client().await {
        Ok(c) => c,
        Err(e) => {
            log::error!("toggle: get client: {}", e);
            return;
        }
    };

    // Get current config
    let cfg = match client
        .get_config(proto::GetConfigRequest {
            profile_name: String::new(),
            username: String::new(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            log::error!("toggle: get config: {}", e);
            return;
        }
    };

    // Build set config request based on which toggle was clicked
    let mut req = proto::SetConfigRequest {
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

    match toggle_id {
        "toggle_ssh" => req.server_ssh_allowed = Some(!cfg.server_ssh_allowed),
        "toggle_auto_connect" => req.disable_auto_connect = Some(!cfg.disable_auto_connect),
        "toggle_rosenpass" => req.rosenpass_enabled = Some(!cfg.rosenpass_enabled),
        "toggle_lazy_conn" => req.lazy_connection_enabled = Some(!cfg.lazy_connection_enabled),
        "toggle_block_inbound" => req.block_inbound = Some(!cfg.block_inbound),
        "toggle_notifications" => req.disable_notifications = Some(!cfg.disable_notifications),
        _ => return,
    }

    if let Err(e) = client.set_config(req).await {
        log::error!("toggle {}: set config: {}", toggle_id, e);
    }

    // Refresh toggle states after change
    refresh_toggle_states(app, grpc).await;
}

async fn refresh_toggle_states(app: &AppHandle, grpc: &GrpcClient) {
    let mut client = match grpc.get_client().await {
        Ok(c) => c,
        Err(e) => {
            log::debug!("refresh toggles: {}", e);
            return;
        }
    };

    let cfg = match client
        .get_config(proto::GetConfigRequest {
            profile_name: String::new(),
            username: String::new(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            log::debug!("refresh toggles: get config: {}", e);
            return;
        }
    };

    let menu_items = app.state::<SharedTrayMenuItems>();
    let guard = menu_items.lock().await;
    if let Some(ref items) = *guard {
        let _ = items.ssh_item.set_checked(cfg.server_ssh_allowed);
        let _ = items.auto_connect_item.set_checked(!cfg.disable_auto_connect);
        let _ = items.rosenpass_item.set_checked(cfg.rosenpass_enabled);
        let _ = items.lazy_conn_item.set_checked(cfg.lazy_connection_enabled);
        let _ = items.block_inbound_item.set_checked(cfg.block_inbound);
        let _ = items.notifications_item.set_checked(!cfg.disable_notifications);
    }
}
