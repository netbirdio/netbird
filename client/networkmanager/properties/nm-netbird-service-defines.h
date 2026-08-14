#ifndef NM_NETBIRD_SERVICE_DEFINES_H
#define NM_NETBIRD_SERVICE_DEFINES_H

#define NM_DBUS_SERVICE_NETBIRD "org.freedesktop.NetworkManager.netbird"
#define NM_VPN_SERVICE_TYPE_NETBIRD "org.freedesktop.NetworkManager.netbird"

/* Must match profilemanager.DefaultManagementURL
 * (client/internal/profilemanager/config.go), the project-wide default the
 * daemon itself falls back to when no management URL is configured. */
#define NM_NETBIRD_DEFAULT_MANAGEMENT_URL "https://api.netbird.io:443"

#define NM_NETBIRD_KEY_MANAGEMENT_URL "management-url"
#define NM_NETBIRD_KEY_ADMIN_URL "admin-url"
#define NM_NETBIRD_KEY_SETUP_KEY "setup-key"
#define NM_NETBIRD_KEY_INTERFACE_NAME "interface-name"
#define NM_NETBIRD_KEY_HOSTNAME "hostname"
#define NM_NETBIRD_KEY_MTU "mtu"
#define NM_NETBIRD_KEY_WIREGUARD_PORT "wireguard-port"
#define NM_NETBIRD_KEY_BLOCK_INBOUND "block-inbound"
#define NM_NETBIRD_KEY_DISABLE_SERVER_ROUTES "disable-server-routes"
#define NM_NETBIRD_KEY_BLOCK_LAN_ACCESS "block-lan-access"
#define NM_NETBIRD_KEY_DISABLE_CLIENT_ROUTES "disable-client-routes"
#define NM_NETBIRD_KEY_DISABLE_DNS "disable-dns"
#define NM_NETBIRD_KEY_DISABLE_FIREWALL "disable-firewall"
#define NM_NETBIRD_KEY_DISABLE_IPV6 "disable-ipv6"
#define NM_NETBIRD_KEY_ROSENPASS_ENABLED "rosenpass-enabled"
#define NM_NETBIRD_KEY_ROSENPASS_PERMISSIVE "rosenpass-permissive"
#define NM_NETBIRD_KEY_DISABLE_AUTO_CONNECT "disable-auto-connect"
#define NM_NETBIRD_KEY_NETWORK_MONITOR "network-monitor"

#define NM_NETBIRD_VALUE_YES "yes"
#define NM_NETBIRD_VALUE_NO "no"

#endif /* NM_NETBIRD_SERVICE_DEFINES_H */
