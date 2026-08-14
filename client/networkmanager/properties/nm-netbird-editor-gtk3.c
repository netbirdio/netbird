#include "nm-netbird-editor.h"

#include <gtk/gtk.h>

#include "nm-netbird-service-defines.h"

struct _NetbirdEditor {
	GObject parent;

	GtkBuilder *builder;
	GtkWidget *widget;

	GtkWidget *management_url_entry;
	GtkWidget *setup_key_entry;
	GtkWidget *admin_url_entry;
	GtkWidget *interface_name_entry;
	GtkWidget *hostname_entry;
	GtkWidget *mtu_spin;
	GtkWidget *wireguard_port_spin;
	GtkWidget *block_inbound_check;
	GtkWidget *disable_server_routes_check;
	GtkWidget *block_lan_access_check;
	GtkWidget *disable_client_routes_check;
	GtkWidget *disable_dns_check;
	GtkWidget *disable_firewall_check;
	GtkWidget *disable_ipv6_check;
	GtkWidget *rosenpass_enabled_check;
	GtkWidget *rosenpass_permissive_check;
	GtkWidget *disable_auto_connect_check;
	GtkWidget *network_monitor_check;
};

static void netbird_editor_iface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NetbirdEditor, netbird_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR, netbird_editor_iface_init))

static gboolean
is_data_item_yes (NMSettingVpn *s_vpn, const char *key)
{
	return g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, key), NM_NETBIRD_VALUE_YES) == 0;
}

static void
set_entry_text (GtkWidget *entry, const char *value)
{
	gtk_entry_set_text (GTK_ENTRY (entry), value ? value : "");
}

static void
init_widgets_from_connection (NetbirdEditor *self, NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		return;
	}

	set_entry_text (self->management_url_entry, nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_MANAGEMENT_URL));
	set_entry_text (self->setup_key_entry, nm_setting_vpn_get_secret (s_vpn, NM_NETBIRD_KEY_SETUP_KEY));
	set_entry_text (self->admin_url_entry, nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_ADMIN_URL));
	set_entry_text (self->interface_name_entry, nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_INTERFACE_NAME));
	set_entry_text (self->hostname_entry, nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_HOSTNAME));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_MTU);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (self->mtu_spin), value ? g_ascii_strtod (value, NULL) : 0);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NETBIRD_KEY_WIREGUARD_PORT);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (self->wireguard_port_spin), value ? g_ascii_strtod (value, NULL) : 0);

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->block_inbound_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_BLOCK_INBOUND));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_server_routes_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_SERVER_ROUTES));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->block_lan_access_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_BLOCK_LAN_ACCESS));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_client_routes_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_CLIENT_ROUTES));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_dns_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_DNS));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_firewall_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_FIREWALL));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_ipv6_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_IPV6));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->rosenpass_enabled_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_ROSENPASS_ENABLED));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->rosenpass_permissive_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_ROSENPASS_PERMISSIVE));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->disable_auto_connect_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_DISABLE_AUTO_CONNECT));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (self->network_monitor_check),
	                               is_data_item_yes (s_vpn, NM_NETBIRD_KEY_NETWORK_MONITOR));

	gtk_widget_set_sensitive (self->rosenpass_permissive_check,
	                          gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->rosenpass_enabled_check)));
}

static void
rosenpass_enabled_toggled_cb (GtkToggleButton *button, gpointer user_data)
{
	NetbirdEditor *self = NETBIRD_EDITOR (user_data);

	gtk_widget_set_sensitive (self->rosenpass_permissive_check, gtk_toggle_button_get_active (button));
	g_signal_emit_by_name (self, "changed");
}

static void
emit_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (NETBIRD_EDITOR (user_data), "changed");
}

static void
connect_changed_signals (NetbirdEditor *self)
{
	GtkWidget *entries[] = {
		self->management_url_entry,
		self->setup_key_entry,
		self->admin_url_entry,
		self->interface_name_entry,
		self->hostname_entry,
	};
	GtkWidget *checks[] = {
		self->block_inbound_check,
		self->disable_server_routes_check,
		self->block_lan_access_check,
		self->disable_client_routes_check,
		self->disable_dns_check,
		self->disable_firewall_check,
		self->disable_ipv6_check,
		self->rosenpass_enabled_check,
		self->rosenpass_permissive_check,
		self->disable_auto_connect_check,
		self->network_monitor_check,
	};
	GtkWidget *spins[] = { self->mtu_spin, self->wireguard_port_spin };
	guint ii;

	for (ii = 0; ii < G_N_ELEMENTS (entries); ii++) {
		g_signal_connect (entries[ii], "changed", G_CALLBACK (emit_changed_cb), self);
	}
	for (ii = 0; ii < G_N_ELEMENTS (checks); ii++) {
		g_signal_connect (checks[ii], "toggled", G_CALLBACK (emit_changed_cb), self);
	}
	for (ii = 0; ii < G_N_ELEMENTS (spins); ii++) {
		g_signal_connect (spins[ii], "value-changed", G_CALLBACK (emit_changed_cb), self);
	}
}

static void
add_optional_data_item (NMSettingVpn *s_vpn, const char *key, const char *value)
{
	if (value && value[0]) {
		nm_setting_vpn_add_data_item (s_vpn, key, value);
	}
}

static void
add_bool_data_item (NMSettingVpn *s_vpn, const char *key, gboolean active)
{
	nm_setting_vpn_add_data_item (s_vpn, key, active ? NM_NETBIRD_VALUE_YES : NM_NETBIRD_VALUE_NO);
}

static void
add_optional_int_data_item (NMSettingVpn *s_vpn, const char *key, GtkWidget *spin)
{
	int value;

	value = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (spin));
	if (value != 0) {
		char *text = g_strdup_printf ("%d", value);
		nm_setting_vpn_add_data_item (s_vpn, key, text);
		g_free (text);
	}
}

static gboolean
update_connection (NMVpnEditor *iface, NMConnection *connection, GError **error)
{
	NetbirdEditor *self = NETBIRD_EDITOR (iface);
	NMSettingVpn *s_vpn;
	const char *setup_key;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_NETBIRD, NULL);

	/* Left empty, this means the same thing "normal" (non-self-managed)
	 * setup means in netbird-ui: use NetBird's own hosted management
	 * service (api.netbird.io) instead of a self-hosted one. */
	add_optional_data_item (s_vpn, NM_NETBIRD_KEY_MANAGEMENT_URL,
	                         gtk_entry_get_text (GTK_ENTRY (self->management_url_entry)));

	setup_key = gtk_entry_get_text (GTK_ENTRY (self->setup_key_entry));
	if (setup_key && setup_key[0]) {
		nm_setting_vpn_add_secret (s_vpn, NM_NETBIRD_KEY_SETUP_KEY, setup_key);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_NETBIRD_KEY_SETUP_KEY,
		                              NM_SETTING_SECRET_FLAG_AGENT_OWNED, NULL);
	}

	add_optional_data_item (s_vpn, NM_NETBIRD_KEY_ADMIN_URL,
	                         gtk_entry_get_text (GTK_ENTRY (self->admin_url_entry)));
	add_optional_data_item (s_vpn, NM_NETBIRD_KEY_INTERFACE_NAME,
	                         gtk_entry_get_text (GTK_ENTRY (self->interface_name_entry)));
	add_optional_data_item (s_vpn, NM_NETBIRD_KEY_HOSTNAME,
	                         gtk_entry_get_text (GTK_ENTRY (self->hostname_entry)));

	add_optional_int_data_item (s_vpn, NM_NETBIRD_KEY_MTU, self->mtu_spin);
	add_optional_int_data_item (s_vpn, NM_NETBIRD_KEY_WIREGUARD_PORT, self->wireguard_port_spin);

	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_BLOCK_INBOUND,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->block_inbound_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_SERVER_ROUTES,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_server_routes_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_BLOCK_LAN_ACCESS,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->block_lan_access_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_CLIENT_ROUTES,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_client_routes_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_DNS,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_dns_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_FIREWALL,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_firewall_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_IPV6,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_ipv6_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_ROSENPASS_ENABLED,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->rosenpass_enabled_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_ROSENPASS_PERMISSIVE,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->rosenpass_permissive_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_DISABLE_AUTO_CONNECT,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->disable_auto_connect_check)));
	add_bool_data_item (s_vpn, NM_NETBIRD_KEY_NETWORK_MONITOR,
	                     gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (self->network_monitor_check)));

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	return G_OBJECT (NETBIRD_EDITOR (iface)->widget);
}

static void
netbird_editor_iface_init (NMVpnEditorInterface *iface_class)
{
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
netbird_editor_init (NetbirdEditor *self)
{
}

static void
dispose (GObject *object)
{
	NetbirdEditor *self = NETBIRD_EDITOR (object);

	g_clear_object (&self->widget);
	g_clear_object (&self->builder);

	G_OBJECT_CLASS (netbird_editor_parent_class)->dispose (object);
}

static void
netbird_editor_class_init (NetbirdEditorClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}

NMVpnEditor *
nm_vpn_editor_factory_netbird (NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
	NetbirdEditor *self;
	GtkBuilder *builder;

	builder = gtk_builder_new ();
	if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-netbird/nm-netbird-dialog-gtk3.ui", error)) {
		g_object_unref (builder);
		return NULL;
	}

	self = g_object_new (NETBIRD_TYPE_EDITOR, NULL);
	self->builder = builder;

	self->widget = GTK_WIDGET (gtk_builder_get_object (builder, "netbird-vbox"));
	g_object_ref_sink (self->widget);

	self->management_url_entry = GTK_WIDGET (gtk_builder_get_object (builder, "management_url_entry"));
	gtk_entry_set_placeholder_text (GTK_ENTRY (self->management_url_entry), NM_NETBIRD_DEFAULT_MANAGEMENT_URL);
	self->setup_key_entry = GTK_WIDGET (gtk_builder_get_object (builder, "setup_key_entry"));
	self->admin_url_entry = GTK_WIDGET (gtk_builder_get_object (builder, "admin_url_entry"));
	self->interface_name_entry = GTK_WIDGET (gtk_builder_get_object (builder, "interface_name_entry"));
	self->hostname_entry = GTK_WIDGET (gtk_builder_get_object (builder, "hostname_entry"));
	self->mtu_spin = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_spin"));
	self->wireguard_port_spin = GTK_WIDGET (gtk_builder_get_object (builder, "wireguard_port_spin"));
	self->block_inbound_check = GTK_WIDGET (gtk_builder_get_object (builder, "block_inbound_check"));
	self->disable_server_routes_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_server_routes_check"));
	self->block_lan_access_check = GTK_WIDGET (gtk_builder_get_object (builder, "block_lan_access_check"));
	self->disable_client_routes_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_client_routes_check"));
	self->disable_dns_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_dns_check"));
	self->disable_firewall_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_firewall_check"));
	self->disable_ipv6_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_ipv6_check"));
	self->rosenpass_enabled_check = GTK_WIDGET (gtk_builder_get_object (builder, "rosenpass_enabled_check"));
	self->rosenpass_permissive_check = GTK_WIDGET (gtk_builder_get_object (builder, "rosenpass_permissive_check"));
	self->disable_auto_connect_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_auto_connect_check"));
	self->network_monitor_check = GTK_WIDGET (gtk_builder_get_object (builder, "network_monitor_check"));

	init_widgets_from_connection (self, connection);

	g_signal_connect (self->rosenpass_enabled_check, "toggled", G_CALLBACK (rosenpass_enabled_toggled_cb), self);
	connect_changed_signals (self);

	return NM_VPN_EDITOR (self);
}
