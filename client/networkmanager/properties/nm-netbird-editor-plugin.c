#include "nm-netbird-editor-plugin.h"

#include <gmodule.h>

#include "nm-netbird-service-defines.h"

#ifndef NETBIRD_EDITOR_MODULE_PATH_GTK3
#define NETBIRD_EDITOR_MODULE_PATH_GTK3 PLUGINDIR "/libnm-vpn-plugin-netbird-editor.so"
#endif

#ifndef NETBIRD_EDITOR_MODULE_PATH_GTK4
#define NETBIRD_EDITOR_MODULE_PATH_GTK4 PLUGINDIR "/libnm-gtk4-vpn-plugin-netbird-editor.so"
#endif

#define NETBIRD_EDITOR_FACTORY_SYMBOL "nm_vpn_editor_factory_netbird"

typedef NMVpnEditor *(*NetbirdEditorFactoryFunc) (NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error);

/* nm-connection-editor (network-manager-applet) is still a GTK3 process on
 * some distributions even where GTK4 is otherwise the default, while GNOME
 * Settings' own network panel is GTK4. Loading a GTK4-linked editor module
 * into a GTK3 host process (or vice versa) corrupts the GObject type
 * registry, since both toolkits define types with the same names (GtkWidget,
 * GtkEditable, ...). gtk_container_add was removed in GTK4, so its presence
 * in the running process is a reliable way to tell which toolkit is already
 * loaded and pick the matching editor module. */
static gboolean
gtk3_is_loaded (void)
{
	GModule *self_module;
	gpointer symbol;

	self_module = g_module_open (NULL, G_MODULE_BIND_LAZY);
	if (!self_module)
		return FALSE;

	return g_module_symbol (self_module, "gtk_container_add", &symbol);
}

static const char *
editor_module_path (void)
{
	if (gtk3_is_loaded ())
		return NETBIRD_EDITOR_MODULE_PATH_GTK3;
	return NETBIRD_EDITOR_MODULE_PATH_GTK4;
}

enum {
	PROP_NAME = 1,
	PROP_DESCRIPTION,
	PROP_SERVICE,
};

struct _NetbirdEditorPlugin {
	GObject parent;
	GModule *editor_module;
};

static void netbird_editor_plugin_iface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NetbirdEditorPlugin, netbird_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN, netbird_editor_plugin_iface_init))

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
	NetbirdEditorPlugin *self = NETBIRD_EDITOR_PLUGIN (plugin);
	NetbirdEditorFactoryFunc factory;

	if (!self->editor_module) {
		const char *module_path = editor_module_path ();

		self->editor_module = g_module_open (module_path, G_MODULE_BIND_LOCAL);
		if (!self->editor_module) {
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			             "cannot load netbird editor module %s: %s",
			             module_path, g_module_error ());
			return NULL;
		}
	}

	if (!g_module_symbol (self->editor_module, NETBIRD_EDITOR_FACTORY_SYMBOL, (gpointer *) &factory)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "cannot find %s in netbird editor module: %s",
		             NETBIRD_EDITOR_FACTORY_SYMBOL, g_module_error ());
		return NULL;
	}

	return factory (plugin, connection, error);
}

static guint32
get_capabilities (NMVpnEditorPlugin *plugin)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static void
netbird_editor_plugin_iface_init (NMVpnEditorPluginInterface *iface_class)
{
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
}

static void
netbird_editor_plugin_init (NetbirdEditorPlugin *self)
{
}

static void
dispose (GObject *object)
{
	NetbirdEditorPlugin *self = NETBIRD_EDITOR_PLUGIN (object);

	g_clear_pointer (&self->editor_module, g_module_close);

	G_OBJECT_CLASS (netbird_editor_plugin_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, "NetBird");
		break;
	case PROP_DESCRIPTION:
		g_value_set_string (value, "NetBird VPN client");
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_DBUS_SERVICE_NETBIRD);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
netbird_editor_plugin_class_init (NetbirdEditorPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
	object_class->get_property = get_property;

	g_object_class_override_property (object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
	g_object_class_override_property (object_class, PROP_DESCRIPTION, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
	g_object_class_override_property (object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		*error = NULL;
	return g_object_new (NETBIRD_TYPE_EDITOR_PLUGIN, NULL);
}
