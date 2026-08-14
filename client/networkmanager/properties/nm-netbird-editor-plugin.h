#ifndef NM_NETBIRD_EDITOR_PLUGIN_H
#define NM_NETBIRD_EDITOR_PLUGIN_H

#include <glib-object.h>
#include <NetworkManager.h>

#define NETBIRD_TYPE_EDITOR_PLUGIN (netbird_editor_plugin_get_type ())
G_DECLARE_FINAL_TYPE (NetbirdEditorPlugin, netbird_editor_plugin, NETBIRD, EDITOR_PLUGIN, GObject)

#endif /* NM_NETBIRD_EDITOR_PLUGIN_H */
