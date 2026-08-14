#ifndef NM_NETBIRD_EDITOR_H
#define NM_NETBIRD_EDITOR_H

#include <glib-object.h>
#include <NetworkManager.h>

#define NETBIRD_TYPE_EDITOR (netbird_editor_get_type ())
G_DECLARE_FINAL_TYPE (NetbirdEditor, netbird_editor, NETBIRD, EDITOR, GObject)

NMVpnEditor *nm_vpn_editor_factory_netbird (NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error);

#endif /* NM_NETBIRD_EDITOR_H */
