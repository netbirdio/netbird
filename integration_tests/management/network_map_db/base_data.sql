insert into accounts (id, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups,
                      settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
VALUES('account-1','network-1','{"IP":"100.103.0.0","Mask":"//8AAA=="}','{"IP":"fdde:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',1,'["disabled-group-1","disabled-group-2"]',
       true, 86400000000000, false,
       86400000000000, null, '["group-one-resource-id"]', false,
       false, 'disabled', false, false);
insert into accounts (id, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups,
                      settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
VALUES('account-2','network-2','{"IP":"110.0.0.0","Mask":"//8AAA=="}','{"IP":"fddf:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',2,null,
       true, 86400000000000, false,
       86400000000000, null, '["group-two-resources-id"]', false,
       false, 'disabled', false, false);
insert into groups (id, account_id, name, resources, public_id) VALUES('group-one-resource-id','account-1','group-1-name', '[{"ID":"host-id-1","Type":"host"}]','group-one-resource-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-two-resources-id','account-1','group-2-name', '[{"ID":"subnet-id-1","Type":"subnet"}, {"ID":"host-id-2","Type":"host"}]','group-two-resources-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-no-resources-id','account-1','group-3-name', null,'group-no-resources-id-public');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-1','group-one-resource-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-2','group-two-resources-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-3','group-two-resources-id');
insert into peers (id, account_id, "key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-1','account-1','key-1','ssh-key-1','peer-1','["extra-peer-1"]','user-id-1',true,true,'2026-08-06 13:25:59.12999','"10.10.10.1"','"fdf4:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-1.netbird.services',
                   '0.76.0','linux','26.4.1','6.8.0-134-generic','[{"NetIP":"fe80::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ac"},{"NetIP":"192.168.16.1/20","Mac":"00:15:5d:24:0c:ac"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.148.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-2','account-1','key-2','ssh-key-2','peer-2','["extra-peer-2"]','user-id-2',true,true,'2026-08-06 14:25:59.12999','"10.10.100.1"','"fdf5:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-2.netbird.services',
                   '0.76.1','linux','26.4.2','6.8.0-135-generic','[{"NetIP":"fe81::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ad"},{"NetIP":"192.168.17.1/20","Mac":"00:15:5d:24:0c:ad"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',0,
                   'DE','Berlin','"46.201.149.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-3','account-1','key-3','ssh-key-3','peer-3','["extra-peer-3"]','user-id-3',true,true,'2026-08-06 12:25:59.12999','"10.10.200.1"','"fdf6:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-3.netbird.services',
                   '0.76.2','linux','26.4.3','6.8.0-136-generic','[{"NetIP":"fe82::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ae"},{"NetIP":"192.168.18.1/20","Mac":"00:15:5d:24:0c:ae"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.150.187"');

