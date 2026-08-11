insert into peers (id, account_id, "key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-1','account-1','key-1','ssh-key-1','peer-1','["extra-peer-1"]','user-id-1',true,true,'2026-08-06 13:25:59.12999+00','"10.10.10.1"','"fdf4:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-1.netbird.services',
                   '0.76.0','linux','26.4.1','6.8.0-134-generic','[{"NetIP":"fe80::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ac"},{"NetIP":"192.168.16.1/20","Mac":"00:15:5d:24:0c:ac"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.148.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-2','account-1','key-2','ssh-key-2','peer-2','["extra-peer-2"]','user-id-2',true,true,'2026-08-06 14:25:59.12999+00','"10.10.100.1"','"fdf5:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-2.netbird.services',
                   '0.76.1','linux','26.4.2','6.8.0-135-generic','[{"NetIP":"fe81::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ad"},{"NetIP":"192.168.17.1/20","Mac":"00:15:5d:24:0c:ad"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',0,
                   'DE','Berlin','"46.201.149.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-3','account-1','key-3','ssh-key-3','peer-3','["extra-peer-3"]','user-id-3',true,true,'2026-08-06 12:25:59.12999+00','"10.10.200.1"','"fdf6:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-3.netbird.services',
                   '0.76.2','linux','26.4.3','6.8.0-136-generic','[{"NetIP":"fe82::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ae"},{"NetIP":"192.168.18.1/20","Mac":"00:15:5d:24:0c:ae"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.150.187"');
