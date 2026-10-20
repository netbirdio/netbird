insert into accounts (id, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups,
                      settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
VALUES('account-33','network-331','{"IP":"100.103.0.0","Mask":"//8AAA=="}','{"IP":"fdde:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',1,'["disabled-group-1","disabled-group-2"]',
       true, 86400000000000, false,
       86400000000000, null, '["33-group-one-resource-id"]', false,
       false, 'disabled', false, false);
insert into groups (id, account_id, name, resources, public_id) VALUES('33-group-one-resource-id','account-33','group-1-name', '[{"ID":"host-id-1","Type":"host"}]','group-one-resource-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('33-group-two-resources-id','account-33','group-2-name', '[{"ID":"subnet-id-1","Type":"subnet"}, {"ID":"host-id-2","Type":"host"}]','33-group-two-resources-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('33-group-no-resources-id','account-33','group-3-name', null,'33-group-no-resources-id-public');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-33','peer-id-331','33-group-one-resource-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-33','peer-id-332','33-group-two-resources-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-33','peer-id-333','33-group-two-resources-id');
insert into peers (id, account_id, "key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-331','account-33','key-331','ssh-key-1','peer-1','["extra-peer-1"]','user-id-1',true,true,'2026-08-06 13:25:59.12999','"10.10.10.1"','"fdf4:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-1.netbird.services',
                   '0.76.0','linux','26.4.1','6.8.0-134-generic','[{"NetIP":"fe80::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ac"},{"NetIP":"192.168.16.1/20","Mac":"00:15:5d:24:0c:ac"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.148.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-332','account-33','key-332','ssh-key-2','peer-2','["extra-peer-2"]','user-id-2',true,true,'2026-08-06 14:25:59.12999','"10.10.100.1"','"fdf5:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-2.netbird.services',
                   '0.76.1','linux','26.4.2','6.8.0-135-generic','[{"NetIP":"fe81::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ad"},{"NetIP":"192.168.17.1/20","Mac":"00:15:5d:24:0c:ad"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',0,
                   'DE','Berlin','"46.201.149.187"');
insert into peers (id,account_id,"key", ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	            peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	            meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files,
                   meta_capabilities, meta_flags, meta_sync_message_version,
	            location_country_code, location_city_name, location_connection_ip)
            values('peer-id-333','account-33','key-333','ssh-key-3','peer-3','["extra-peer-3"]','user-id-3',true,true,'2026-08-06 12:25:59.12999','"10.10.200.1"','"fdf6:ba80:6aa5:89f1:44d7:8701:8699:4940"',
                   false,true,true,'cluster-3.netbird.services',
                   '0.76.2','linux','26.4.3','6.8.0-136-generic','[{"NetIP":"fe82::8b4c:973f:a76b:3771/64","Mac":"00:15:5d:24:0c:ae"},{"NetIP":"192.168.18.1/20","Mac":"00:15:5d:24:0c:ae"}]','[{"Path":"/usr/bin/netbird","Exist":false,"ProcessIsRunning":false}]',
                   '[1,2]','{"RosenpassEnabled":false,"RosenpassPermissive":false,"ServerSSHAllowed":true,"DisableClientRoutes":false,"DisableServerRoutes":false,"DisableDNS":false,"DisableFirewall":false,"BlockLANAccess":false,"BlockInbound":false,"DisableIPv6":false,"LazyConnectionEnabled":false}',1,
                   'DE','Berlin','"46.201.150.187"');

insert into zones (id, account_id, domain, enabled, enable_search_domain, distribution_groups)
		VALUES('zone-331','account-33','test-331.com',true,true,'["33-group-one-resource-id"]');
insert into zones (id, account_id, domain, enabled, enable_search_domain, distribution_groups)
		VALUES('zone-332','account-33','disabled-331.com',false,true,'["33-group-one-resource-id"]');
insert into zones (id, account_id, domain, enabled, enable_search_domain, distribution_groups)
		VALUES('zone-333','account-33','search-off-331.com',true,false,'["33-group-two-resources-id"]');
insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-333','account-33','zone-332','test.disabled-331.com','A',1800,'1.1.1.9');
insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-334','account-33','zone-333','test.search-off-331.com','A',1800,'1.1.1.3');
insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-335','account-33','zone-333','alias.search-off-331.com','CNAME',1800,'test.search-off-331.com');
insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-331','account-33','zone-331','test.test-331.com','A',1800,'1.1.1.1');
insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-332','account-33','zone-331','test2.test-331.com','A',1800,'1.1.1.2');

insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-331','account-33','test-331.com','target-1.cluster.local');

insert into name_server_groups (id, public_id, name, description, name_servers, groups, domains, enabled, search_domains_enabled, "primary", account_id)
		VALUES('nsgroup-331','nsgroup-1-public','nsgroup-1','nsgroup-1','[{"IP":"192.168.31.2","NSType":1,"Port":53}]','["33-group-one-resource-id"]','["test-1.com"]',TRUE,FALSE,TRUE,'account-33');
insert into name_server_groups (id, public_id, name, description, name_servers, groups, domains, enabled, search_domains_enabled,"primary",account_id)
		VALUES('nsgroup-332','nsgroup-2-public','nsgroup-2','nsgroup-2','[{"IP":"192.168.32.3","NSType":1,"Port":53}]','["33-group-one-resource-id","33-group-no-resources-id"]','["test-1.com","test-2.com"]',TRUE,FALSE,TRUE,'account-33');

insert into network_resources (id, account_id, network_id, public_id, name, description, type, domain, prefix, enabled)
		VALUES('net-resource-331','account-33','network-331','net-resource-public-1','network-resource-1','network-resource-1','subnet','','"10.0.0.0/16"',TRUE);
insert into network_resources (id, account_id, network_id, public_id, name, description, type, domain, prefix, enabled)
		VALUES('net-resource-332','account-33','network-332','net-resource-public-2','network-resource-2','network-resource-2','domain','test.com','',TRUE);

insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-331','account-33','public-id-1','peer-id-331','network-id-1',TRUE,999,TRUE,'["33-group-one-resource-id"]');
insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-332','account-33','public-id-2','','network-id-2',TRUE,333,TRUE,'["33-group-two-resources-id","33-group-no-resources-id"]');

insert into networks (id, account_id, public_id) VALUES('network-331','account-33','network-1-public');
insert into networks (id, account_id, public_id) VALUES('network-332','account-33','network-2-public');

insert into policies (id, public_id, account_id, enabled, source_posture_checks)
		 values('policy-331','policy-1-public','account-33',true,'["posture-checks-1","posture-checks-2"]');
insert into policy_rules (id, policy_id, enabled, action, protocol, bidirectional, sources, destinations,
		                           source_resource, destination_resource, ports, port_ranges,
								   authorized_groups, authorized_user)
		 values('policy-331-rule-1','policy-331',true,'accept','tcp',true,'["33-group-one-resource-id","33-group-two-resources-id"]','["33-group-one-resource-id","33-group-two-resources-id"]',
		        '{"ID":"host-id-1","Type":"host"}','{"ID":"domain-331","Type":"domain"}','["8080","8443"]', '[{"Start":8080,"End":8090}]',
				'{"33-group-one-resource-id":["user-1", "user-2"]}','user-3');

insert into posture_checks (id, account_id, public_id, checks)
		VALUES('posturecheck-331','account-33','posturecheck-1-public',
		'{"NBVersionCheck":{"MinVersion":"0.25.0"},
		  "OSVersionCheck":{"Darwin":{"MinVersion":"12.0"}},
		  "GeoLocationCheck":{"Locations":[{"CountryCode":"FI","CityName":""}],"Action":"allow"},
		  "PeerNetworkRangeCheck":{"Action":"deny","Ranges":["192.168.0.1/24"]}}');

insert into routes (id, account_id, public_id, network, domains, keep_route, net_id, description,
	                         peer, peer_groups, network_type, masquerade, metric, enabled, 
	                         groups, access_control_groups, skip_auto_apply)
		VALUES('route-331','account-33','route-1-public','"172.0.0.0/16"','["test-1.com"]',true,'route-331-net-id','route-1',
		        'peer-id-331','["33-group-one-resource-id"]',1,true,9999,true,
				'["33-group-one-resource-id"]','["33-group-one-resource-id"]',false);

insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-331','account-33',true,true,'["33-group-one-resource-id"]','test-1.com','test-332.com');
