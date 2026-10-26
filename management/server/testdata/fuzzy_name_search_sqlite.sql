alter table users add column name_hash_1 integer;
alter table users add column name_hash_2 integer;
alter table users add column name_hash_3 integer;
alter table users add column name_hash_4 integer;
alter table users add column name_hash_5 integer;
alter table users add column name_hash_6 integer;

insert into accounts (id, domain, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups,
                      settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
VALUES('account-1','account-1-test.com','network-1','{"IP":"100.103.0.0","Mask":"//8AAA=="}','{"IP":"fdde:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',1,'["disabled-group-1","disabled-group-2"]',
       true, 86400000000000, false,
       86400000000000, null, '["group-one-resource-id"]', false,
       false, 'disabled', false, false);

