insert into accounts (id, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups)
VALUES('account-1','network-1','{"IP":"100.103.0.0","Mask":"//8AAA=="}','{"IP":"fdde:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',1,'["disabled-group-1","disabled-group-2"]');
insert into accounts (id, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups)
VALUES('account-2','network-2','{"IP":"110.0.0.0","Mask":"//8AAA=="}','{"IP":"fddf:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',2,null);
insert into groups (id, account_id, name, resources, public_id) VALUES('group-one-resource-id','account-1','group-1-name', '[{"ID":"host-id-1","Type":"host"}]','group-one-resource-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-two-resources-id','account-1','group-2-name', '[{"ID":"subnet-id-1","Type":"subnet"}, {"ID":"host-id-2","Type":"host"}]','group-two-resources-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-no-resources-id','account-1','group-3-name', null,'group-no-resources-id-public');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-1','group-one-resource-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-2','group-two-resources-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-3','group-two-resources-id');
