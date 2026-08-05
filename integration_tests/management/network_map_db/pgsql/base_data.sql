insert into accounts (id) VALUES('account-1');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-one-resource-id','account-1','group-1-name', '[{"ID":"host-id-1","Type":"host"}]','group-one-resource-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-two-resources-id','account-1','group-2-name', '[{"ID":"subnet-id-1","Type":"subnet"}, {"ID":"host-id-2","Type":"host"}]','group-two-resources-id-public');
insert into groups (id, account_id, name, resources, public_id) VALUES('group-no-resources-id','account-1','group-3-name', null,'group-no-resources-id-public');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-1','group-one-resource-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-2','group-two-resources-id');
insert into group_peers (account_id, peer_id, group_id) VALUES('account-1','peer-id-3','group-two-resources-id');
