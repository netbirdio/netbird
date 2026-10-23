CREATE EXTENSION bloom;

CREATE OR REPLACE FUNCTION bitcheck(bigint, INTEGER)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
SECURITY INVOKER
PARALLEL SAFE
COST 0.01
AS $$
  SELECT CASE
    WHEN $1 & (1 << ($2 - 1)) > 0 THEN $2
    ELSE -$2
  END
$$
;

alter table users add column if not exists name_hash_1 bigint, 
add column if not exists name_hash_2 bigint,
add column if not exists name_hash_3 bigint,
add column if not exists name_hash_4 bigint,
add column if not exists name_hash_5 bigint;

create index if not exists name_idx_1 on users
  using bloom (
    bitcheck(name_hash_1, 1)
    ,bitcheck(name_hash_1, 2)
    ,bitcheck(name_hash_1, 3)
    ,bitcheck(name_hash_1, 4)
    ,bitcheck(name_hash_1, 5)
    ,bitcheck(name_hash_1, 6)
    ,bitcheck(name_hash_1, 7)
    ,bitcheck(name_hash_1, 8)
    ,bitcheck(name_hash_1, 9)
    ,bitcheck(name_hash_1, 10)
    ,bitcheck(name_hash_1, 11)
    ,bitcheck(name_hash_1, 12)
    ,bitcheck(name_hash_1, 13)
    ,bitcheck(name_hash_1, 14)
    ,bitcheck(name_hash_1, 15)
    ,bitcheck(name_hash_1, 16)
    ,bitcheck(name_hash_1, 17)
    ,bitcheck(name_hash_1, 18)
    ,bitcheck(name_hash_1, 19)
    ,bitcheck(name_hash_1, 20)
    ,bitcheck(name_hash_1, 21)
    ,bitcheck(name_hash_1, 22)
    ,bitcheck(name_hash_1, 23)
    ,bitcheck(name_hash_1, 24)
    ,bitcheck(name_hash_1, 25)
    ,bitcheck(name_hash_1, 26)
    ,bitcheck(name_hash_1, 27)
    ,bitcheck(name_hash_1, 28)
    ,bitcheck(name_hash_1, 29)
    ,bitcheck(name_hash_1, 20)
    ,bitcheck(name_hash_1, 31)
    ,bitcheck(name_hash_1, 32)
  ) with (length=128);
create index if not exists name_idx_2 on users
  using bloom (
    bitcheck(name_hash_2, 1)
    ,bitcheck(name_hash_2, 2)
    ,bitcheck(name_hash_2, 3)
    ,bitcheck(name_hash_2, 4)
    ,bitcheck(name_hash_2, 5)
    ,bitcheck(name_hash_2, 6)
    ,bitcheck(name_hash_2, 7)
    ,bitcheck(name_hash_2, 8)
    ,bitcheck(name_hash_2, 9)
    ,bitcheck(name_hash_2, 10)
    ,bitcheck(name_hash_2, 11)
    ,bitcheck(name_hash_2, 12)
    ,bitcheck(name_hash_2, 13)
    ,bitcheck(name_hash_2, 14)
    ,bitcheck(name_hash_2, 15)
    ,bitcheck(name_hash_2, 16)
    ,bitcheck(name_hash_2, 17)
    ,bitcheck(name_hash_2, 18)
    ,bitcheck(name_hash_2, 19)
    ,bitcheck(name_hash_2, 20)
    ,bitcheck(name_hash_2, 21)
    ,bitcheck(name_hash_2, 22)
    ,bitcheck(name_hash_2, 23)
    ,bitcheck(name_hash_2, 24)
    ,bitcheck(name_hash_2, 25)
    ,bitcheck(name_hash_2, 26)
    ,bitcheck(name_hash_2, 27)
    ,bitcheck(name_hash_2, 28)
    ,bitcheck(name_hash_2, 29)
    ,bitcheck(name_hash_2, 20)
    ,bitcheck(name_hash_2, 31)
    ,bitcheck(name_hash_2, 32)
  ) with (length=128);
create index if not exists name_idx_3 on users
  using bloom (
    bitcheck(name_hash_3, 1)
    ,bitcheck(name_hash_3, 2)
    ,bitcheck(name_hash_3, 3)
    ,bitcheck(name_hash_3, 4)
    ,bitcheck(name_hash_3, 5)
    ,bitcheck(name_hash_3, 6)
    ,bitcheck(name_hash_3, 7)
    ,bitcheck(name_hash_3, 8)
    ,bitcheck(name_hash_3, 9)
    ,bitcheck(name_hash_3, 10)
    ,bitcheck(name_hash_3, 11)
    ,bitcheck(name_hash_3, 12)
    ,bitcheck(name_hash_3, 13)
    ,bitcheck(name_hash_3, 14)
    ,bitcheck(name_hash_3, 15)
    ,bitcheck(name_hash_3, 16)
    ,bitcheck(name_hash_3, 17)
    ,bitcheck(name_hash_3, 18)
    ,bitcheck(name_hash_3, 19)
    ,bitcheck(name_hash_3, 20)
    ,bitcheck(name_hash_3, 21)
    ,bitcheck(name_hash_3, 22)
    ,bitcheck(name_hash_3, 23)
    ,bitcheck(name_hash_3, 24)
    ,bitcheck(name_hash_3, 25)
    ,bitcheck(name_hash_3, 26)
    ,bitcheck(name_hash_3, 27)
    ,bitcheck(name_hash_3, 28)
    ,bitcheck(name_hash_3, 29)
    ,bitcheck(name_hash_3, 20)
    ,bitcheck(name_hash_3, 31)
    ,bitcheck(name_hash_3, 32)
  ) with (length=128);
create index if not exists name_idx_4 on users
  using bloom (
    bitcheck(name_hash_4, 1)
    ,bitcheck(name_hash_4, 2)
    ,bitcheck(name_hash_4, 3)
    ,bitcheck(name_hash_4, 4)
    ,bitcheck(name_hash_4, 5)
    ,bitcheck(name_hash_4, 6)
    ,bitcheck(name_hash_4, 7)
    ,bitcheck(name_hash_4, 8)
    ,bitcheck(name_hash_4, 9)
    ,bitcheck(name_hash_4, 10)
    ,bitcheck(name_hash_4, 11)
    ,bitcheck(name_hash_4, 12)
    ,bitcheck(name_hash_4, 13)
    ,bitcheck(name_hash_4, 14)
    ,bitcheck(name_hash_4, 15)
    ,bitcheck(name_hash_4, 16)
    ,bitcheck(name_hash_4, 17)
    ,bitcheck(name_hash_4, 18)
    ,bitcheck(name_hash_4, 19)
    ,bitcheck(name_hash_4, 20)
    ,bitcheck(name_hash_4, 21)
    ,bitcheck(name_hash_4, 22)
    ,bitcheck(name_hash_4, 23)
    ,bitcheck(name_hash_4, 24)
    ,bitcheck(name_hash_4, 25)
    ,bitcheck(name_hash_4, 26)
    ,bitcheck(name_hash_4, 27)
    ,bitcheck(name_hash_4, 28)
    ,bitcheck(name_hash_4, 29)
    ,bitcheck(name_hash_4, 20)
    ,bitcheck(name_hash_4, 31)
    ,bitcheck(name_hash_4, 32)
  ) with (length=128);
create index if not exists name_idx_5 on users
  using bloom (
    bitcheck(name_hash_5, 1)
    ,bitcheck(name_hash_5, 2)
    ,bitcheck(name_hash_5, 3)
    ,bitcheck(name_hash_5, 4)
    ,bitcheck(name_hash_5, 5)
    ,bitcheck(name_hash_5, 6)
    ,bitcheck(name_hash_5, 7)
    ,bitcheck(name_hash_5, 8)
    ,bitcheck(name_hash_5, 9)
    ,bitcheck(name_hash_5, 10)
    ,bitcheck(name_hash_5, 11)
    ,bitcheck(name_hash_5, 12)
    ,bitcheck(name_hash_5, 13)
    ,bitcheck(name_hash_5, 14)
    ,bitcheck(name_hash_5, 15)
    ,bitcheck(name_hash_5, 16)
    ,bitcheck(name_hash_5, 17)
    ,bitcheck(name_hash_5, 18)
    ,bitcheck(name_hash_5, 19)
    ,bitcheck(name_hash_5, 20)
    ,bitcheck(name_hash_5, 21)
    ,bitcheck(name_hash_5, 22)
    ,bitcheck(name_hash_5, 23)
    ,bitcheck(name_hash_5, 24)
    ,bitcheck(name_hash_5, 25)
    ,bitcheck(name_hash_5, 26)
    ,bitcheck(name_hash_5, 27)
    ,bitcheck(name_hash_5, 28)
    ,bitcheck(name_hash_5, 29)
    ,bitcheck(name_hash_5, 20)
    ,bitcheck(name_hash_5, 31)
    ,bitcheck(name_hash_5, 32)
  ) with (length=128);

insert into accounts (id, domain, network_identifier, network_net, network_net_v6, network_dns, network_serial,dns_settings_disabled_management_groups,
                      settings_peer_login_expiration_enabled, settings_peer_login_expiration, settings_peer_inactivity_expiration_enabled,
                      settings_peer_inactivity_expiration, settings_dns_domain, settings_ipv6_enabled_groups, settings_routing_peer_dns_resolution_enabled,
                      settings_lazy_connection_enabled, settings_auto_update_version, settings_auto_update_always, settings_metrics_push_enabled)
VALUES('account-1','account-1-test.com','network-1','{"IP":"100.103.0.0","Mask":"//8AAA=="}','{"IP":"fdde:e995:fd38:a465::","Mask":"//////////8AAAAAAAAAAA=="}','',1,'["disabled-group-1","disabled-group-2"]',
       true, 86400000000000, false,
       86400000000000, null, '["group-one-resource-id"]', false,
       false, 'disabled', false, false);
-- insert into users (id,account_id,"name",email) values('user-1','account-1','','');

