CREATE TABLE `accounts` (`id` text,`created_by` text,`created_at` datetime,`domain` text,`domain_category` text,`is_domain_primary_account` numeric,`network_identifier` text,`network_net` text,`network_dns` text,`network_serial` integer,`dns_settings_disabled_management_groups` text,`settings_peer_login_expiration_enabled` numeric,`settings_peer_login_expiration` integer,`settings_regular_users_view_blocked` numeric,`settings_groups_propagation_enabled` numeric,`settings_jwt_groups_enabled` numeric,`settings_jwt_groups_claim_name` text,`settings_jwt_allow_groups` text,`settings_extra_peer_approval_enabled` numeric,`settings_extra_integrated_validator_groups` text,PRIMARY KEY (`id`));
CREATE TABLE `setup_keys` (`id` text,`account_id` text,`key` text,`name` text,`type` text,`created_at` datetime,`expires_at` datetime,`updated_at` datetime,`revoked` numeric,`used_times` integer,`last_used` datetime DEFAULT NULL,`auto_groups` text,`usage_limit` integer,`ephemeral` numeric,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_setup_keys_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `peers` (`id` text,`account_id` text,`key` text,`setup_key` text,`ip` text,`meta_hostname` text,`meta_go_os` text,`meta_kernel` text,`meta_core` text,`meta_platform` text,`meta_os` text,`meta_os_version` text,`meta_wt_version` text,`meta_ui_version` text,`meta_kernel_version` text,`meta_network_addresses` text,`meta_system_serial_number` text,`meta_system_product_name` text,`meta_system_manufacturer` text,`meta_environment` text,`meta_files` text,`name` text,`dns_label` text,`peer_status_last_seen` datetime,`peer_status_connected` numeric,`peer_status_login_expired` numeric,`peer_status_requires_approval` numeric,`user_id` text,`ssh_key` text,`ssh_enabled` numeric,`login_expiration_enabled` numeric,`last_login` datetime,`created_at` datetime,`ephemeral` numeric,`location_connection_ip` text,`location_country_code` text,`location_city_name` text,`location_geo_name_id` integer,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_peers_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `users` (`id` text,`account_id` text,`role` text,`is_service_user` numeric,`non_deletable` numeric,`service_user_name` text,`auto_groups` text,`blocked` numeric,`last_login` datetime DEFAULT NULL,`created_at` datetime,`issued` text DEFAULT "api",`integration_ref_id` integer,`integration_ref_integration_type` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_users_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `personal_access_tokens` (`id` text,`user_id` text,`name` text,`hashed_token` text,`expiration_date` datetime,`created_by` text,`created_at` datetime,`last_used` datetime,PRIMARY KEY (`id`),CONSTRAINT `fk_users_pa_ts_g` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`));
CREATE TABLE `groups` (`id` text,`account_id` text,`name` text,`issued` text,`peers` text,`integration_ref_id` integer,`integration_ref_integration_type` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_groups_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `policies` (`id` text,`account_id` text,`name` text,`description` text,`enabled` numeric,`source_posture_checks` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_policies` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `policy_rules` (`id` text,`policy_id` text,`name` text,`description` text,`enabled` numeric,`action` text,`destinations` text,`sources` text,`bidirectional` numeric,`protocol` text,`ports` text,`port_ranges` text,PRIMARY KEY (`id`),CONSTRAINT `fk_policies_rules` FOREIGN KEY (`policy_id`) REFERENCES `policies`(`id`) ON DELETE CASCADE);
CREATE TABLE `routes` (`id` text,`account_id` text,`network` text,`domains` text,`keep_route` numeric,`net_id` text,`description` text,`peer` text,`peer_groups` text,`network_type` integer,`masquerade` numeric,`metric` integer,`enabled` numeric,`groups` text,`access_control_groups` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_routes_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `name_server_groups` (`id` text,`account_id` text,`name` text,`description` text,`name_servers` text,`groups` text,`primary` numeric,`domains` text,`enabled` numeric,`search_domains_enabled` numeric,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_name_server_groups_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `installations` (`id` integer,`installation_id_value` text,PRIMARY KEY (`id`));
CREATE TABLE `extra_settings` (`peer_approval_enabled` numeric,`integrated_validator_groups` text);
CREATE TABLE `posture_checks` (`id` text,`name` text,`description` text,`account_id` text,`checks` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_posture_checks` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `network_addresses` (`net_ip` text,`mac` text);
CREATE INDEX `idx_accounts_domain` ON `accounts`(`domain`);
CREATE INDEX `idx_setup_keys_account_id` ON `setup_keys`(`account_id`);
CREATE INDEX `idx_peers_key` ON `peers`(`key`);
CREATE INDEX `idx_peers_account_id` ON `peers`(`account_id`);
CREATE INDEX `idx_users_account_id` ON `users`(`account_id`);
CREATE INDEX `idx_personal_access_tokens_user_id` ON `personal_access_tokens`(`user_id`);
CREATE INDEX `idx_groups_account_id` ON `groups`(`account_id`);
CREATE INDEX `idx_policies_account_id` ON `policies`(`account_id`);
CREATE INDEX `idx_policy_rules_policy_id` ON `policy_rules`(`policy_id`);
CREATE INDEX `idx_routes_account_id` ON `routes`(`account_id`);
CREATE INDEX `idx_name_server_groups_account_id` ON `name_server_groups`(`account_id`);
CREATE INDEX `idx_posture_checks_account_id` ON `posture_checks`(`account_id`);

INSERT INTO accounts VALUES('bf1c8084-ba50-4ce7-9439-34653001fc3b','','2024-10-02 16:04:23.538411+02:00','test.com','private',1,'af1c8024-ha40-4ce2-9418-34653101fc3c','{"IP":"100.64.0.0","Mask":"//8AAA=="}','',0,'[]',0,86400000000000,0,0,0,'',NULL,NULL,NULL);
INSERT INTO setup_keys VALUES('','bf1c8084-ba50-4ce7-9439-34653001fc3b','A2C8E62B-38F5-4553-B31E-DD66C696CEBB','Default key','reusable','2021-08-19 20:46:20.005936822+02:00','2321-09-18 20:46:20.005936822+02:00','2021-08-19 20:46:20.005936822+02:00',0,0,NULL,'[]',0,0);
INSERT INTO peers VALUES('cfefqs706sqkneg59g4g','bf1c8084-ba50-4ce7-9439-34653001fc3b','MI5mHfJhbggPfD3FqEIsXm8X5bSWeUI2LhO9MpEEtWA=','','"100.103.179.238"','Ubuntu-2204-jammy-amd64-base','linux','Linux','22.04','x86_64','Ubuntu','','development','','',NULL,'','','','{"Cloud":"","Platform":""}',NULL,'crocodile','crocodile','2023-02-13 12:37:12.635454796+00:00',1,0,0,'edafee4e-63fb-11ec-90d6-0242ac120003','AAAAC3NzaC1lZDI1NTE5AAAAIJN1NM4bpB9K',0,0,'2024-10-02 14:04:23.523293+00:00','2024-10-02 16:04:23.538926+02:00',0,'""','','',0);
INSERT INTO peers VALUES('cfeg6sf06sqkneg59g50','bf1c8084-ba50-4ce7-9439-34653001fc3b','zMAOKUeIYIuun4n0xPR1b3IdYZPmsyjYmB2jWCuloC4=','','"100.103.26.180"','borg','linux','Linux','22.04','x86_64','Ubuntu','','development','','',NULL,'','','','{"Cloud":"","Platform":""}',NULL,'dingo','dingo','2023-02-21 09:37:42.565899199+00:00',0,0,0,'f4f6d672-63fb-11ec-90d6-0242ac120003','AAAAC3NzaC1lZDI1NTE5AAAAILHW',1,0,'2024-10-02 14:04:23.523293+00:00','2024-10-02 16:04:23.538926+02:00',0,'""','','',0);
INSERT INTO users VALUES('edafee4e-63fb-11ec-90d6-0242ac120003','bf1c8084-ba50-4ce7-9439-34653001fc3b','admin',0,0,'','[]',0,NULL,'2024-10-02 16:04:23.539152+02:00','api',0,'');
INSERT INTO users VALUES('f4f6d672-63fb-11ec-90d6-0242ac120003','bf1c8084-ba50-4ce7-9439-34653001fc3b','user',0,0,'','[]',0,NULL,'2024-10-02 16:04:23.539152+02:00','api',0,'');
INSERT INTO "groups" VALUES('cfefqs706sqkneg59g3g','bf1c8084-ba50-4ce7-9439-34653001fc3b','All','api','["cfefqs706sqkneg59g4g","cfeg6sf06sqkneg59g50"]',0,'');
INSERT INTO "groups" VALUES('cfefqs706sqkneg59g4h','bf1c8084-ba50-4ce7-9439-34653001fc3b','groupA','api','',0,'');
INSERT INTO installations VALUES(1,'');
