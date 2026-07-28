-- Schema definitions (must match GORM auto-migrate order)
CREATE TABLE `accounts` (`id` text,`created_by` text,`created_at` datetime,`domain` text,`domain_category` text,`is_domain_primary_account` numeric,`network_identifier` text,`network_net` text,`network_dns` text,`network_serial` integer,`dns_settings_disabled_management_groups` text,`settings_peer_login_expiration_enabled` numeric,`settings_peer_login_expiration` integer,`settings_regular_users_view_blocked` numeric,`settings_groups_propagation_enabled` numeric,`settings_jwt_groups_enabled` numeric,`settings_jwt_groups_claim_name` text,`settings_jwt_allow_groups` text,`settings_extra_peer_approval_enabled` numeric,`settings_extra_integrated_validator_groups` text,PRIMARY KEY (`id`));
CREATE TABLE `groups` (`id` text,`account_id` text,`name` text,`issued` text,`peers` text,`integration_ref_id` integer,`integration_ref_integration_type` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_groups_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));
CREATE TABLE `users` (`id` text,`account_id` text,`role` text,`is_service_user` numeric,`non_deletable` numeric,`service_user_name` text,`auto_groups` text,`blocked` numeric,`last_login` datetime DEFAULT NULL,`created_at` datetime,`issued` text DEFAULT "api",`integration_ref_id` integer,`integration_ref_integration_type` text,PRIMARY KEY (`id`),CONSTRAINT `fk_accounts_users_g` FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`));

-- Test accounts
INSERT INTO accounts VALUES('testAccountId','','2024-10-02 16:01:38.000000000+00:00','test.com','private',1,'testNetworkIdentifier','{"IP":"100.64.0.0","Mask":"//8AAA=="}','',0,'[]',0,86400000000000,0,0,0,'',NULL,NULL,NULL);
INSERT INTO accounts VALUES('otherAccountId','','2024-10-02 16:01:38.000000000+00:00','other.com','private',1,'otherNetworkIdentifier','{"IP":"100.64.0.0","Mask":"//8AAA=="}','',0,'[]',0,86400000000000,0,0,0,'',NULL,NULL,NULL);

-- Test groups
INSERT INTO "groups" VALUES('allowedGroupId','testAccountId','Allowed Group','api','[]',0,'');
INSERT INTO "groups" VALUES('restrictedGroupId','testAccountId','Restricted Group','api','[]',0,'');

-- Test users
INSERT INTO users VALUES('allowedUserId','testAccountId','user',0,0,'','["allowedGroupId"]',0,NULL,'2024-10-02 16:01:38.000000000+00:00','api',0,'');
INSERT INTO users VALUES('nonGroupUserId','testAccountId','user',0,0,'','[]',0,NULL,'2024-10-02 16:01:38.000000000+00:00','api',0,'');
INSERT INTO users VALUES('otherAccountUserId','otherAccountId','user',0,0,'','["allowedGroupId"]',0,NULL,'2024-10-02 16:01:38.000000000+00:00','api',0,'');
