-- +goose Up
CREATE TABLE `events` (`timestamp` datetime,`activity` integer,`id` integer PRIMARY KEY AUTOINCREMENT,`initiator_id` text,`target_id` text,`account_id` text,`meta` text);
CREATE INDEX `idx_events_account_id` ON `events`(`account_id`);
CREATE TABLE `deleted_users` (`id` text,`email` text NOT NULL,`name` text,`enc_algo` text NOT NULL,PRIMARY KEY (`id`));
