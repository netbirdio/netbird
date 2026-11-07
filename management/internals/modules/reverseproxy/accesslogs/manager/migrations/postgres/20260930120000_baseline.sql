-- +goose Up
SET LOCAL lock_timeout = '5s';
CREATE TABLE "access_log_entries" ("id" text,"account_id" text,"service_id" text,"timestamp" timestamptz,"location_connection_ip" text,"location_country_code" text,"location_city_name" text,"location_geo_name_id" bigint,"subdivision_code" text,"method" text,"host" text,"path" text,"duration" bigint,"status_code" bigint,"reason" text,"user_id" text,"auth_method_used" text,"bytes_upload" bigint,"bytes_download" bigint,"protocol" text,"metadata" text,"agent_network" boolean,PRIMARY KEY ("id"));
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_duration" ON "access_log_entries" ("duration");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_host" ON "access_log_entries" ("host");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_agent_network" ON "access_log_entries" ("agent_network");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_bytes_download" ON "access_log_entries" ("bytes_download");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_auth_method_used" ON "access_log_entries" ("auth_method_used");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_account_id" ON "access_log_entries" ("account_id");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_protocol" ON "access_log_entries" ("protocol");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_user_id" ON "access_log_entries" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_path" ON "access_log_entries" ("path");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_service_id" ON "access_log_entries" ("service_id");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_bytes_upload" ON "access_log_entries" ("bytes_upload");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_status_code" ON "access_log_entries" ("status_code");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_method" ON "access_log_entries" ("method");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_timestamp" ON "access_log_entries" ("timestamp");
CREATE INDEX IF NOT EXISTS "idx_access_log_entries_account_timestamp" ON "access_log_entries" ("account_id","timestamp");
