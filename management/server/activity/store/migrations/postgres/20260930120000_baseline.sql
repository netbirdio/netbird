-- +goose Up
SET LOCAL lock_timeout = '5s';
CREATE TABLE "events" ("timestamp" timestamptz,"activity" integer,"id" bigserial,"initiator_id" text,"target_id" text,"account_id" text,"meta" text,PRIMARY KEY ("id"));
CREATE INDEX IF NOT EXISTS "idx_events_account_id" ON "events" ("account_id");
CREATE TABLE "deleted_users" ("id" text,"email" text NOT NULL,"name" text,"enc_algo" text NOT NULL,PRIMARY KEY ("id"));
