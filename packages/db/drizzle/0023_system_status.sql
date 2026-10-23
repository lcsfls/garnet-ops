CREATE TABLE "system_report" (
	"key" text PRIMARY KEY NOT NULL,
	"data" jsonb NOT NULL,
	"reported_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "worker_heartbeat" (
	"instance_id" text PRIMARY KEY NOT NULL,
	"version" text NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"beat_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "last_probe_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "last_probe_ok" boolean;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "last_probe_error" text;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "last_probe_url" text;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD COLUMN "last_reconcile_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD COLUMN "last_reconcile_result" text;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD COLUMN "last_reconcile_checked" integer;--> statement-breakpoint
CREATE INDEX "worker_heartbeat_beat_idx" ON "worker_heartbeat" USING btree ("beat_at");