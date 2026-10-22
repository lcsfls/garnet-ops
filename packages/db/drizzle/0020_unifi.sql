CREATE TABLE "unifi_connection" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"api_url" text NOT NULL,
	"host" text NOT NULL,
	"port" integer DEFAULT 443 NOT NULL,
	"api_base" text DEFAULT 'auto' NOT NULL,
	"secret_id" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"cert_status" text DEFAULT 'pending' NOT NULL,
	"cert_fingerprint" text,
	"cert_subject" text,
	"cert_issuer" text,
	"cert_valid_from" timestamp with time zone,
	"cert_valid_to" timestamp with time zone,
	"cert_confirmed_at" timestamp with time zone,
	"cert_confirmed_by" text,
	"candidate_fingerprint" text,
	"candidate_subject" text,
	"candidate_issuer" text,
	"candidate_valid_from" timestamp with time zone,
	"candidate_valid_to" timestamp with time zone,
	"candidate_ca_trusted" boolean,
	"candidate_seen_at" timestamp with time zone,
	"version" text,
	"last_sync_at" timestamp with time zone,
	"last_error" text,
	"ips_enabled" boolean DEFAULT false NOT NULL,
	"ips_username" text,
	"ips_secret_id" text,
	"ips_interval_seconds" integer DEFAULT 60 NOT NULL,
	"ips_enabled_by" text,
	"ips_enabled_at" timestamp with time zone,
	"ips_cursor_at" timestamp with time zone,
	"ips_next_poll_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ips_last_poll_at" timestamp with time zone,
	"ips_last_event_at" timestamp with time zone,
	"ips_last_error" text,
	"ips_failures" integer DEFAULT 0 NOT NULL,
	"ips_rights" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ips_rights_acknowledged" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ips_rights_acknowledged_at" timestamp with time zone,
	"ips_rights_acknowledged_by" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "unifi_connection_ips_interval" CHECK ("unifi_connection"."ips_interval_seconds" between 30 and 600)
);
--> statement-breakpoint
CREATE TABLE "unifi_device" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"site_id" text NOT NULL,
	"unifi_id" text NOT NULL,
	"name" text NOT NULL,
	"model" text,
	"mac" text,
	"ip" text,
	"state" text NOT NULL,
	"raw_state" text NOT NULL,
	"state_since" timestamp with time zone NOT NULL,
	"firmware_version" text,
	"firmware_updatable" boolean,
	"latest_firmware" text,
	"uptime_sec" bigint,
	"offline_syncs" integer DEFAULT 0 NOT NULL,
	"offline_notified" boolean DEFAULT false NOT NULL,
	"firmware_notified_version" text,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "unifi_site" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"unifi_id" text NOT NULL,
	"name" text NOT NULL,
	"internal_ref" text,
	"client_count" integer,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "unifi_sync_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"state" text NOT NULL,
	"trigger" text NOT NULL,
	"requested_by" text,
	"site_count" integer,
	"device_count" integer,
	"request_count" integer,
	"warnings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "unifi_threat_event" (
	"seq" bigint PRIMARY KEY DEFAULT nextval('wazuh_attack_event_seq_seq') NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"doc_id" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip" text NOT NULL,
	"action" text NOT NULL,
	"signature" text NOT NULL,
	"category" text,
	"dest_port" integer,
	"proto" text,
	"site_name" text
);
--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_cert_confirmed_by_user_id_fk" FOREIGN KEY ("cert_confirmed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_ips_secret_id_secret_id_fk" FOREIGN KEY ("ips_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_ips_enabled_by_user_id_fk" FOREIGN KEY ("ips_enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_ips_rights_acknowledged_by_user_id_fk" FOREIGN KEY ("ips_rights_acknowledged_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_connection" ADD CONSTRAINT "unifi_connection_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_device" ADD CONSTRAINT "unifi_device_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_device" ADD CONSTRAINT "unifi_device_connection_id_unifi_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."unifi_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_device" ADD CONSTRAINT "unifi_device_site_id_unifi_site_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."unifi_site"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_site" ADD CONSTRAINT "unifi_site_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_site" ADD CONSTRAINT "unifi_site_connection_id_unifi_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."unifi_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_sync_run" ADD CONSTRAINT "unifi_sync_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_sync_run" ADD CONSTRAINT "unifi_sync_run_connection_id_unifi_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."unifi_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_sync_run" ADD CONSTRAINT "unifi_sync_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_threat_event" ADD CONSTRAINT "unifi_threat_event_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "unifi_threat_event" ADD CONSTRAINT "unifi_threat_event_connection_id_unifi_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."unifi_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "unifi_connection_org_name_uq" ON "unifi_connection" USING btree ("organization_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "unifi_connection_org_endpoint_uq" ON "unifi_connection" USING btree ("organization_id","host","port");--> statement-breakpoint
CREATE UNIQUE INDEX "unifi_device_connection_uq" ON "unifi_device" USING btree ("connection_id","unifi_id");--> statement-breakpoint
CREATE INDEX "unifi_device_org_name_idx" ON "unifi_device" USING btree ("organization_id","name","id");--> statement-breakpoint
CREATE UNIQUE INDEX "unifi_site_connection_uq" ON "unifi_site" USING btree ("connection_id","unifi_id");--> statement-breakpoint
CREATE INDEX "unifi_sync_run_connection_idx" ON "unifi_sync_run" USING btree ("connection_id","created_at","id");--> statement-breakpoint
CREATE INDEX "unifi_sync_run_org_idx" ON "unifi_sync_run" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "unifi_threat_event_doc_uq" ON "unifi_threat_event" USING btree ("connection_id","doc_id");--> statement-breakpoint
CREATE INDEX "unifi_threat_event_org_idx" ON "unifi_threat_event" USING btree ("organization_id","seq");--> statement-breakpoint
CREATE INDEX "unifi_threat_event_org_at_idx" ON "unifi_threat_event" USING btree ("organization_id","at");--> statement-breakpoint
CREATE INDEX "unifi_threat_event_at_idx" ON "unifi_threat_event" USING btree ("at");