CREATE TABLE "wazuh_agent" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"name" text NOT NULL,
	"ip" text,
	"os_name" text,
	"os_version" text,
	"os_platform" text,
	"arch" text,
	"version" text,
	"status" text NOT NULL,
	"last_keep_alive_at" timestamp with time zone,
	"groups" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"registered_at" timestamp with time zone,
	"is_manager" boolean DEFAULT false NOT NULL,
	"vuln_critical" integer,
	"vuln_high" integer,
	"vuln_medium" integer,
	"vuln_low" integer,
	"host_id" text,
	"linked_at" timestamp with time zone,
	"linked_by" text,
	"suggested_host_id" text,
	"suggestion_reason" text,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_connection" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"dashboard_url" text,
	"enrollment_host" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"adapter" text,
	"manager_version" text,
	"indexer_version" text,
	"extra_privileges" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"acknowledged_privileges" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"privileges_acknowledged_at" timestamp with time zone,
	"privileges_acknowledged_by" text,
	"permissions_checked_at" timestamp with time zone,
	"last_sync_at" timestamp with time zone,
	"last_error" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_endpoint" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"kind" text NOT NULL,
	"api_url" text NOT NULL,
	"host" text NOT NULL,
	"port" integer NOT NULL,
	"username" text NOT NULL,
	"secret_id" text,
	"trust_mode" text DEFAULT 'pin' NOT NULL,
	"ca_pem" text,
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
	"last_error" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_fim_event" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"agent_id" text NOT NULL,
	"agent_name" text NOT NULL,
	"path" text NOT NULL,
	"event" text NOT NULL,
	"rule_level" integer
);
--> statement-breakpoint
CREATE TABLE "wazuh_snapshot" (
	"connection_id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"data" jsonb NOT NULL,
	"synced_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_source_ip" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"time_window" text NOT NULL,
	"ip" text NOT NULL,
	"count" integer NOT NULL,
	"groups" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_summary" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"status" text NOT NULL,
	"language" text DEFAULT 'en' NOT NULL,
	"content" text DEFAULT '' NOT NULL,
	"error" text,
	"model" text,
	"prompt_tokens" integer,
	"completion_tokens" integer,
	"latency_ms" integer,
	"requested_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "wazuh_sync_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"state" text NOT NULL,
	"trigger" text NOT NULL,
	"requested_by" text,
	"agent_count" integer,
	"request_count" integer,
	"warnings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "wazuh_agent" ADD CONSTRAINT "wazuh_agent_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_agent" ADD CONSTRAINT "wazuh_agent_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_agent" ADD CONSTRAINT "wazuh_agent_host_id_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."host"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_agent" ADD CONSTRAINT "wazuh_agent_linked_by_user_id_fk" FOREIGN KEY ("linked_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_agent" ADD CONSTRAINT "wazuh_agent_suggested_host_id_host_id_fk" FOREIGN KEY ("suggested_host_id") REFERENCES "public"."host"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_connection" ADD CONSTRAINT "wazuh_connection_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_connection" ADD CONSTRAINT "wazuh_connection_privileges_acknowledged_by_user_id_fk" FOREIGN KEY ("privileges_acknowledged_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_connection" ADD CONSTRAINT "wazuh_connection_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_endpoint" ADD CONSTRAINT "wazuh_endpoint_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_endpoint" ADD CONSTRAINT "wazuh_endpoint_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_endpoint" ADD CONSTRAINT "wazuh_endpoint_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_endpoint" ADD CONSTRAINT "wazuh_endpoint_cert_confirmed_by_user_id_fk" FOREIGN KEY ("cert_confirmed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_fim_event" ADD CONSTRAINT "wazuh_fim_event_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_fim_event" ADD CONSTRAINT "wazuh_fim_event_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_snapshot" ADD CONSTRAINT "wazuh_snapshot_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_snapshot" ADD CONSTRAINT "wazuh_snapshot_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_source_ip" ADD CONSTRAINT "wazuh_source_ip_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_source_ip" ADD CONSTRAINT "wazuh_source_ip_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_summary" ADD CONSTRAINT "wazuh_summary_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_summary" ADD CONSTRAINT "wazuh_summary_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_summary" ADD CONSTRAINT "wazuh_summary_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_sync_run" ADD CONSTRAINT "wazuh_sync_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_sync_run" ADD CONSTRAINT "wazuh_sync_run_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_sync_run" ADD CONSTRAINT "wazuh_sync_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_agent_connection_agent_uq" ON "wazuh_agent" USING btree ("connection_id","agent_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_agent_host_uq" ON "wazuh_agent" USING btree ("host_id") WHERE "wazuh_agent"."host_id" is not null;--> statement-breakpoint
CREATE INDEX "wazuh_agent_org_name_idx" ON "wazuh_agent" USING btree ("organization_id","name","id");--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_connection_org_uq" ON "wazuh_connection" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_endpoint_connection_kind_uq" ON "wazuh_endpoint" USING btree ("connection_id","kind");--> statement-breakpoint
CREATE INDEX "wazuh_fim_event_conn_idx" ON "wazuh_fim_event" USING btree ("connection_id","at");--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_source_ip_uq" ON "wazuh_source_ip" USING btree ("connection_id","time_window","ip");--> statement-breakpoint
CREATE INDEX "wazuh_summary_conn_idx" ON "wazuh_summary" USING btree ("connection_id","created_at");--> statement-breakpoint
CREATE INDEX "wazuh_sync_run_conn_idx" ON "wazuh_sync_run" USING btree ("connection_id","created_at","id");--> statement-breakpoint
CREATE INDEX "wazuh_sync_run_org_idx" ON "wazuh_sync_run" USING btree ("organization_id","created_at","id");