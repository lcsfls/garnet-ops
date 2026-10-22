CREATE TABLE "attack_osint_result" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"provider" text NOT NULL,
	"ip" text NOT NULL,
	"score" integer NOT NULL,
	"reports" integer NOT NULL,
	"last_reported_at" timestamp with time zone,
	"checked_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "attack_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"retention_days" integer DEFAULT 90 NOT NULL,
	"geoip_download_enabled" boolean DEFAULT false NOT NULL,
	"geoip_download_enabled_by" text,
	"geoip_download_enabled_at" timestamp with time zone,
	"geoip_download_last_attempt_at" timestamp with time zone,
	"geoip_download_last_error" text,
	"osint_enabled" boolean DEFAULT false NOT NULL,
	"osint_provider" text,
	"osint_secret_id" text,
	"osint_top_n" integer DEFAULT 20 NOT NULL,
	"osint_daily_budget" integer DEFAULT 300 NOT NULL,
	"osint_acknowledged_by" text,
	"osint_acknowledged_at" timestamp with time zone,
	"osint_usage_day" date,
	"osint_usage_count" integer DEFAULT 0 NOT NULL,
	"osint_last_run_at" timestamp with time zone,
	"osint_last_error" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "attack_summary" (
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
CREATE TABLE "geoip_asn_range" (
	"dataset_id" text NOT NULL,
	"range_start" "inet" NOT NULL,
	"range_end" "inet" NOT NULL,
	"asn" bigint NOT NULL,
	"org" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "geoip_country_range" (
	"dataset_id" text NOT NULL,
	"range_start" "inet" NOT NULL,
	"range_end" "inet" NOT NULL,
	"country" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "geoip_dataset" (
	"id" text PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"state" text NOT NULL,
	"source" text NOT NULL,
	"dataset_month" text,
	"row_count" integer,
	"sha256" text,
	"compressed_bytes" bigint,
	"error" text,
	"imported_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "wazuh_attack_window" (
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"time_window" text NOT NULL,
	"attack_alerts" integer NOT NULL,
	"distinct_sources" integer NOT NULL,
	"agents" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"previous_attack_alerts" integer,
	"previous_distinct_sources" integer,
	"previous_sources" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"read_at" timestamp with time zone NOT NULL,
	CONSTRAINT "wazuh_attack_window_connection_id_time_window_pk" PRIMARY KEY("connection_id","time_window")
);
--> statement-breakpoint
ALTER TABLE "wazuh_source_ip" ADD COLUMN "first_seen_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "wazuh_source_ip" ADD COLUMN "last_seen_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "wazuh_source_ip" ADD COLUMN "agents" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "attack_osint_result" ADD CONSTRAINT "attack_osint_result_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_geoip_download_enabled_by_user_id_fk" FOREIGN KEY ("geoip_download_enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_osint_secret_id_secret_id_fk" FOREIGN KEY ("osint_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_osint_acknowledged_by_user_id_fk" FOREIGN KEY ("osint_acknowledged_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_summary" ADD CONSTRAINT "attack_summary_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_summary" ADD CONSTRAINT "attack_summary_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "attack_summary" ADD CONSTRAINT "attack_summary_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "geoip_asn_range" ADD CONSTRAINT "geoip_asn_range_dataset_id_geoip_dataset_id_fk" FOREIGN KEY ("dataset_id") REFERENCES "public"."geoip_dataset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "geoip_country_range" ADD CONSTRAINT "geoip_country_range_dataset_id_geoip_dataset_id_fk" FOREIGN KEY ("dataset_id") REFERENCES "public"."geoip_dataset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "geoip_dataset" ADD CONSTRAINT "geoip_dataset_imported_by_user_id_fk" FOREIGN KEY ("imported_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_attack_window" ADD CONSTRAINT "wazuh_attack_window_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_attack_window" ADD CONSTRAINT "wazuh_attack_window_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "attack_osint_result_uq" ON "attack_osint_result" USING btree ("organization_id","provider","ip");--> statement-breakpoint
CREATE INDEX "attack_osint_result_checked_idx" ON "attack_osint_result" USING btree ("checked_at");--> statement-breakpoint
CREATE INDEX "attack_summary_conn_idx" ON "attack_summary" USING btree ("connection_id","created_at");--> statement-breakpoint
CREATE INDEX "geoip_asn_range_lookup" ON "geoip_asn_range" USING btree ("dataset_id","range_start");--> statement-breakpoint
CREATE INDEX "geoip_country_range_lookup" ON "geoip_country_range" USING btree ("dataset_id","range_start");--> statement-breakpoint
CREATE UNIQUE INDEX "geoip_dataset_active_uq" ON "geoip_dataset" USING btree ("kind") WHERE "geoip_dataset"."state" = 'active';