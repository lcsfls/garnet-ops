CREATE TABLE "exposure_asset" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"include_subdomains" boolean DEFAULT false NOT NULL,
	"verify_token" text NOT NULL,
	"verify_state" text DEFAULT 'unverified' NOT NULL,
	"verify_method" text,
	"verified_at" timestamp with time zone,
	"verify_checked_at" timestamp with time zone,
	"verify_error" text,
	"passive_enabled" boolean DEFAULT true NOT NULL,
	"stage2_enabled" boolean DEFAULT false NOT NULL,
	"stage2_schedule" text DEFAULT 'daily' NOT NULL,
	"stage2_acknowledged_by" text,
	"stage2_acknowledged_at" timestamp with time zone,
	"last_passive_at" timestamp with time zone,
	"passive_error" text,
	"last_active_at" timestamp with time zone,
	"active_error" text,
	"passive" jsonb,
	"active" jsonb,
	"cert_notified_level" integer,
	"ct_checked_at" timestamp with time zone,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "exposure_discovery" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"asset_id" text NOT NULL,
	"name" text NOT NULL,
	"source" text NOT NULL,
	"state" text DEFAULT 'new' NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "exposure_finding" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"asset_id" text NOT NULL,
	"stage" text NOT NULL,
	"rule" text NOT NULL,
	"subject" text DEFAULT '' NOT NULL,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"state" text NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"notified_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "exposure_port" (
	"asset_id" text NOT NULL,
	"address" text NOT NULL,
	"port" integer NOT NULL,
	"organization_id" text NOT NULL,
	"service" text NOT NULL,
	"banner" text,
	"tls" jsonb,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "exposure_port_asset_id_address_port_pk" PRIMARY KEY("asset_id","address","port")
);
--> statement-breakpoint
CREATE TABLE "exposure_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"asset_id" text NOT NULL,
	"stage" text NOT NULL,
	"state" text NOT NULL,
	"trigger" text NOT NULL,
	"requested_by" text,
	"error" text,
	"finding_counts" jsonb,
	"open_ports" integer,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "exposure_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"ct_enabled" boolean DEFAULT false NOT NULL,
	"ct_enabled_by" text,
	"ct_enabled_at" timestamp with time zone,
	"ct_usage_day" date,
	"ct_usage_count" integer DEFAULT 0 NOT NULL,
	"ct_last_request_at" timestamp with time zone,
	"ct_last_error" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD CONSTRAINT "exposure_asset_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD CONSTRAINT "exposure_asset_stage2_acknowledged_by_user_id_fk" FOREIGN KEY ("stage2_acknowledged_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD CONSTRAINT "exposure_asset_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_discovery" ADD CONSTRAINT "exposure_discovery_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_discovery" ADD CONSTRAINT "exposure_discovery_asset_id_exposure_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."exposure_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_finding" ADD CONSTRAINT "exposure_finding_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_finding" ADD CONSTRAINT "exposure_finding_asset_id_exposure_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."exposure_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_port" ADD CONSTRAINT "exposure_port_asset_id_exposure_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."exposure_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_port" ADD CONSTRAINT "exposure_port_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_run" ADD CONSTRAINT "exposure_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_run" ADD CONSTRAINT "exposure_run_asset_id_exposure_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."exposure_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_run" ADD CONSTRAINT "exposure_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD CONSTRAINT "exposure_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD CONSTRAINT "exposure_settings_ct_enabled_by_user_id_fk" FOREIGN KEY ("ct_enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "exposure_asset_org_value_uq" ON "exposure_asset" USING btree ("organization_id","value");--> statement-breakpoint
CREATE UNIQUE INDEX "exposure_asset_token_uq" ON "exposure_asset" USING btree ("verify_token");--> statement-breakpoint
CREATE INDEX "exposure_asset_org_idx" ON "exposure_asset" USING btree ("organization_id","value","id");--> statement-breakpoint
CREATE INDEX "exposure_asset_due_idx" ON "exposure_asset" USING btree ("last_passive_at");--> statement-breakpoint
CREATE UNIQUE INDEX "exposure_discovery_uq" ON "exposure_discovery" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "exposure_discovery_asset_idx" ON "exposure_discovery" USING btree ("asset_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "exposure_finding_uq" ON "exposure_finding" USING btree ("asset_id","rule","subject");--> statement-breakpoint
CREATE INDEX "exposure_finding_asset_idx" ON "exposure_finding" USING btree ("asset_id","state","severity_rank","id");--> statement-breakpoint
CREATE INDEX "exposure_finding_org_idx" ON "exposure_finding" USING btree ("organization_id","state","severity_rank");--> statement-breakpoint
CREATE INDEX "exposure_port_org_idx" ON "exposure_port" USING btree ("organization_id","asset_id");--> statement-breakpoint
CREATE INDEX "exposure_run_asset_idx" ON "exposure_run" USING btree ("asset_id","created_at","id");--> statement-breakpoint
CREATE INDEX "exposure_run_org_idx" ON "exposure_run" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "exposure_run_active_uq" ON "exposure_run" USING btree ("asset_id","stage") WHERE "exposure_run"."state" in ('queued', 'running');