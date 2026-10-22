CREATE TABLE "host" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"address" text NOT NULL,
	"port" integer DEFAULT 22 NOT NULL,
	"ssh_user" text DEFAULT 'garnetops' NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"source_ref" text,
	"host_key_status" text DEFAULT 'pending' NOT NULL,
	"host_key_type" text,
	"host_key" text,
	"host_key_fingerprint" text,
	"host_key_confirmed_at" timestamp with time zone,
	"host_key_confirmed_by" text,
	"candidate_key_type" text,
	"candidate_key" text,
	"candidate_key_fingerprint" text,
	"candidate_key_seen_at" timestamp with time zone,
	"os_id" text,
	"os_version_id" text,
	"os_name" text,
	"kernel" text,
	"arch" text,
	"package_count" integer,
	"pending_updates" integer,
	"security_updates" integer,
	"last_inventory_at" timestamp with time zone,
	"last_error" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "host_access_key" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"public_key" text NOT NULL,
	"fingerprint" text NOT NULL,
	"secret_id" text,
	"state" text DEFAULT 'active' NOT NULL,
	"allowed_source" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "host_finding" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"host_id" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"dedup_key" text NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text NOT NULL,
	"package_type" text NOT NULL,
	"package_purl" text,
	"fixed_in" jsonb,
	"fix_state" text,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"state" text NOT NULL,
	"first_seen_run_id" text NOT NULL,
	"last_seen_run_id" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "host_inventory_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"host_id" text NOT NULL,
	"state" text NOT NULL,
	"trigger" text NOT NULL,
	"requested_by" text,
	"package_count" integer,
	"pending_updates" integer,
	"new_findings" integer,
	"resolved_findings" integer,
	"severity_counts" jsonb,
	"scanner_versions" jsonb,
	"vuln_db_built_at" timestamp with time zone,
	"error" text,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "host_package" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"host_id" text NOT NULL,
	"name" text NOT NULL,
	"version" text NOT NULL,
	"arch" text,
	"type" text NOT NULL,
	"origin" text,
	"origin_version" text,
	"upgradable_to" text,
	"security_update" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "host_setup_link" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"access_key_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"allowed_source" text NOT NULL,
	"script_sha256" text NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"used_ip" text
);
--> statement-breakpoint
ALTER TABLE "host" ADD CONSTRAINT "host_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host" ADD CONSTRAINT "host_host_key_confirmed_by_user_id_fk" FOREIGN KEY ("host_key_confirmed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host" ADD CONSTRAINT "host_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_access_key" ADD CONSTRAINT "host_access_key_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_access_key" ADD CONSTRAINT "host_access_key_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_finding" ADD CONSTRAINT "host_finding_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_finding" ADD CONSTRAINT "host_finding_host_id_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_finding" ADD CONSTRAINT "host_finding_vulnerability_id_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerability"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_inventory_run" ADD CONSTRAINT "host_inventory_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_inventory_run" ADD CONSTRAINT "host_inventory_run_host_id_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_inventory_run" ADD CONSTRAINT "host_inventory_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_package" ADD CONSTRAINT "host_package_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_package" ADD CONSTRAINT "host_package_host_id_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_setup_link" ADD CONSTRAINT "host_setup_link_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_setup_link" ADD CONSTRAINT "host_setup_link_access_key_id_host_access_key_id_fk" FOREIGN KEY ("access_key_id") REFERENCES "public"."host_access_key"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_setup_link" ADD CONSTRAINT "host_setup_link_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "host_org_address_port_uq" ON "host" USING btree ("organization_id","address","port");--> statement-breakpoint
CREATE INDEX "host_org_name_idx" ON "host" USING btree ("organization_id","name","id");--> statement-breakpoint
CREATE UNIQUE INDEX "host_source_ref_uq" ON "host" USING btree ("organization_id","source","source_ref") WHERE "host"."source_ref" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "host_access_key_active_uq" ON "host_access_key" USING btree ("organization_id") WHERE "host_access_key"."state" = 'active';--> statement-breakpoint
CREATE UNIQUE INDEX "host_finding_dedup_uq" ON "host_finding" USING btree ("organization_id","dedup_key");--> statement-breakpoint
CREATE INDEX "host_finding_host_idx" ON "host_finding" USING btree ("host_id","state","severity_rank","id");--> statement-breakpoint
CREATE INDEX "host_finding_org_idx" ON "host_finding" USING btree ("organization_id","state","severity_rank","last_seen_at","id");--> statement-breakpoint
CREATE INDEX "host_finding_vuln_idx" ON "host_finding" USING btree ("vulnerability_id");--> statement-breakpoint
CREATE INDEX "host_inventory_run_host_idx" ON "host_inventory_run" USING btree ("host_id","created_at","id");--> statement-breakpoint
CREATE INDEX "host_inventory_run_org_idx" ON "host_inventory_run" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE INDEX "host_package_host_idx" ON "host_package" USING btree ("host_id","name","version","id");--> statement-breakpoint
CREATE INDEX "host_package_org_name_idx" ON "host_package" USING btree ("organization_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "host_setup_link_token_hash_uq" ON "host_setup_link" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "host_setup_link_org_idx" ON "host_setup_link" USING btree ("organization_id","created_at");