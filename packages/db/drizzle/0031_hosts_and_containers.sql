CREATE TABLE "agent_enrolment" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"code_hash" text NOT NULL,
	"label" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"host_id" text
);
--> statement-breakpoint
CREATE TABLE "agent_host" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"hostname" text NOT NULL,
	"public_key" text NOT NULL,
	"agent_version" text,
	"docker_version" text,
	"os" text,
	"enrolled_by" text,
	"enrolled_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone,
	"last_inventory_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_nonce" (
	"host_id" text NOT NULL,
	"nonce" text NOT NULL,
	"seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "agent_nonce_host_id_nonce_pk" PRIMARY KEY("host_id","nonce")
);
--> statement-breakpoint
CREATE TABLE "container_image" (
	"organization_id" text NOT NULL,
	"image_id" text NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"digests" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"os" text,
	"architecture" text,
	"built_at" timestamp with time zone,
	"labels" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"source_key" text,
	"distro" text,
	"packages" jsonb,
	"package_count" integer,
	"packages_at" timestamp with time zone,
	"matched_at" timestamp with time zone,
	"matched_db_built" timestamp with time zone,
	"match_error" text,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "container_image_organization_id_image_id_pk" PRIMARY KEY("organization_id","image_id")
);
--> statement-breakpoint
CREATE TABLE "container_image_finding" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"image_id" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text NOT NULL,
	"package_type" text NOT NULL,
	"package_purl" text,
	"fixed_in" jsonb,
	"fix_state" text,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "host_container" (
	"host_id" text NOT NULL,
	"container_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"image_ref" text NOT NULL,
	"image_id" text NOT NULL,
	"state" text NOT NULL,
	"started_at" timestamp with time zone,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "host_container_host_id_container_id_pk" PRIMARY KEY("host_id","container_id")
);
--> statement-breakpoint
CREATE TABLE "host_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"enabled_by" text,
	"enabled_at" timestamp with time zone,
	"registry_checks" boolean DEFAULT false NOT NULL,
	"registry_checks_by" text,
	"registry_checks_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "image_update_check" (
	"organization_id" text NOT NULL,
	"ref" text NOT NULL,
	"checked_at" timestamp with time zone NOT NULL,
	"current_digest" text,
	"newer_tag" text,
	"newer_kind" text,
	"error" text,
	CONSTRAINT "image_update_check_organization_id_ref_pk" PRIMARY KEY("organization_id","ref")
);
--> statement-breakpoint
ALTER TABLE "agent_enrolment" ADD CONSTRAINT "agent_enrolment_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_enrolment" ADD CONSTRAINT "agent_enrolment_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_host" ADD CONSTRAINT "agent_host_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_host" ADD CONSTRAINT "agent_host_enrolled_by_user_id_fk" FOREIGN KEY ("enrolled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_nonce" ADD CONSTRAINT "agent_nonce_host_id_agent_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."agent_host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "container_image" ADD CONSTRAINT "container_image_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "container_image_finding" ADD CONSTRAINT "container_image_finding_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "container_image_finding" ADD CONSTRAINT "container_image_finding_vulnerability_id_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerability"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_container" ADD CONSTRAINT "host_container_host_id_agent_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."agent_host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_container" ADD CONSTRAINT "host_container_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_settings" ADD CONSTRAINT "host_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_settings" ADD CONSTRAINT "host_settings_enabled_by_user_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_settings" ADD CONSTRAINT "host_settings_registry_checks_by_user_id_fk" FOREIGN KEY ("registry_checks_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "image_update_check" ADD CONSTRAINT "image_update_check_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_enrolment_code_uq" ON "agent_enrolment" USING btree ("code_hash");--> statement-breakpoint
CREATE INDEX "agent_enrolment_org_idx" ON "agent_enrolment" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "agent_host_org_idx" ON "agent_host" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "agent_nonce_seen_idx" ON "agent_nonce" USING btree ("seen_at");--> statement-breakpoint
CREATE INDEX "container_image_source_idx" ON "container_image" USING btree ("organization_id","source_key");--> statement-breakpoint
CREATE UNIQUE INDEX "container_image_finding_uq" ON "container_image_finding" USING btree ("organization_id","image_id","vulnerability_id","package_type","package_name");--> statement-breakpoint
CREATE INDEX "container_image_finding_list_idx" ON "container_image_finding" USING btree ("organization_id","image_id","severity_rank");--> statement-breakpoint
CREATE INDEX "host_container_image_idx" ON "host_container" USING btree ("organization_id","image_id");