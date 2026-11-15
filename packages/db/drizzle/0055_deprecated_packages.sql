CREATE TABLE "deprecation_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"enabled_by" text,
	"enabled_at" timestamp with time zone,
	"registries" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"excluded" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"last_run" jsonb,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "package_status" (
	"scope" text NOT NULL,
	"ecosystem" text NOT NULL,
	"name" text NOT NULL,
	"version" text NOT NULL,
	"state" text NOT NULL,
	"message" text,
	"checked_at" timestamp with time zone NOT NULL,
	CONSTRAINT "package_status_scope_ecosystem_name_version_pk" PRIMARY KEY("scope","ecosystem","name","version")
);
--> statement-breakpoint
ALTER TABLE "deprecation_settings" ADD CONSTRAINT "deprecation_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deprecation_settings" ADD CONSTRAINT "deprecation_settings_enabled_by_user_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "package_status_checked_idx" ON "package_status" USING btree ("checked_at");