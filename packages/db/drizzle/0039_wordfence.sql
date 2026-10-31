CREATE TABLE "wordpress_advisory" (
	"organization_id" text NOT NULL,
	"id" text NOT NULL,
	"kind" text NOT NULL,
	"slug" text NOT NULL,
	"title" text NOT NULL,
	"cve" text,
	"cvss_score" real,
	"severity" text NOT NULL,
	"affected" jsonb NOT NULL,
	"patched" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"published" text,
	CONSTRAINT "wordpress_advisory_organization_id_id_kind_slug_pk" PRIMARY KEY("organization_id","id","kind","slug")
);
--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_secret_id" text;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_set_by" text;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_set_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_synced_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_error" text;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordfence_advisories" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "wordpress_advisory" ADD CONSTRAINT "wordpress_advisory_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD CONSTRAINT "exposure_settings_wordfence_set_by_user_id_fk" FOREIGN KEY ("wordfence_set_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;