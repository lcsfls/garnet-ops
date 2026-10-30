CREATE TABLE "wordpress_component" (
	"kind" text NOT NULL,
	"slug" text NOT NULL,
	"latest" text,
	"listed" boolean DEFAULT false NOT NULL,
	"checked_at" timestamp with time zone NOT NULL,
	"error" text,
	CONSTRAINT "wordpress_component_kind_slug_pk" PRIMARY KEY("kind","slug")
);
--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordpress_org_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordpress_org_enabled_by" text;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "wordpress_org_enabled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD CONSTRAINT "exposure_settings_wordpress_org_enabled_by_user_id_fk" FOREIGN KEY ("wordpress_org_enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;