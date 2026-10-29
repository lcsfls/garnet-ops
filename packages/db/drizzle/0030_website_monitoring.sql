ALTER TABLE "exposure_settings" ADD COLUMN "enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "enabled_by" text;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD COLUMN "enabled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_settings" ADD CONSTRAINT "exposure_settings_enabled_by_user_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;