ALTER TABLE "exposure_asset" ADD COLUMN "wordpress_token_secret_id" text;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "wordpress_token_set_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "wordpress_token_set_by" text;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD CONSTRAINT "exposure_asset_wordpress_token_set_by_user_id_fk" FOREIGN KEY ("wordpress_token_set_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;