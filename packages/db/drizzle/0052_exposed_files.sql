ALTER TABLE "exposure_asset" ADD COLUMN "exposed_files_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "exposed_files_by" text;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD CONSTRAINT "exposure_asset_exposed_files_by_user_id_fk" FOREIGN KEY ("exposed_files_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;