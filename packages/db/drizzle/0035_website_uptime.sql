CREATE TABLE "exposure_uptime_check" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"asset_id" text NOT NULL,
	"checked_at" timestamp with time zone NOT NULL,
	"up" boolean NOT NULL,
	"status" integer,
	"response_ms" integer,
	"error" text
);
--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_interval_minutes" integer DEFAULT 5 NOT NULL;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_state" text;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_since" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_failures" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "exposure_asset" ADD COLUMN "uptime_checked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "exposure_uptime_check" ADD CONSTRAINT "exposure_uptime_check_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exposure_uptime_check" ADD CONSTRAINT "exposure_uptime_check_asset_id_exposure_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."exposure_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "exposure_uptime_check_asset_idx" ON "exposure_uptime_check" USING btree ("asset_id","checked_at");