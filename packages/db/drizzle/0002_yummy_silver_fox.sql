CREATE TABLE "scan_schedule_run" (
	"organization_id" text NOT NULL,
	"local_date" date NOT NULL,
	"queued_scans" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scan_schedule_run_organization_id_local_date_pk" PRIMARY KEY("organization_id","local_date")
);
--> statement-breakpoint
ALTER TABLE "organization" ADD COLUMN "scan_schedule_enabled" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "organization" ADD COLUMN "scan_local_time" time DEFAULT '04:00:00' NOT NULL;--> statement-breakpoint
ALTER TABLE "organization" ADD COLUMN "scan_time_zone" text DEFAULT 'UTC' NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_schedule_run" ADD CONSTRAINT "scan_schedule_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;