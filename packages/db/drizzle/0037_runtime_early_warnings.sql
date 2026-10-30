CREATE TABLE "runtime_early_warning" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"kind" text NOT NULL,
	"subject_id" text NOT NULL,
	"host_id" text,
	"vulnerability_id" text NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text NOT NULL,
	"package_type" text NOT NULL,
	"fixed_in" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"state" text DEFAULT 'open' NOT NULL,
	"db_built_at" timestamp with time zone,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL,
	"closed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "runtime_early_warning" ADD CONSTRAINT "runtime_early_warning_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runtime_early_warning" ADD CONSTRAINT "runtime_early_warning_host_id_agent_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."agent_host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "runtime_early_warning" ADD CONSTRAINT "runtime_early_warning_vulnerability_id_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerability"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "runtime_early_warning_uq" ON "runtime_early_warning" USING btree ("organization_id","kind","subject_id","vulnerability_id","package_type","package_name","package_version");--> statement-breakpoint
CREATE INDEX "runtime_early_warning_org_state_idx" ON "runtime_early_warning" USING btree ("organization_id","state");