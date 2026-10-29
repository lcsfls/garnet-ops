CREATE TABLE "host_kernel_finding" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"host_id" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text NOT NULL,
	"fixed_in" jsonb,
	"fix_state" text,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_release" text;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "os_name" text;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_package" jsonb;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_problem" text;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_matched_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_matched_db_built" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "kernel_match_error" text;--> statement-breakpoint
ALTER TABLE "host_kernel_finding" ADD CONSTRAINT "host_kernel_finding_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_kernel_finding" ADD CONSTRAINT "host_kernel_finding_host_id_agent_host_id_fk" FOREIGN KEY ("host_id") REFERENCES "public"."agent_host"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_kernel_finding" ADD CONSTRAINT "host_kernel_finding_vulnerability_id_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerability"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "host_kernel_finding_uq" ON "host_kernel_finding" USING btree ("host_id","vulnerability_id","package_name");--> statement-breakpoint
CREATE INDEX "host_kernel_finding_org_idx" ON "host_kernel_finding" USING btree ("organization_id","host_id","severity_rank");