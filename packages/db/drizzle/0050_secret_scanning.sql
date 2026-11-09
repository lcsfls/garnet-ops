CREATE TABLE "secret_finding" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"rule_id" text NOT NULL,
	"severity" text NOT NULL,
	"severity_rank" integer NOT NULL,
	"fingerprint" text NOT NULL,
	"state" text NOT NULL,
	"state_reason" text,
	"state_by" text,
	"state_at" timestamp with time zone,
	"in_tree" boolean NOT NULL,
	"tree_locations" jsonb NOT NULL,
	"tree_location_count" integer NOT NULL,
	"history_locations" jsonb NOT NULL,
	"history_location_count" integer NOT NULL,
	"first_seen_scan_id" text NOT NULL,
	"last_seen_scan_id" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "secret_history_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "secret_history_by" text;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "secret_history_checked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "secret_history" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "secret_scan" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "secret_counts" jsonb;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "new_secrets" integer;--> statement-breakpoint
ALTER TABLE "secret_finding" ADD CONSTRAINT "secret_finding_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_finding" ADD CONSTRAINT "secret_finding_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_finding" ADD CONSTRAINT "secret_finding_state_by_user_id_fk" FOREIGN KEY ("state_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "secret_finding_uq" ON "secret_finding" USING btree ("repository_id","fingerprint");--> statement-breakpoint
CREATE INDEX "secret_finding_list_idx" ON "secret_finding" USING btree ("organization_id","state","severity_rank","last_seen_at","id");--> statement-breakpoint
CREATE INDEX "secret_finding_repo_idx" ON "secret_finding" USING btree ("repository_id","state");--> statement-breakpoint
ALTER TABLE "repository" ADD CONSTRAINT "repository_secret_history_by_user_id_fk" FOREIGN KEY ("secret_history_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;