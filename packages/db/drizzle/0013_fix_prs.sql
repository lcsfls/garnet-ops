CREATE TABLE "fix_pr" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"proposal_key" text NOT NULL,
	"ecosystem" text NOT NULL,
	"package_name" text NOT NULL,
	"from_version" text NOT NULL,
	"to_version" text NOT NULL,
	"major_upgrade" boolean DEFAULT false NOT NULL,
	"manifest_path" text NOT NULL,
	"expected_blob_sha" text NOT NULL,
	"severity" text NOT NULL,
	"vulnerability_ids" jsonb NOT NULL,
	"state" text NOT NULL,
	"reason" text,
	"branch" text,
	"base_branch" text,
	"pr_number" integer,
	"pr_url" text,
	"requested_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"opened_at" timestamp with time zone,
	"closed_at" timestamp with time zone,
	"last_checked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "repository_manifest" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"path" text NOT NULL,
	"kind" text NOT NULL,
	"blob_sha" text NOT NULL,
	"size" integer NOT NULL,
	"dependencies" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "repository_write_access" (
	"repository_id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"secret_id" text NOT NULL,
	"forge_kind" text NOT NULL,
	"api_base_url" text NOT NULL,
	"enabled_by" text,
	"enabled_at" timestamp with time zone DEFAULT now() NOT NULL,
	"status" text DEFAULT 'unchecked' NOT NULL,
	"status_reason" text,
	"warning" text,
	"checked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "fix_pr" ADD CONSTRAINT "fix_pr_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fix_pr" ADD CONSTRAINT "fix_pr_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fix_pr" ADD CONSTRAINT "fix_pr_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_manifest" ADD CONSTRAINT "repository_manifest_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_manifest" ADD CONSTRAINT "repository_manifest_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_write_access" ADD CONSTRAINT "repository_write_access_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_write_access" ADD CONSTRAINT "repository_write_access_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_write_access" ADD CONSTRAINT "repository_write_access_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_write_access" ADD CONSTRAINT "repository_write_access_enabled_by_user_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "fix_pr_org_created_idx" ON "fix_pr" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE INDEX "fix_pr_repo_idx" ON "fix_pr" USING btree ("repository_id","state");--> statement-breakpoint
CREATE INDEX "fix_pr_state_idx" ON "fix_pr" USING btree ("state","last_checked_at");--> statement-breakpoint
CREATE UNIQUE INDEX "fix_pr_active_uq" ON "fix_pr" USING btree ("repository_id","proposal_key") WHERE "fix_pr"."state" in ('queued', 'running', 'open');--> statement-breakpoint
CREATE INDEX "repository_manifest_repo_idx" ON "repository_manifest" USING btree ("repository_id");--> statement-breakpoint
CREATE UNIQUE INDEX "repository_manifest_path_uq" ON "repository_manifest" USING btree ("repository_id","path");