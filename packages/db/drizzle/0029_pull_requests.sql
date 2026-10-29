CREATE TABLE "pull_request" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"number" integer NOT NULL,
	"title" text NOT NULL,
	"author" text,
	"url" text NOT NULL,
	"head_ref" text,
	"head_sha" text NOT NULL,
	"base_ref" text,
	"draft" boolean DEFAULT false NOT NULL,
	"opened_at" timestamp with time zone,
	"updated_at" timestamp with time zone,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "pull_requests_checked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "pull_requests_problem" text;--> statement-breakpoint
ALTER TABLE "pull_request" ADD CONSTRAINT "pull_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pull_request" ADD CONSTRAINT "pull_request_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "pull_request_repo_number_uq" ON "pull_request" USING btree ("repository_id","number");--> statement-breakpoint
CREATE INDEX "pull_request_org_idx" ON "pull_request" USING btree ("organization_id","updated_at");