CREATE TABLE "secret_ignore_rule" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text,
	"path_pattern" text,
	"rule_id" text,
	"reason" text NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "secret_finding" ADD COLUMN "ignored_by" text;--> statement-breakpoint
ALTER TABLE "secret_ignore_rule" ADD CONSTRAINT "secret_ignore_rule_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_ignore_rule" ADD CONSTRAINT "secret_ignore_rule_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret_ignore_rule" ADD CONSTRAINT "secret_ignore_rule_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "secret_ignore_rule_org_idx" ON "secret_ignore_rule" USING btree ("organization_id");--> statement-breakpoint
ALTER TABLE "secret_finding" ADD CONSTRAINT "secret_finding_ignored_by_secret_ignore_rule_id_fk" FOREIGN KEY ("ignored_by") REFERENCES "public"."secret_ignore_rule"("id") ON DELETE set null ON UPDATE no action;