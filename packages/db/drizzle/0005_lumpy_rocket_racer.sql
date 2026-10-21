CREATE TABLE "repository_package" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"name" text NOT NULL,
	"version" text NOT NULL,
	"type" text NOT NULL,
	"purl" text,
	"locations" jsonb,
	"licenses" jsonb
);
--> statement-breakpoint
ALTER TABLE "repository_package" ADD CONSTRAINT "repository_package_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_package" ADD CONSTRAINT "repository_package_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "repository_package_list_idx" ON "repository_package" USING btree ("organization_id","name","version","id");--> statement-breakpoint
CREATE INDEX "repository_package_repo_idx" ON "repository_package" USING btree ("repository_id");