CREATE TABLE "vulndb_build_settings" (
	"id" text PRIMARY KEY NOT NULL,
	"github_secret_id" text,
	"github_organization_id" text,
	"github_set_by" text,
	"github_set_at" timestamp with time zone,
	"nvd_secret_id" text,
	"nvd_organization_id" text,
	"nvd_set_by" text,
	"nvd_set_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vulndb_build_settings" ADD CONSTRAINT "vulndb_build_settings_github_organization_id_organization_id_fk" FOREIGN KEY ("github_organization_id") REFERENCES "public"."organization"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulndb_build_settings" ADD CONSTRAINT "vulndb_build_settings_github_set_by_user_id_fk" FOREIGN KEY ("github_set_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulndb_build_settings" ADD CONSTRAINT "vulndb_build_settings_nvd_organization_id_organization_id_fk" FOREIGN KEY ("nvd_organization_id") REFERENCES "public"."organization"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulndb_build_settings" ADD CONSTRAINT "vulndb_build_settings_nvd_set_by_user_id_fk" FOREIGN KEY ("nvd_set_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;