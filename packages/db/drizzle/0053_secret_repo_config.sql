ALTER TABLE "repository" ADD COLUMN "secret_repo_config_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "secret_repo_config_by" text;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "secret_repo_config_result" jsonb;--> statement-breakpoint
ALTER TABLE "secret_finding" ADD COLUMN "set_aside_by_repository" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "repository" ADD CONSTRAINT "repository_secret_repo_config_by_user_id_fk" FOREIGN KEY ("secret_repo_config_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;