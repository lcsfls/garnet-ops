ALTER TABLE "repository" ADD COLUMN "inactive_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "inactive_by" text;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "inactive_reason" text;--> statement-breakpoint
ALTER TABLE "repository" ADD CONSTRAINT "repository_inactive_by_user_id_fk" FOREIGN KEY ("inactive_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;