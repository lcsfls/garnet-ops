ALTER TABLE "fix_pr" ADD COLUMN "via" text DEFAULT 'repository' NOT NULL;--> statement-breakpoint
ALTER TABLE "fix_pr" ADD COLUMN "connection_id" text;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "pull_requests" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "pull_requests_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "write_scope" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD COLUMN "write" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "fix_pr" ADD CONSTRAINT "fix_pr_connection_id_forge_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."forge_connection"("id") ON DELETE set null ON UPDATE no action;