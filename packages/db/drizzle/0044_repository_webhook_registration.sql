ALTER TABLE "repository_webhook" ADD COLUMN "connection_id" text;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD COLUMN "forge_hook_id" text;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD COLUMN "register_state" text;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD COLUMN "register_reason" text;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD COLUMN "handover_secret_id" text;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD CONSTRAINT "repository_webhook_connection_id_forge_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."forge_connection"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_webhook" ADD CONSTRAINT "repository_webhook_handover_secret_id_secret_id_fk" FOREIGN KEY ("handover_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;