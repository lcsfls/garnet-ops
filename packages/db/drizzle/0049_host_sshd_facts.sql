ALTER TABLE "agent_host" ADD COLUMN "service_manager" text;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "sshd_facts" jsonb;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "sshd_facts_at" timestamp with time zone;