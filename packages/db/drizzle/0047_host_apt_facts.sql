ALTER TABLE "agent_host" ADD COLUMN "apt_facts" jsonb;--> statement-breakpoint
ALTER TABLE "agent_host" ADD COLUMN "apt_facts_at" timestamp with time zone;