ALTER TABLE "repository" ADD COLUMN "ssh_known_hosts" text;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "ssh_known_hosts_pinned_at" timestamp with time zone;