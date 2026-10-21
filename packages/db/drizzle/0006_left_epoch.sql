CREATE TABLE "updater_journal_cursor" (
	"id" integer PRIMARY KEY NOT NULL,
	"last_event_id" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_log" ADD COLUMN "source" text;--> statement-breakpoint
ALTER TABLE "audit_log" ADD COLUMN "event_id" text;--> statement-breakpoint
CREATE UNIQUE INDEX "audit_source_event_idx" ON "audit_log" USING btree ("source","event_id");