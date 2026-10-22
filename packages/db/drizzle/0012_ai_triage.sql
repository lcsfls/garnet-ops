CREATE TABLE "ai_probe" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"kind" text NOT NULL,
	"base_url" text NOT NULL,
	"model" text,
	"secret_id" text,
	"temp_secret" boolean DEFAULT false NOT NULL,
	"ack_host" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"result" jsonb,
	"requested_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_note" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"finding_id" text NOT NULL,
	"author_user_id" text,
	"body" text NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"message_id" text,
	"meta" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "enabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "max_tokens" integer DEFAULT 1024 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "temperature" real DEFAULT 0.2 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "timeout_seconds" integer DEFAULT 120 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "max_concurrent" integer DEFAULT 2 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "endpoint_scope" text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "external_ack_host" text;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "external_ack_by" text;--> statement-breakpoint
ALTER TABLE "ai_settings" ADD COLUMN "external_ack_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "chat_message" ADD COLUMN "seq" bigserial NOT NULL;--> statement-breakpoint
ALTER TABLE "chat_message" ADD COLUMN "kind" text DEFAULT 'chat' NOT NULL;--> statement-breakpoint
ALTER TABLE "chat_message" ADD COLUMN "structured" jsonb;--> statement-breakpoint
ALTER TABLE "chat_message" ADD COLUMN "error" text;--> statement-breakpoint
ALTER TABLE "ai_probe" ADD CONSTRAINT "ai_probe_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_probe" ADD CONSTRAINT "ai_probe_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_probe" ADD CONSTRAINT "ai_probe_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_finding_id_finding_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."finding"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_author_user_id_user_id_fk" FOREIGN KEY ("author_user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_message_id_chat_message_id_fk" FOREIGN KEY ("message_id") REFERENCES "public"."chat_message"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ai_probe_org_idx" ON "ai_probe" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "finding_note_finding_idx" ON "finding_note" USING btree ("finding_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "finding_note_message_uq" ON "finding_note" USING btree ("message_id");--> statement-breakpoint
ALTER TABLE "ai_settings" ADD CONSTRAINT "ai_settings_external_ack_by_user_id_fk" FOREIGN KEY ("external_ack_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "chat_message_thread_seq_idx" ON "chat_message" USING btree ("thread_id","seq");--> statement-breakpoint
CREATE INDEX "chat_message_active_idx" ON "chat_message" USING btree ("status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "chat_thread_finding_uq" ON "chat_thread" USING btree ("finding_id");