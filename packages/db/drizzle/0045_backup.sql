CREATE TABLE "backup_chunk" (
	"run_id" text NOT NULL,
	"seq" integer NOT NULL,
	"data" "bytea" NOT NULL,
	CONSTRAINT "backup_chunk_run_id_seq_pk" PRIMARY KEY("run_id","seq")
);
--> statement-breakpoint
CREATE TABLE "backup_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"requested_by" text,
	"state" text NOT NULL,
	"error" text,
	"secret_id" text,
	"size_bytes" bigint,
	"sha256" text,
	"row_count" integer,
	"app_version" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ready_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"downloaded_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "backup_chunk" ADD CONSTRAINT "backup_chunk_run_id_backup_run_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."backup_run"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_run" ADD CONSTRAINT "backup_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_run" ADD CONSTRAINT "backup_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "backup_run_org_created_idx" ON "backup_run" USING btree ("organization_id","created_at");