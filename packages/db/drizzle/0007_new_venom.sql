CREATE TABLE "gate_rule" (
	"organization_id" text NOT NULL,
	"rule" text NOT NULL,
	"mode" text NOT NULL,
	"config" jsonb,
	"updated_by" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "gate_rule_organization_id_rule_pk" PRIMARY KEY("organization_id","rule")
);
--> statement-breakpoint
CREATE TABLE "gate_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"scan_id" text NOT NULL,
	"result" text NOT NULL,
	"matches" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "gate_token" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"prefix" text NOT NULL,
	"label" text NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "ref" text;--> statement-breakpoint
ALTER TABLE "scan" ADD COLUMN "expected_sha" text;--> statement-breakpoint
ALTER TABLE "gate_rule" ADD CONSTRAINT "gate_rule_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_rule" ADD CONSTRAINT "gate_rule_updated_by_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_run" ADD CONSTRAINT "gate_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_run" ADD CONSTRAINT "gate_run_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_run" ADD CONSTRAINT "gate_run_scan_id_scan_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scan"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_token" ADD CONSTRAINT "gate_token_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_token" ADD CONSTRAINT "gate_token_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_token" ADD CONSTRAINT "gate_token_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "gate_run_scan_uq" ON "gate_run" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "gate_run_org_created_idx" ON "gate_run" USING btree ("organization_id","created_at","id");--> statement-breakpoint
CREATE INDEX "gate_run_repo_created_idx" ON "gate_run" USING btree ("repository_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "gate_token_hash_uq" ON "gate_token" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "gate_token_repo_idx" ON "gate_token" USING btree ("repository_id");