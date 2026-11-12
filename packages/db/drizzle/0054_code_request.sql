CREATE TABLE "code_request" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"requested_by" text NOT NULL,
	"finding_id" text NOT NULL,
	"repository_id" text NOT NULL,
	"state" text DEFAULT 'queued' NOT NULL,
	"result" jsonb,
	"error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "code_request" ADD CONSTRAINT "code_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "code_request" ADD CONSTRAINT "code_request_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "code_request" ADD CONSTRAINT "code_request_finding_id_finding_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."finding"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "code_request" ADD CONSTRAINT "code_request_repository_id_repository_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."repository"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "code_request_org_idx" ON "code_request" USING btree ("organization_id","state","created_at");