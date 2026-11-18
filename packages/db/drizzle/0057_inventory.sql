CREATE TABLE "inventory_software" (
	"system_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	CONSTRAINT "inventory_software_system_id_name_version_pk" PRIMARY KEY("system_id","name","version")
);
--> statement-breakpoint
CREATE TABLE "inventory_system" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"kind" text DEFAULT 'server' NOT NULL,
	"environment" text,
	"notes" text,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source" text NOT NULL,
	"reported_at" timestamp with time zone,
	"reported_by_token" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "inventory_token" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"prefix" text NOT NULL,
	"label" text NOT NULL,
	"scope" text NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "inventory_software" ADD CONSTRAINT "inventory_software_system_id_inventory_system_id_fk" FOREIGN KEY ("system_id") REFERENCES "public"."inventory_system"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory_software" ADD CONSTRAINT "inventory_software_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory_system" ADD CONSTRAINT "inventory_system_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory_system" ADD CONSTRAINT "inventory_system_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory_token" ADD CONSTRAINT "inventory_token_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory_token" ADD CONSTRAINT "inventory_token_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "inventory_software_name_idx" ON "inventory_software" USING btree ("organization_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "inventory_system_key_uq" ON "inventory_system" USING btree ("organization_id","key");--> statement-breakpoint
CREATE INDEX "inventory_system_name_idx" ON "inventory_system" USING btree ("organization_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "inventory_token_hash_uq" ON "inventory_token" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "inventory_token_org_idx" ON "inventory_token" USING btree ("organization_id");