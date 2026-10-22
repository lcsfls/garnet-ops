CREATE TABLE "directory_identity" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"unique_id" text NOT NULL,
	"dn" text NOT NULL,
	"login_name" text NOT NULL,
	"linked_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_sign_in_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "directory_request" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"kind" text NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"password_secret_id" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"result" jsonb,
	"requested_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ldap_config" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"preset" text NOT NULL,
	"servers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"tls_trust" text DEFAULT 'system' NOT NULL,
	"ca_certificate" text DEFAULT '' NOT NULL,
	"bind_dn" text NOT NULL,
	"bind_secret_id" text,
	"user_base_dn" text NOT NULL,
	"user_filter" text NOT NULL,
	"email_attribute" text DEFAULT 'mail' NOT NULL,
	"name_attribute" text DEFAULT 'cn' NOT NULL,
	"unique_id_attribute" text NOT NULL,
	"group_mode" text NOT NULL,
	"group_filter" text DEFAULT '' NOT NULL,
	"group_roles" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"connect_timeout_seconds" integer DEFAULT 5 NOT NULL,
	"operation_timeout_seconds" integer DEFAULT 10 NOT NULL,
	"size_limit" integer DEFAULT 50 NOT NULL,
	"tested_at" timestamp with time zone,
	"bind_blocked_until" timestamp with time zone,
	"updated_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "directory_identity" ADD CONSTRAINT "directory_identity_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "directory_identity" ADD CONSTRAINT "directory_identity_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "directory_identity" ADD CONSTRAINT "directory_identity_linked_by_user_id_fk" FOREIGN KEY ("linked_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "directory_request" ADD CONSTRAINT "directory_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "directory_request" ADD CONSTRAINT "directory_request_password_secret_id_secret_id_fk" FOREIGN KEY ("password_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "directory_request" ADD CONSTRAINT "directory_request_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD CONSTRAINT "ldap_config_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD CONSTRAINT "ldap_config_bind_secret_id_secret_id_fk" FOREIGN KEY ("bind_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ldap_config" ADD CONSTRAINT "ldap_config_updated_by_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "directory_identity_unique_id_uq" ON "directory_identity" USING btree ("organization_id","unique_id");--> statement-breakpoint
CREATE UNIQUE INDEX "directory_identity_user_uq" ON "directory_identity" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "directory_request_created_idx" ON "directory_request" USING btree ("created_at");