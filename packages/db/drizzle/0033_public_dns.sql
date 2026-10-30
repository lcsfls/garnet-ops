CREATE TABLE "public_dns_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"provider" text,
	"enabled_by" text,
	"enabled_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "public_dns_settings" ADD CONSTRAINT "public_dns_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "public_dns_settings" ADD CONSTRAINT "public_dns_settings_enabled_by_user_id_fk" FOREIGN KEY ("enabled_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;