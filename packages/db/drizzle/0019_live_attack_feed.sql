CREATE TABLE "wazuh_attack_event" (
	"seq" bigserial PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"connection_id" text NOT NULL,
	"doc_id" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip" text NOT NULL,
	"rule_id" text NOT NULL,
	"rule_level" integer NOT NULL,
	"description" text NOT NULL,
	"groups" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"agent_id" text NOT NULL,
	"agent_name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wazuh_live_state" (
	"connection_id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"interval_seconds" integer DEFAULT 30 NOT NULL,
	"min_level" integer DEFAULT 7 NOT NULL,
	"cursor_at" timestamp with time zone,
	"cursor_id" text,
	"next_poll_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_poll_at" timestamp with time zone,
	"last_event_at" timestamp with time zone,
	"last_error" text,
	"failures" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "wazuh_live_state_interval" CHECK ("wazuh_live_state"."interval_seconds" between 15 and 300),
	CONSTRAINT "wazuh_live_state_level" CHECK ("wazuh_live_state"."min_level" between 3 and 15)
);
--> statement-breakpoint
ALTER TABLE "attack_settings" ADD COLUMN "home_country" text;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD COLUMN "home_lat" double precision;--> statement-breakpoint
ALTER TABLE "attack_settings" ADD COLUMN "home_lon" double precision;--> statement-breakpoint
ALTER TABLE "wazuh_attack_event" ADD CONSTRAINT "wazuh_attack_event_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_attack_event" ADD CONSTRAINT "wazuh_attack_event_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_live_state" ADD CONSTRAINT "wazuh_live_state_connection_id_wazuh_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."wazuh_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wazuh_live_state" ADD CONSTRAINT "wazuh_live_state_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "wazuh_attack_event_doc_uq" ON "wazuh_attack_event" USING btree ("connection_id","doc_id");--> statement-breakpoint
CREATE INDEX "wazuh_attack_event_org_idx" ON "wazuh_attack_event" USING btree ("organization_id","seq");--> statement-breakpoint
CREATE INDEX "wazuh_attack_event_at_idx" ON "wazuh_attack_event" USING btree ("at");--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_home_country" CHECK ("attack_settings"."home_country" is null or "attack_settings"."home_country" ~ '^[A-Z]{2}$');--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_home_point" CHECK (("attack_settings"."home_lat" is null) = ("attack_settings"."home_lon" is null));--> statement-breakpoint
ALTER TABLE "attack_settings" ADD CONSTRAINT "attack_settings_home_range" CHECK (("attack_settings"."home_lat" is null or "attack_settings"."home_lat" between -90 and 90) and ("attack_settings"."home_lon" is null or "attack_settings"."home_lon" between -180 and 180));