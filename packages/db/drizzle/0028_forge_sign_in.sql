CREATE TABLE "forge_app" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"forge_kind" text NOT NULL,
	"web_base_url" text NOT NULL,
	"api_base_url" text NOT NULL,
	"client_id" text NOT NULL,
	"secret_id" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "forge_sign_in" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"app_id" text NOT NULL,
	"flow" text NOT NULL,
	"state" text DEFAULT 'starting' NOT NULL,
	"state_hash" text,
	"verifier_secret_id" text,
	"code_secret_id" text,
	"user_code" text,
	"verification_uri" text,
	"expires_at" timestamp with time zone NOT NULL,
	"connection_id" text,
	"problem" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "auth_method" text DEFAULT 'token' NOT NULL;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "app_id" text;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "refresh_secret_id" text;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD COLUMN "token_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "forge_app" ADD CONSTRAINT "forge_app_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_app" ADD CONSTRAINT "forge_app_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_app" ADD CONSTRAINT "forge_app_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_app_id_forge_app_id_fk" FOREIGN KEY ("app_id") REFERENCES "public"."forge_app"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_verifier_secret_id_secret_id_fk" FOREIGN KEY ("verifier_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_code_secret_id_secret_id_fk" FOREIGN KEY ("code_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_sign_in" ADD CONSTRAINT "forge_sign_in_connection_id_forge_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."forge_connection"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "forge_app_org_web_uq" ON "forge_app" USING btree ("organization_id","web_base_url");--> statement-breakpoint
CREATE INDEX "forge_sign_in_user_idx" ON "forge_sign_in" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "forge_sign_in_state_uq" ON "forge_sign_in" USING btree ("state_hash");--> statement-breakpoint
ALTER TABLE "forge_connection" ADD CONSTRAINT "forge_connection_app_id_forge_app_id_fk" FOREIGN KEY ("app_id") REFERENCES "public"."forge_app"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD CONSTRAINT "forge_connection_refresh_secret_id_secret_id_fk" FOREIGN KEY ("refresh_secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;