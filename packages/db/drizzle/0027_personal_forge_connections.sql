CREATE TABLE "forge_connection" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"forge_kind" text NOT NULL,
	"web_base_url" text NOT NULL,
	"api_base_url" text NOT NULL,
	"secret_id" text,
	"account_login" text,
	"state" text DEFAULT 'unchecked' NOT NULL,
	"problem" text,
	"broad_token" boolean DEFAULT false NOT NULL,
	"truncated" boolean DEFAULT false NOT NULL,
	"last_checked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "forge_connection_repository" (
	"connection_id" text NOT NULL,
	"forge_id" text NOT NULL,
	"full_name" text NOT NULL,
	"clone_url" text NOT NULL,
	"default_branch" text,
	"private" boolean NOT NULL,
	"archived" boolean DEFAULT false NOT NULL,
	"description" text,
	"listed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "forge_connection_repository_connection_id_forge_id_pk" PRIMARY KEY("connection_id","forge_id")
);
--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "forge_connection_id" text;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "visibility" text DEFAULT 'organization' NOT NULL;--> statement-breakpoint
ALTER TABLE "repository" ADD COLUMN "share_requested_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD CONSTRAINT "forge_connection_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD CONSTRAINT "forge_connection_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_connection" ADD CONSTRAINT "forge_connection_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "forge_connection_repository" ADD CONSTRAINT "forge_connection_repository_connection_id_forge_connection_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."forge_connection"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "forge_connection_user_idx" ON "forge_connection" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "forge_connection_user_forge_uq" ON "forge_connection" USING btree ("organization_id","user_id","web_base_url");--> statement-breakpoint
ALTER TABLE "repository" ADD CONSTRAINT "repository_forge_connection_id_forge_connection_id_fk" FOREIGN KEY ("forge_connection_id") REFERENCES "public"."forge_connection"("id") ON DELETE set null ON UPDATE no action;