CREATE TABLE "notification_preference" (
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"event" text NOT NULL,
	"in_app" boolean NOT NULL,
	"email" boolean NOT NULL,
	"scope" text DEFAULT 'all' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "notification_preference_organization_id_user_id_event_pk" PRIMARY KEY("organization_id","user_id","event")
);
--> statement-breakpoint
CREATE TABLE "user_notification" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"event" text NOT NULL,
	"title_key" text NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"link" text NOT NULL,
	"in_app" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"read_at" timestamp with time zone,
	"mail_state" text DEFAULT 'none' NOT NULL,
	"mailed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "notification_preference" ADD CONSTRAINT "notification_preference_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_preference" ADD CONSTRAINT "notification_preference_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_notification" ADD CONSTRAINT "user_notification_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_notification" ADD CONSTRAINT "user_notification_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "user_notification_user_idx" ON "user_notification" USING btree ("user_id","id");--> statement-breakpoint
CREATE INDEX "user_notification_unread_idx" ON "user_notification" USING btree ("user_id") WHERE "user_notification"."read_at" is null and "user_notification"."in_app";--> statement-breakpoint
CREATE INDEX "user_notification_mail_idx" ON "user_notification" USING btree ("user_id","event","id") WHERE "user_notification"."mail_state" = 'pending';--> statement-breakpoint
CREATE INDEX "user_notification_created_idx" ON "user_notification" USING btree ("created_at");