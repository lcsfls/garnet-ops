CREATE TABLE "report_mail_run" (
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"period_key" text NOT NULL,
	"state" text NOT NULL,
	"error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	CONSTRAINT "report_mail_run_organization_id_user_id_period_key_pk" PRIMARY KEY("organization_id","user_id","period_key")
);
--> statement-breakpoint
CREATE TABLE "report_subscription" (
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"frequency" text NOT NULL,
	"attach_pdf" boolean DEFAULT true NOT NULL,
	"since" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "report_subscription_organization_id_user_id_pk" PRIMARY KEY("organization_id","user_id")
);
--> statement-breakpoint
ALTER TABLE "report_mail_run" ADD CONSTRAINT "report_mail_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_mail_run" ADD CONSTRAINT "report_mail_run_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_subscription" ADD CONSTRAINT "report_subscription_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_subscription" ADD CONSTRAINT "report_subscription_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "report_mail_run_created_idx" ON "report_mail_run" USING btree ("created_at");