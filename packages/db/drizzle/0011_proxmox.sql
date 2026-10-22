CREATE TABLE "proxmox_cluster" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"api_url" text NOT NULL,
	"host" text NOT NULL,
	"port" integer DEFAULT 8006 NOT NULL,
	"token_id" text NOT NULL,
	"secret_id" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"cert_status" text DEFAULT 'pending' NOT NULL,
	"cert_fingerprint" text,
	"cert_subject" text,
	"cert_issuer" text,
	"cert_valid_from" timestamp with time zone,
	"cert_valid_to" timestamp with time zone,
	"cert_confirmed_at" timestamp with time zone,
	"cert_confirmed_by" text,
	"candidate_fingerprint" text,
	"candidate_subject" text,
	"candidate_issuer" text,
	"candidate_valid_from" timestamp with time zone,
	"candidate_valid_to" timestamp with time zone,
	"candidate_ca_trusted" boolean,
	"candidate_seen_at" timestamp with time zone,
	"extra_privileges" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"acknowledged_privileges" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"privileges_acknowledged_at" timestamp with time zone,
	"privileges_acknowledged_by" text,
	"permissions_checked_at" timestamp with time zone,
	"version" text,
	"cluster_name" text,
	"quorate" boolean,
	"backups_readable" boolean DEFAULT false NOT NULL,
	"last_sync_at" timestamp with time zone,
	"last_error" text,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "proxmox_guest" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cluster_id" text NOT NULL,
	"vmid" integer NOT NULL,
	"type" text NOT NULL,
	"name" text NOT NULL,
	"node" text NOT NULL,
	"status" text NOT NULL,
	"status_since" timestamp with time zone NOT NULL,
	"cpu" real,
	"cpus" integer,
	"mem" bigint,
	"max_mem" bigint,
	"disk" bigint,
	"max_disk" bigint,
	"uptime" bigint,
	"ostype" text,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"template" boolean DEFAULT false NOT NULL,
	"ha_state" text,
	"in_backup_job" boolean,
	"last_backup_at" timestamp with time zone,
	"snapshot_count" integer,
	"newest_snapshot_at" timestamp with time zone,
	"oldest_snapshot_at" timestamp with time zone,
	"ips" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "proxmox_node" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cluster_id" text NOT NULL,
	"name" text NOT NULL,
	"online" boolean NOT NULL,
	"cpu" real,
	"cpus" integer,
	"mem" bigint,
	"max_mem" bigint,
	"disk" bigint,
	"max_disk" bigint,
	"uptime" bigint,
	"pve_version" text,
	"kernel" text,
	"pending_updates" integer,
	"last_seen_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "proxmox_storage" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cluster_id" text NOT NULL,
	"node" text NOT NULL,
	"name" text NOT NULL,
	"type" text,
	"content" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"shared" boolean DEFAULT false NOT NULL,
	"status" text,
	"used" bigint,
	"total" bigint
);
--> statement-breakpoint
CREATE TABLE "proxmox_sync_run" (
	"id" text PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"cluster_id" text NOT NULL,
	"state" text NOT NULL,
	"trigger" text NOT NULL,
	"requested_by" text,
	"node_count" integer,
	"guest_count" integer,
	"request_count" integer,
	"warnings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "proxmox_cluster" ADD CONSTRAINT "proxmox_cluster_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_cluster" ADD CONSTRAINT "proxmox_cluster_secret_id_secret_id_fk" FOREIGN KEY ("secret_id") REFERENCES "public"."secret"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_cluster" ADD CONSTRAINT "proxmox_cluster_cert_confirmed_by_user_id_fk" FOREIGN KEY ("cert_confirmed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_cluster" ADD CONSTRAINT "proxmox_cluster_privileges_acknowledged_by_user_id_fk" FOREIGN KEY ("privileges_acknowledged_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_cluster" ADD CONSTRAINT "proxmox_cluster_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_guest" ADD CONSTRAINT "proxmox_guest_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_guest" ADD CONSTRAINT "proxmox_guest_cluster_id_proxmox_cluster_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."proxmox_cluster"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_node" ADD CONSTRAINT "proxmox_node_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_node" ADD CONSTRAINT "proxmox_node_cluster_id_proxmox_cluster_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."proxmox_cluster"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_storage" ADD CONSTRAINT "proxmox_storage_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_storage" ADD CONSTRAINT "proxmox_storage_cluster_id_proxmox_cluster_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."proxmox_cluster"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_sync_run" ADD CONSTRAINT "proxmox_sync_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_sync_run" ADD CONSTRAINT "proxmox_sync_run_cluster_id_proxmox_cluster_id_fk" FOREIGN KEY ("cluster_id") REFERENCES "public"."proxmox_cluster"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "proxmox_sync_run" ADD CONSTRAINT "proxmox_sync_run_requested_by_user_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "proxmox_cluster_org_name_uq" ON "proxmox_cluster" USING btree ("organization_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "proxmox_cluster_org_endpoint_uq" ON "proxmox_cluster" USING btree ("organization_id","host","port");--> statement-breakpoint
CREATE UNIQUE INDEX "proxmox_guest_cluster_vmid_uq" ON "proxmox_guest" USING btree ("cluster_id","vmid");--> statement-breakpoint
CREATE INDEX "proxmox_guest_org_name_idx" ON "proxmox_guest" USING btree ("organization_id","name","id");--> statement-breakpoint
CREATE UNIQUE INDEX "proxmox_node_cluster_name_uq" ON "proxmox_node" USING btree ("cluster_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "proxmox_storage_cluster_uq" ON "proxmox_storage" USING btree ("cluster_id","node","name");--> statement-breakpoint
CREATE INDEX "proxmox_sync_run_cluster_idx" ON "proxmox_sync_run" USING btree ("cluster_id","created_at","id");--> statement-breakpoint
CREATE INDEX "proxmox_sync_run_org_idx" ON "proxmox_sync_run" USING btree ("organization_id","created_at","id");