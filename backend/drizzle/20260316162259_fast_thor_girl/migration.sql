CREATE TABLE "configuration_snapshots" (
	"id" uuid PRIMARY KEY,
	"version_number" integer NOT NULL,
	"snapshot_type" varchar(32) NOT NULL,
	"checksum" varchar(128) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"payload_json" json NOT NULL,
	"changeSummary" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dns_blacklist" (
	"id" uuid PRIMARY KEY,
	"domain" varchar(255) NOT NULL,
	"reason" text NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "firewall_certificates" (
	"id" uuid PRIMARY KEY,
	"cert_type" varchar(32) NOT NULL,
	"common_name" varchar(255) NOT NULL,
	"fingerprint" varchar(128) NOT NULL,
	"certificate_pem" text NOT NULL,
	"private_key_ref" varchar(255) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "identity_manager_user_sessions" (
	"id" uuid PRIMARY KEY,
	"identity_user_id" uuid NOT NULL,
	"radius_username" varchar(255) NOT NULL,
	"mac_address" varchar(45) NOT NULL,
	"ip_address" varchar(45) NOT NULL,
	"nas_ip" varchar(64) NOT NULL,
	"called_station_id" varchar(64) NOT NULL,
	"authenticated_at" timestamp NOT NULL,
	"expires_at" timestamp NOT NULL,
	"synced_from_redis_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "identity_users" (
	"id" uuid PRIMARY KEY,
	"username" varchar(128) NOT NULL,
	"display_name" varchar(128) NOT NULL,
	"source" varchar(16) NOT NULL,
	"external_id" varchar(255) NOT NULL,
	"email" varchar(255),
	"last_seen_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ips_signatures" (
	"id" uuid PRIMARY KEY,
	"name" varchar(128) NOT NULL,
	"category" varchar(32) NOT NULL,
	"pattern" text NOT NULL,
	"severity" varchar(16) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ml_models" (
	"id" uuid PRIMARY KEY,
	"name" varchar(128) NOT NULL,
	"version" varchar(64) NOT NULL,
	"artifact_path" varchar(255) NOT NULL,
	"checksum" varchar(128) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"activated_at" timestamp,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "nat_rules" (
	"id" uuid PRIMARY KEY,
	"type" varchar(16) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"src_ip" varchar(64),
	"dst_ip" varchar(64),
	"src_port" integer,
	"dst_port" integer,
	"translated_ip" varchar(64),
	"translated_port" integer,
	"priority" integer NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "network_session_history" (
	"id" uuid PRIMARY KEY,
	"identity_session_id" uuid NOT NULL,
	"src_ip" varchar(45) NOT NULL,
	"dst_ip" varchar(45) NOT NULL,
	"application" varchar(64) NOT NULL,
	"domain" varchar(255) NOT NULL,
	"bytesSent" bigint NOT NULL,
	"bytesReceived" bigint NOT NULL,
	"packetsTotal" bigint NOT NULL,
	"started_at" timestamp NOT NULL,
	"ended_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "permissions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"name" varchar(128) NOT NULL UNIQUE,
	"description" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"role_id" uuid,
	"permission_id" uuid,
	CONSTRAINT "role_permissions_pkey" PRIMARY KEY("role_id","permission_id")
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"name" varchar(64) NOT NULL UNIQUE,
	"description" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "user_roles" (
	"user_id" uuid,
	"role_id" uuid,
	CONSTRAINT "user_roles_pkey" PRIMARY KEY("user_id","role_id")
);
--> statement-breakpoint
CREATE TABLE "rule_change_history" (
	"id" uuid PRIMARY KEY,
	"rule_id" uuid NOT NULL,
	"changed_by" uuid NOT NULL,
	"modified_at" timestamp NOT NULL,
	"content" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rules" (
	"id" uuid PRIMARY KEY,
	"name" varchar(128) NOT NULL,
	"description" text,
	"zone_pair_id" uuid NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"content" text NOT NULL,
	"priority" smallint NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY,
	"user_id" uuid NOT NULL,
	"ip_address" varchar(45) NOT NULL,
	"user_agent" varchar(255) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"expires_at" timestamp NOT NULL,
	"revoked_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "ssl_bypass_list" (
	"id" uuid PRIMARY KEY,
	"domain" varchar(255) NOT NULL,
	"reason" text NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_group_members" (
	"id" uuid PRIMARY KEY,
	"group_id" uuid NOT NULL,
	"identity_user_id" uuid NOT NULL,
	"joined_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_groups" (
	"id" uuid PRIMARY KEY,
	"name" varchar(64) NOT NULL,
	"description" text,
	"source" varchar(16) NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY,
	"username" varchar(64) NOT NULL,
	"password_hash" varchar(255) NOT NULL,
	"refresh_token" varchar,
	"refresh_token_expiry" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "zone_interfaces" (
	"id" uuid PRIMARY KEY,
	"zone_id" uuid NOT NULL,
	"interface_name" varchar(64) NOT NULL,
	"vlanId" integer NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "zone_pairs" (
	"id" uuid PRIMARY KEY,
	"src_zone_id" uuid NOT NULL,
	"dst_zone_id" uuid NOT NULL,
	"default_policy" varchar NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "zones" (
	"id" uuid PRIMARY KEY,
	"name" varchar(64) NOT NULL,
	"description" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
ALTER TABLE "configuration_snapshots" ADD CONSTRAINT "configuration_snapshots_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "dns_blacklist" ADD CONSTRAINT "dns_blacklist_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "firewall_certificates" ADD CONSTRAINT "firewall_certificates_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "identity_manager_user_sessions" ADD CONSTRAINT "identity_manager_user_sessions_ohlLwI7NTFYH_fkey" FOREIGN KEY ("identity_user_id") REFERENCES "identity_users"("id");--> statement-breakpoint
ALTER TABLE "ml_models" ADD CONSTRAINT "ml_models_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "nat_rules" ADD CONSTRAINT "nat_rules_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "network_session_history" ADD CONSTRAINT "network_session_history_XkXUscJR3Z1h_fkey" FOREIGN KEY ("identity_session_id") REFERENCES "identity_manager_user_sessions"("id");--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_id_roles_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permission_id_permissions_id_fkey" FOREIGN KEY ("permission_id") REFERENCES "permissions"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_id_roles_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "rule_change_history" ADD CONSTRAINT "rule_change_history_rule_id_rules_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "rules"("id");--> statement-breakpoint
ALTER TABLE "rule_change_history" ADD CONSTRAINT "rule_change_history_changed_by_users_id_fkey" FOREIGN KEY ("changed_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "rules" ADD CONSTRAINT "rules_zone_pair_id_zone_pairs_id_fkey" FOREIGN KEY ("zone_pair_id") REFERENCES "zone_pairs"("id");--> statement-breakpoint
ALTER TABLE "rules" ADD CONSTRAINT "rules_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "ssl_bypass_list" ADD CONSTRAINT "ssl_bypass_list_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "user_group_members" ADD CONSTRAINT "user_group_members_group_id_user_groups_id_fkey" FOREIGN KEY ("group_id") REFERENCES "user_groups"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "user_group_members" ADD CONSTRAINT "user_group_members_identity_user_id_identity_users_id_fkey" FOREIGN KEY ("identity_user_id") REFERENCES "identity_users"("id");--> statement-breakpoint
ALTER TABLE "user_groups" ADD CONSTRAINT "user_groups_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "zone_interfaces" ADD CONSTRAINT "zone_interfaces_zone_id_zones_id_fkey" FOREIGN KEY ("zone_id") REFERENCES "zones"("id");--> statement-breakpoint
ALTER TABLE "zone_pairs" ADD CONSTRAINT "zone_pairs_src_zone_id_zones_id_fkey" FOREIGN KEY ("src_zone_id") REFERENCES "zones"("id");--> statement-breakpoint
ALTER TABLE "zone_pairs" ADD CONSTRAINT "zone_pairs_dst_zone_id_zones_id_fkey" FOREIGN KEY ("dst_zone_id") REFERENCES "zones"("id");--> statement-breakpoint
ALTER TABLE "zone_pairs" ADD CONSTRAINT "zone_pairs_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");--> statement-breakpoint
ALTER TABLE "zones" ADD CONSTRAINT "zones_created_by_users_id_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id");