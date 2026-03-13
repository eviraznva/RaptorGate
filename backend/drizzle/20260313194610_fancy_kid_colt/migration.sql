CREATE TYPE "user_roles" AS ENUM('super_admin', 'admin', 'operator', 'viewer');--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY,
	"username" varchar(64) NOT NULL,
	"password_hash" varchar(255) NOT NULL,
	"refresh_token" varchar,
	"role" "user_roles" DEFAULT 'viewer'::"user_roles" NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
