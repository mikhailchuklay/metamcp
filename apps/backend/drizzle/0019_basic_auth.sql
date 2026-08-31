CREATE TYPE "public"."mcp_server_auth_type" AS ENUM('NONE', 'BEARER', 'BASIC');--> statement-breakpoint
ALTER TABLE "mcp_servers" ADD COLUMN "auth_type" "mcp_server_auth_type" DEFAULT 'NONE' NOT NULL;--> statement-breakpoint
ALTER TABLE "mcp_servers" ADD COLUMN "basic_username" text;--> statement-breakpoint
ALTER TABLE "mcp_servers" ADD COLUMN "basic_password" text;
--> statement-breakpoint
-- Backfill: before this column existed, a server sent `Authorization: Bearer
-- <bearer_token>` whenever a bearer token was set. Flag those rows as BEARER
-- so they keep behaving identically. Rows without a token stay NONE, which
-- leaves any hand-written `Authorization` custom header in force -- the
-- pre-existing workaround for Basic auth.
UPDATE "mcp_servers" SET "auth_type" = 'BEARER' WHERE "bearer_token" IS NOT NULL AND "bearer_token" <> '';
