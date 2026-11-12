-- Case-insensitive email uniqueness index on users(LOWER(email))
-- Preserves existing users_email_key and users_sub_key constraints while preventing
-- case-variant email bypasses during OIDC authentication and Admin bootstrap.

BEGIN;

CREATE UNIQUE INDEX "users_email_lower_key" ON "users" (LOWER("email"));

COMMIT;
