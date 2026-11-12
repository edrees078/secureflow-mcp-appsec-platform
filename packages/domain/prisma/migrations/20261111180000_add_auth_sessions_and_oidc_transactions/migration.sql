BEGIN;

-- CreateTable
CREATE TABLE "user_sessions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "session_token_hash" VARCHAR(64) NOT NULL,
    "csrf_token" VARCHAR(64) NOT NULL,
    "oidc_sid" VARCHAR(255),
    "ip_address" INET,
    "user_agent" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_active_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idle_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revoke_reason" VARCHAR(100),

    CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_transactions" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "txn_token_hash" VARCHAR(64) NOT NULL,
    "state_hash" VARCHAR(64) NOT NULL,
    "nonce" VARCHAR(255) NOT NULL,
    "code_verifier" VARCHAR(255) NOT NULL,
    "return_to" VARCHAR(500) NOT NULL DEFAULT '/',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),

    CONSTRAINT "oidc_transactions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_sessions_session_token_hash_key" ON "user_sessions"("session_token_hash");

-- CreateIndex
CREATE INDEX "user_sessions_user_id_revoked_at_idx" ON "user_sessions"("user_id", "revoked_at");

-- CreateIndex
CREATE INDEX "user_sessions_expires_at_idx" ON "user_sessions"("expires_at");

-- CreateIndex
CREATE INDEX "user_sessions_idle_expires_at_idx" ON "user_sessions"("idle_expires_at");

-- CreateIndex
CREATE INDEX "user_sessions_oidc_sid_idx" ON "user_sessions"("oidc_sid");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_transactions_txn_token_hash_key" ON "oidc_transactions"("txn_token_hash");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_transactions_state_hash_key" ON "oidc_transactions"("state_hash");

-- CreateIndex
CREATE INDEX "oidc_transactions_expires_at_idx" ON "oidc_transactions"("expires_at");

-- AddForeignKey
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

COMMIT;
