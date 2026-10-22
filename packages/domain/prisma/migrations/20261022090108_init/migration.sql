BEGIN;

-- CreateEnum
CREATE TYPE "global_role" AS ENUM ('ADMIN', 'ANALYST', 'DEVELOPER');

-- CreateEnum
CREATE TYPE "project_role" AS ENUM ('ANALYST', 'DEVELOPER');

-- CreateEnum
CREATE TYPE "finding_severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "finding_category" AS ENUM ('INJECTION', 'AUTH', 'ACCESS_CONTROL', 'CRYPTO', 'XSS', 'SSRF', 'IDOR', 'INSECURE_DESERIALIZATION', 'SUPPLY_CHAIN', 'CONFIG_EXPOSURE', 'SENSITIVE_DATA', 'LOGGING', 'OTHER');

-- CreateEnum
CREATE TYPE "finding_status" AS ENUM ('OPEN', 'TRIAGED', 'IN_PROGRESS', 'READY_FOR_REVIEW', 'VERIFIED', 'CLOSED', 'REOPENED');

-- CreateEnum
CREATE TYPE "remediation_task_status" AS ENUM ('PENDING', 'IN_PROGRESS', 'SUBMITTED', 'VERIFIED', 'REJECTED');

-- CreateEnum
CREATE TYPE "finding_event_type" AS ENUM ('CREATED', 'STATUS_CHANGED', 'ASSIGNED', 'UNASSIGNED', 'UPDATED', 'DELETED', 'REOPENED');

-- CreateEnum
CREATE TYPE "audit_event_category" AS ENUM ('AUTH', 'FINDING', 'PROJECT', 'MEMBER', 'TASK', 'MCP');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "sub" VARCHAR(255) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "display_name" VARCHAR(255) NOT NULL,
    "global_role" "global_role" NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "projects" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "name" VARCHAR(255) NOT NULL,
    "slug" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_by_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "project_members" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "project_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role" "project_role" NOT NULL,
    "added_by_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "project_members_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "project_id" UUID NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "finding_severity" NOT NULL,
    "category" "finding_category" NOT NULL,
    "cvss_score" DECIMAL(3,1),
    "status" "finding_status" NOT NULL DEFAULT 'OPEN',
    "created_by_id" UUID NOT NULL,
    "assigned_to_id" UUID,
    "due_date" DATE,
    "is_deleted" BOOLEAN NOT NULL DEFAULT false,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remediation_tasks" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "finding_id" UUID NOT NULL,
    "assigned_to_id" UUID NOT NULL,
    "assigned_by_id" UUID NOT NULL,
    "description" TEXT NOT NULL,
    "notes" TEXT,
    "status" "remediation_task_status" NOT NULL DEFAULT 'PENDING',
    "due_date" DATE,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "remediation_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "finding_id" UUID NOT NULL,
    "actor_id" UUID NOT NULL,
    "event_type" "finding_event_type" NOT NULL,
    "previous_status" VARCHAR(50),
    "new_status" VARCHAR(50),
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "actor_id" UUID,
    "event_category" "audit_event_category" NOT NULL,
    "event_type" VARCHAR(100) NOT NULL,
    "resource_id" UUID,
    "resource_type" VARCHAR(100),
    "before_state" JSONB,
    "after_state" JSONB,
    "ip_address" INET,
    "user_agent" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_sub_key" ON "users"("sub");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "projects_slug_key" ON "projects"("slug");

-- CreateIndex
CREATE INDEX "projects_created_by_id_idx" ON "projects"("created_by_id");

-- CreateIndex
CREATE INDEX "project_members_user_id_idx" ON "project_members"("user_id");

-- CreateIndex
CREATE INDEX "project_members_added_by_id_idx" ON "project_members"("added_by_id");

-- CreateIndex
CREATE UNIQUE INDEX "project_members_project_id_user_id_key" ON "project_members"("project_id", "user_id");

-- CreateIndex
CREATE INDEX "findings_project_id_idx" ON "findings"("project_id");

-- CreateIndex
CREATE INDEX "findings_assigned_to_id_idx" ON "findings"("assigned_to_id");

-- CreateIndex
CREATE INDEX "findings_status_idx" ON "findings"("status");

-- CreateIndex
CREATE INDEX "findings_project_id_status_idx" ON "findings"("project_id", "status");

-- CreateIndex
CREATE INDEX "findings_is_deleted_idx" ON "findings"("is_deleted");

-- CreateIndex
CREATE INDEX "findings_created_by_id_idx" ON "findings"("created_by_id");

-- CreateIndex
CREATE INDEX "remediation_tasks_finding_id_idx" ON "remediation_tasks"("finding_id");

-- CreateIndex
CREATE INDEX "remediation_tasks_assigned_to_id_idx" ON "remediation_tasks"("assigned_to_id");

-- CreateIndex
CREATE INDEX "remediation_tasks_assigned_by_id_idx" ON "remediation_tasks"("assigned_by_id");

-- CreateIndex
CREATE INDEX "finding_events_finding_id_idx" ON "finding_events"("finding_id");

-- CreateIndex
CREATE INDEX "finding_events_actor_id_idx" ON "finding_events"("actor_id");

-- CreateIndex
CREATE INDEX "finding_events_created_at_idx" ON "finding_events"("created_at" DESC);

-- CreateIndex
CREATE INDEX "audit_events_actor_id_idx" ON "audit_events"("actor_id");

-- CreateIndex
CREATE INDEX "audit_events_event_category_event_type_idx" ON "audit_events"("event_category", "event_type");

-- CreateIndex
CREATE INDEX "audit_events_resource_id_resource_type_idx" ON "audit_events"("resource_id", "resource_type");

-- CreateIndex
CREATE INDEX "audit_events_created_at_idx" ON "audit_events"("created_at" DESC);

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_members" ADD CONSTRAINT "project_members_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_members" ADD CONSTRAINT "project_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_members" ADD CONSTRAINT "project_members_added_by_id_fkey" FOREIGN KEY ("added_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_assigned_to_id_fkey" FOREIGN KEY ("assigned_to_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_tasks" ADD CONSTRAINT "remediation_tasks_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_tasks" ADD CONSTRAINT "remediation_tasks_assigned_to_id_fkey" FOREIGN KEY ("assigned_to_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_tasks" ADD CONSTRAINT "remediation_tasks_assigned_by_id_fkey" FOREIGN KEY ("assigned_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_events" ADD CONSTRAINT "finding_events_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ============================================================================
-- Supplementary Database Integrity Constraints
-- ============================================================================

-- 1. Partial Unique Index: Exactly one active remediation task per finding
CREATE UNIQUE INDEX "one_active_remediation_task_per_finding"
ON "remediation_tasks"("finding_id")
WHERE "status" NOT IN ('VERIFIED', 'REJECTED');

-- 2. CHECK Constraint: CVSS v3.1 score must be within [0.0, 10.0] or NULL
ALTER TABLE "findings"
ADD CONSTRAINT "check_cvss_score_range"
CHECK ("cvss_score" IS NULL OR ("cvss_score" >= 0.0 AND "cvss_score" <= 10.0));

COMMIT;
