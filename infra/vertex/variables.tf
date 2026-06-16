# Input variables for the keyless Vertex/Gemini WIF foundation (DESIGN_03, Phase 2).
#
# These are the single source of truth for the identifiers referenced across this
# module's other files:
#   - wif.tf      : google_iam_workload_identity_pool.github
#                   google_iam_workload_identity_pool_provider.github
#                   google_service_account.guardian (+ IAM bindings)
#   - outputs.tf  : the full provider resource name + SA email consumed by CI.
#
# Security note (DESIGN_03 Decision 3/11): the provider is REPO-SCOPED. The
# attribute_condition asserts assertion.repository == var.github_repository, and
# the WIF binding member is
#   principalSet://.../attribute.repository/<github_repository>
# so var.github_repository is load-bearing for the trust boundary. Keep it pinned
# to the exact owner/repo slug. NO service-account key is ever created.

variable "project_id" {
  description = "GCP project ID that owns the Workload Identity Pool, provider, Guardian service account, and the roles/aiplatform.user binding. Required; no default so the project is always chosen explicitly."
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "project_id must be a non-empty GCP project ID."
  }
}

variable "region" {
  description = "GCP region used as the Vertex AI location for Gemini calls (GOOGLE_CLOUD_LOCATION). DESIGN_03 R3 pins us-central1."
  type        = string
  default     = "us-central1"

  validation {
    condition     = length(var.region) > 0
    error_message = "region must be a non-empty GCP region, e.g. us-central1."
  }
}

variable "github_repository" {
  description = "Repo-scoped trust boundary as owner/repo. Drives the provider attribute_condition (assertion.repository == this) and the principalSet WIF binding member. MUST be repo-scoped, never owner-only (DESIGN_03 Decision 3/11)."
  type        = string
  default     = "zanonicode/ifolder-sync"

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repository))
    error_message = "github_repository must be a single owner/repo slug (exactly one slash), e.g. zanonicode/ifolder-sync. An owner-only value would broaden the trust boundary."
  }
}

variable "pool_id" {
  description = "Workload Identity Pool ID (workload_identity_pool_id) for the GitHub Actions OIDC federation. Lower-case letters, digits, and hyphens; 4-32 chars."
  type        = string
  default     = "github-pool"

  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.pool_id))
    error_message = "pool_id must be 4-32 chars of lowercase letters, digits, or hyphens."
  }
}

variable "provider_id" {
  description = "Workload Identity Pool Provider ID (workload_identity_pool_provider_id) for the GitHub OIDC issuer. Lower-case letters, digits, and hyphens; 4-32 chars."
  type        = string
  default     = "github-provider"

  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.provider_id))
    error_message = "provider_id must be 4-32 chars of lowercase letters, digits, or hyphens."
  }
}

variable "sa_account_id" {
  description = "Account ID (local part of the email) for the Guardian service account, bound to roles/aiplatform.user only (least privilege; viewer cannot call predict). GCP requires 6-30 chars: lowercase letter start, lowercase letters/digits/hyphens, no trailing hyphen."
  type        = string
  default     = "invariant-guardian"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.sa_account_id))
    error_message = "sa_account_id must be 6-30 chars: start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}
