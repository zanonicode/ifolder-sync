# Keyless Workload Identity Federation for the Invariant Guardian (DESIGN_03, Pattern 5).
#
# GitHub Actions (zanonicode/ifolder-sync) authenticates to Vertex AI via an OIDC
# token exchanged through this pool/provider, then impersonates the `guardian` service
# account (roles/aiplatform.user). No service-account KEY is ever created — keyless WIF
# is the entire point (Decision 3). SA impersonation (not Direct WIF) yields an OAuth2
# token with up to a 1 h lifetime, vs. Direct WIF's 10 min cap.
#
# Security spine (Decisions 3 & 11):
#   - attribute_condition is REPO-SCOPED (assertion.repository == var.github_repository),
#     never owner-scoped — only this one repo can mint Guardian credentials.
#   - attribute.repository is MAPPED before it is asserted on (asserting an unmapped
#     claim silently fails open in the IAM evaluator).
#   - the workloadIdentityUser binding targets a principalSet keyed by
#     attribute.repository/<repo>, so the federated identity is the repo, not the org.
#
# Note: IAM propagation can take ~5 min after `terraform apply` — do not smoke-test the
# Vertex reachability check immediately after this applies.
#
# The terraform{} and provider "google" blocks live in versions.tf (single source for
# the whole module); re-declaring them here would be a duplicate-provider error.

# --- API enablement (this is a from-scratch project) -------------------------------
#
# aiplatform     — Vertex AI predict (the Guardian's generate_content call).
# iamcredentials — mints the impersonated SA's OAuth2 access token (SA impersonation).
# sts            — Security Token Service: exchanges the GitHub OIDC token for a
#                  federated Google token (the WIF token exchange itself).
#
# disable_on_destroy = false: tearing down this Terraform must never disable a
# project-wide API that other workloads may depend on.

resource "google_project_service" "aiplatform" {
  project            = var.project_id
  service            = "aiplatform.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iamcredentials" {
  project            = var.project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sts" {
  project            = var.project_id
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

# --- Workload Identity Pool + GitHub OIDC provider ---------------------------------

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "GitHub Actions pool"
  description               = "Keyless WIF pool for GitHub Actions OIDC (ifolder-sync AI-CI)."

  # STS must exist before the pool can be created and used for token exchange.
  depends_on = [google_project_service.sts]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "GitHub Actions provider"
  description                        = "GitHub Actions OIDC provider, repo-scoped to ${var.github_repository}."

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # Map a claim BEFORE asserting on it (Decision 3). attribute.repository must be
  # mapped here so the attribute_condition below — and the principalSet binding — can
  # reference it.
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # REPO-SCOPED, never owner-scoped: only zanonicode/ifolder-sync can authenticate.
  attribute_condition = "assertion.repository == '${var.github_repository}'"

  depends_on = [google_iam_workload_identity_pool.github]
}

# --- Guardian service account ------------------------------------------------------

resource "google_service_account" "guardian" {
  project      = var.project_id
  account_id   = var.sa_account_id
  display_name = "Invariant Guardian (Vertex AI-CI)"
  description  = "Impersonated by GitHub Actions via WIF to call Vertex AI. No key."

  # iamcredentials backs the impersonation token-minting for this SA.
  depends_on = [google_project_service.iamcredentials]
}

# Least privilege: roles/aiplatform.user is the minimum that can call predict.
# NOT roles/aiplatform.viewer (viewer cannot invoke the model) and NOT
# roles/aiplatform.serviceAgent (that is for fine-tuning service agents).
resource "google_project_iam_member" "guardian_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.guardian.email}"

  depends_on = [google_project_service.aiplatform]
}

# --- WIF binding: only this repo may impersonate the Guardian SA --------------------
#
# The principalSet is keyed by attribute.repository (mapped above), so the federated
# identity is the repository itself, not its owner. pool .name is the full resource
# name (projects/<NUMBER>/locations/global/workloadIdentityPools/<pool_id>).

resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.guardian.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}
