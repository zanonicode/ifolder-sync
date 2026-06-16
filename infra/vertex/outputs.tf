# Outputs for the keyless WIF + Vertex Guardian setup (DESIGN_03, Decision 3 / Pattern 5).
#
# These map 1:1 to the GitHub repository variables the AI-CI workflows consume
# (ai-guardian.yml, ai-eval.yml). After `terraform apply`, copy each value into the
# matching repo variable (Settings -> Secrets and variables -> Actions -> Variables):
#
#   terraform output -raw workload_identity_provider  ->  repo var WIF_PROVIDER
#   terraform output -raw service_account             ->  repo var VERTEX_SA
#   terraform output -raw project_id                  ->  repo var GCP_PROJECT
#
# None of these are secrets (keyless WIF means there is no service-account key to leak);
# they are non-sensitive repository *variables*, not secrets.

output "workload_identity_provider" {
  description = <<-EOT
    Feeds GitHub repo var WIF_PROVIDER. The FULL provider resource name
    (projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<pool>/providers/<provider>),
    which resolves with the project NUMBER, not the ID. This exact string is what
    google-github-actions/auth@v3 expects for `workload_identity_provider`.
  EOT
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account" {
  description = <<-EOT
    Feeds GitHub repo var VERTEX_SA. The Guardian service account email passed to
    google-github-actions/auth@v3 as `service_account` for SA impersonation
    (roles/aiplatform.user; no key is ever created).
  EOT
  value       = google_service_account.guardian.email
}

output "project_id" {
  description = "Feeds GitHub repo var GCP_PROJECT. The GCP project ID hosting the WIF pool, Guardian SA, and Vertex AI calls."
  value       = var.project_id
}
