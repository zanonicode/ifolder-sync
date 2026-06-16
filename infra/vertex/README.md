# Vertex AI — keyless WIF setup (Invariant Guardian)

One-time setup for the AI-CI Phase 2 foundation: a **keyless** Vertex AI path for the
Invariant Guardian. Terraform builds a Workload Identity Federation (WIF) pool/provider
and a least-privilege service account; GitHub Actions then federates an OIDC token into
that SA — **no service-account key is ever created or committed**.

This guide assumes a brand-new GCP project on the $300 free trial. Run the steps in order.

- **Terraform here:** `wif.tf`, `variables.tf`, `outputs.tf` (provider `hashicorp/google ~> 6.0`).
- **Reference:** `.claude/sdd/features/DESIGN_03_ai_ci_integration.md` — Decision 3 (keyless WIF), Decision 5 (`google-genai`), Decision 10 (cost).

> **Security (one line):** keyless (OIDC → SA impersonation), **repo-scoped** to
> `zanonicode/ifolder-sync`, least privilege (`roles/aiplatform.user`) — nothing static
> is ever committed.

---

## 1. Prerequisites

Install the two CLIs (macOS / Homebrew shown; use your platform's installer otherwise):

```bash
brew install --cask google-cloud-sdk   # gcloud
brew install terraform                  # terraform (or: brew install hashicorp/tap/terraform)
brew install gh                         # GitHub CLI (used in step 5)

gcloud version
terraform version
gh auth status          # must be logged in to GitHub for step 5
```

---

## 2. Create a new GCP project and link the trial billing account

The $300 credit lives on a **Free Trial billing account** created when you sign up.
Find its ID, create a fresh project, link billing, and make the project active.

```bash
# Pick a globally-unique project id (lowercase, digits, hyphens; 6–30 chars):
export PROJECT_ID="ifolder-sync-ai"          # change if taken

# Create the project and make it the active default:
gcloud projects create "$PROJECT_ID"
gcloud config set project "$PROJECT_ID"

# Find your trial billing account id (looks like 0X0X0X-0X0X0X-0X0X0X):
gcloud billing accounts list

# Link it (billing must be enabled before any API can be used):
export BILLING_ACCOUNT_ID="XXXXXX-XXXXXX-XXXXXX"   # from the list above
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT_ID"
```

---

## 3. Application Default Credentials (ADC) login

Terraform and `gcloud` authenticate as **you** for this one-time setup via ADC:

```bash
gcloud auth application-default login
```

---

## 4. Terraform: enable APIs + build the WIF pool/provider/SA (no keys)

`terraform apply` enables the required APIs and creates the WIF pool, provider, and the
`invariant-guardian` service account with `roles/aiplatform.user`. **No key is generated.**

```bash
cd infra/vertex
terraform init
terraform plan  -var="project_id=$PROJECT_ID"
terraform apply -var="project_id=$PROJECT_ID"
```

Defaults you can override with extra `-var=...` flags:

| Variable | Default | Notes |
|---|---|---|
| `project_id` | *(required)* | no default — pass it explicitly |
| `region` | `us-central1` | Vertex region for the Guardian |
| `github_repository` | `zanonicode/ifolder-sync` | repo-scoped WIF condition |
| `pool_id` | `github-pool` | WIF pool id |
| `provider_id` | `github-provider` | WIF provider id |
| `sa_account_id` | `invariant-guardian` | service account id |

---

## 5. Wire the three GitHub repo **variables**

Read the Terraform outputs and set them as repo **variables** (not secrets — these are
non-sensitive identifiers). The Guardian workflow reads `vars.GCP_PROJECT`,
`vars.WIF_PROVIDER`, `vars.VERTEX_SA`.

```bash
# Still in infra/vertex; -raw avoids quoting noise:
gh variable set GCP_PROJECT --body "$(terraform output -raw project_id)"
gh variable set WIF_PROVIDER --body "$(terraform output -raw workload_identity_provider)"
gh variable set VERTEX_SA    --body "$(terraform output -raw service_account)"

gh variable list   # confirm all three are present
```

- `workload_identity_provider` is the **full resource name with the project NUMBER**
  (`projects/<NUMBER>/locations/global/workloadIdentityPools/.../providers/...`) — required
  by `google-github-actions/auth`.
- These are **variables**, not secrets. The only secret, `ANTHROPIC_API_KEY`, is added
  **later in Phase 4** (eval judge only) and is billed separately by Anthropic — keep it
  off this GCP trial.

---

## 6. Wait for IAM propagation, then smoke-test

IAM bindings can take **~5 minutes** to propagate. Don't smoke-test immediately. Then run
the one-call Vertex reachability check (keyless — uses your local ADC from step 3):

```bash
# ~5 min after apply. Back to the repo root first (steps 4–5 left you in infra/vertex):
cd "$(git rev-parse --show-toplevel)"
pip install google-genai==2.8.0

GOOGLE_CLOUD_PROJECT="$PROJECT_ID" \
GOOGLE_CLOUD_LOCATION=us-central1 \
python scripts/ai_guardian/smoke_test.py
```

A successful run confirms `gemini-2.5-flash` is reachable in the project before any CI
wiring depends on it. If it fails with a permissions error, wait a bit longer (propagation)
and retry.

---

## Cost note

- **Guardian:** ~**$0.004 per PR** (`gemini-2.5-flash`, single call, capped diff).
- **Trial credit:** $300, valid for **90 calendar days** from account creation (not
  usage-based) — it expires on the calendar, so spread your testing accordingly.
- **Who pays what:** Gemini/Vertex usage **consumes the GCP credit**; the Phase-4
  `ANTHROPIC_API_KEY` (eval judge) is **billed separately by Anthropic** and cannot be
  paid from the GCP credit. Keep the two on separate billing.