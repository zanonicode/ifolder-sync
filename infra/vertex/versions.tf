# Terraform + provider pins for the keyless Vertex/Gemini WIF foundation.
# Companion files: wif.tf (pool/provider/SA/IAM), variables.tf, outputs.tf.
# Provider held at hashicorp/google ~> 6.0 per DESIGN_03 (verified 2026-06-14);
# every infra/vertex/*.tf file shares this exact pin.

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
