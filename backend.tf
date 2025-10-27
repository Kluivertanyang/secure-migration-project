terraform {
  backend "remote" {
    organization = "TFE-PROD-GRADE-INFRA"

    workspaces {
      name = "s3-secure-data-migration-ai"
    }
  }
}


