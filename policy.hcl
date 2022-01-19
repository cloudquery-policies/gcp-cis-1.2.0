policy "cis-v1.30" {
  title = "GCP CIS V1.2.0 Policy"
  configuration {
    provider "gcp" {
      version = ">= 0.4.0"
    }
  }
    check "1.1" {
      title = "1.1 This policy migrated to github.com/cloudquery-policies/gcp"
      query = file("queries/manual.sql")
    }
}