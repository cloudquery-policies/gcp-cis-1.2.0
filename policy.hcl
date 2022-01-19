policy "cis-v1.30" {
  description = "GCP CIS V1.30 Policy"
  configuration {
    provider "gcp" {
      version = ">= 0.4.0"
    }
  }

  policy "deprecation-notice" {
    description = "deprecation notice"

    query "1" {
      description = "deprecation notice"
      query = "select 'The GCP-CIS-1.3.0 policy is deprecated. please use the gcp pack instead: https://github.com/cloudquery-policies/gcp, or run cloudquery policy run gcp//cis_v1.2.0' as notice;"
    }
  }
}