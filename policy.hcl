policy "cis-v1.30" {
  description = "GCP CIS V1.30 Policy"
  configuration {
    provider "gcp" {
      version = ">= 0.4.0"
    }
  }

  policy "gcp-cis-section-1" {
    description = "GCP CIS Section 1"

    view "gcp_project_policy_members" {
      description = "GCP project policy members"
      query "gcp_project_policy_members_query" {
        query = file("queries/project-policy-members.sql")
      }
    }

    query "1.1" {
      description = "GCP CIS 1.1 Ensure that corporate login credentials are used (Automated)"
      query = <<EOF
      SELECT 'needs to list folders and organizations which is currently not supported'
    EOF
    }

    query "1.2" {
      description = "GCP CIS 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.3" {
      description = "GCP CIS 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.4" {
      description = "GCP CIS 1.4 Ensure that there are only GCP-managed service account keys for each service account (Automated)"
      query = <<EOF
      SELECT project_id , gisa."name" AS "account_name", gisak.name AS "key_name", gisak."key_type"
      FROM gcp_iam_service_accounts gisa
      JOIN gcp_iam_service_account_keys gisak ON
      gisa.cq_id = gisak.service_account_cq_id
      WHERE gisa.email LIKE '%iam.gserviceaccount.com'
      AND gisak."key_type" = 'USER_MANAGED';
    EOF
    }

    query "1.5" {
      description = "GCP CIS 1.5 Ensure that Service Account has no Admin privileges (Automated)"
      query = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE ("role" IN ( 'roles/editor', 'roles/owner')
          OR "role" LIKE ANY (ARRAY['%Admin', '%admin']))
      AND "member" LIKE 'serviceAccount:%';
    EOF
    }

    query "1.6" {
      description = "GCP CIS 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level (Automated)"
      query = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE "role" IN ( 'roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator')
      AND "member" LIKE 'user:%';
    EOF
    }

    query "1.7" {
      description = "GCP CIS 1.7 Ensure user-managed/external keys for service accounts are rotated every 90 days or less (Automated)"
      query = <<EOF
      SELECT project_id , gisa.id AS "account_id", gisak.name AS "key_name", gisak.valid_after_time
      FROM gcp_iam_service_accounts gisa
      JOIN gcp_iam_service_account_keys gisak ON
      gisa.cq_id = gisak.service_account_cq_id
      WHERE gisa.email LIKE '%iam.gserviceaccount.com'
      AND gisak.valid_after_time <= (now() - interval '90' day)
    EOF
    }

    query "1.8" {
      description = "GCP CIS 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users (Manual)"
      query = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE "role" IN ( 'roles/iam.serviceAccountAdmin', 'roles/iam.serviceAccountUser')
      AND "member" LIKE 'user:%';
    EOF
    }

    query "1.9" {
      description = "GCP CIS 1.9 Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible (Automated)"
      query = <<EOF
        SELECT project_id , "role", "member"
        FROM gcp_project_policy_members
        WHERE "member" LIKE '%allUsers%'
        OR "member" LIKE '%allAuthenticatedUsers%';
    EOF
    }

    query "1.10" {
      description = "GCP CIS 1.10 Ensure KMS encryption keys are rotated within a period of 90 days (Automated)"
      query = <<EOF
        SELECT *
        FROM gcp_kms_keyring_crypto_keys gkkck
        WHERE (rotation_period LIKE '%s'
            AND REPLACE(rotation_period, 's', '')::NUMERIC > 7776000)
        OR (rotation_period LIKE '%h'
            AND REPLACE(rotation_period, 'h', '')::NUMERIC > 2160)
        OR (rotation_period LIKE '%m'
            AND REPLACE(rotation_period, 'm', '')::NUMERIC > 129600)
        OR (rotation_period LIKE '%d'
            AND REPLACE(rotation_period, 'd', '')::NUMERIC > 90)
        OR DATE_PART('day', CURRENT_DATE - next_rotation_time ) > 90 ;
    EOF
    }

    query "1.11" {
      description = "GCP CIS 1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users (Automated)"
      query = <<EOF
        SELECT project_id , "role", "member"
        FROM gcp_project_policy_members
        WHERE "role" = 'cloudkms.admin'
        AND "member" LIKE 'user:%';
    EOF
    }

    query "1.12" {
      description = "GCP CIS 1.12 Ensure API keys are not created for a project (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.13" {
      description = "GCP CIS 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.14" {
      description = "GCP CIS 1.14 Ensure API keys are restricted to only APIs that application needs access (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.15" {
      description = "GCP CIS 1.15 Ensure API keys are rotated every 90 days (Manual)"
      query = file("queries/manual.sql")
    }
  }

  policy "gcp-cis-section-2" {
    description = "GCP CIS Section 2"

    view "gcp_log_metric_filters" {
      description = "GCP Log Metric Filter and Alarm"
      query "gcp_log_metric_filters_query" {
        query = file("queries/log-metric-filters.sql")
      }
    }

    query "2.1" {
      description = "GCP CIS 2.1 Ensure that Cloud Audit Logging is configured properly across all services and all users from a project (Automated)"
      query = <<EOF
        WITH project_policy_audit_configs AS ( SELECT project_id, jsonb_array_elements(p.policy -> 'auditConfigs') AS audit_config
        FROM gcp_resource_manager_projects p ), log_types AS (SELECT project_id, audit_config ->> 'service' AS "service", jsonb_array_elements(audit_config -> 'auditLogConfigs') ->> 'logType' AS logs, jsonb_array_elements(audit_config -> 'auditLogConfigs') ->> 'exemptedMembers' AS exempted
        FROM project_policy_audit_configs) SELECT project_id, service , count(*)
        FROM log_types
        WHERE exempted IS NULL
        AND logs IN ('DATA_READ', 'DATA_WRITE')
        AND service = 'allServices'
        GROUP BY project_id, service
        --count(*) > 2 means DATA_READ and DATA_WRITE are there
        HAVING count(*) = 2;
    EOF
    }

    query "2.2" {
      description = "GCP CIS 2.2 Ensure that sinks are configured for all log entries (Automated)"
      query = <<EOF
        WITH found_sinks AS (SELECT count(*) AS configured_sinks
        FROM gcp_logging_sinks gls
        WHERE gls.FILTER = '') SELECT 'no sinks for all log entries configured' AS description
        FROM found_sinks
        WHERE configured_sinks = 0;
    EOF
    }

    query "2.3" {
      description = "GCP CIS 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock (Automated)"
      query = <<EOF
        SELECT gls.project_id, gls.name AS "sink_name", gsb.name AS "bucket_name", gsb.retention_policy_is_locked, gsb.retention_policy_retention_period, gls.destination
        FROM gcp_logging_sinks gls
        JOIN gcp_storage_buckets gsb ON
        gsb.name = REPLACE (gls.destination, 'storage.googleapis.com/', '')
        WHERE gls.destination LIKE 'storage.googleapis.com/%'
        AND ( gsb.retention_policy_is_locked = FALSE
	      OR gsb.retention_policy_retention_period = 0)
    EOF
    }

    query "2.4" {
      description = "GCP CIS 2.4 Ensure log metric filter and alerts exist for project ownership assignments/changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*(\s*protoPayload.serviceName\s*=\s*"cloudresourcemanager.googleapis.com"\s*)\s*AND\s*(\s*ProjectOwnership\s*OR\s*projectOwnerInvitee\s*)\s*OR\s*(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"REMOVE"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*)\s*OR\s*(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"ADD"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*)\s*';
    EOF
    }

    query "2.5" {
      description = "GCP CIS 2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*protoPayload.methodName\s*=\s*"SetIamPolicy"\s*AND\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:*\s*';
    EOF
    }

    query "2.6" {
      description = "GCP CIS 2.6 Ensure that the log metric filter and alerts exist for Custom Role changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*"iam_role"\s*AND\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.CreateRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.DeleteRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.UpdateRole"\s*';
    EOF
    }

    query "2.7" {
      description = "GCP CIS 2.7 Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes (Automated)"
      expect_output = true
      query = <<EOF
          SELECT * FROM gcp_log_metric_filters WHERE
          enabled = TRUE
          AND "filter" ~ '\s*resource.type\s*=\s*"gce_firewall_rule"\s*AND\s*protoPayload.methodName\s*=\s*"v1.compute.firewalls.patch"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.firewalls.insert"\s*';
    EOF
    }

    query "2.8" {
      description = "GCP CIS 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*"gce_route"\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.routes.patch"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.routes.insert"\s*';
    EOF
    }

    query "2.9" {
      description = "GCP CIS 2.9 Ensure that the log metric filter and alerts exist for VPC network changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*gce_network\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.networks.insert"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.networks.patch"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.delete"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.removePeering"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.addPeering"\s*';
    EOF
    }

    query "2.10" {
      description = "GCP CIS 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*gcs_bucket\s*AND\s*protoPayload.methodName\s*=\s*"storage.setIamPermissions"\s*';
    EOF
    }

    query "2.11" {
      description = "GCP CIS 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes (Automated)"
      expect_output = true
      query = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" = 'protoPayload.methodName="cloudsql.instances.update"';
    EOF
    }

    query "2.12" {
      description = "GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks (Automated)"
      query = <<EOF
        SELECT gcn.id, gcn.project_id , gcn.name AS network_name, gcn.self_link as network_link, gdp.name AS policy_network_name
        FROM gcp_compute_networks gcn
        JOIN gcp_dns_policy_networks gdpn ON
        gcn.self_link = REPLACE(gdpn.network_url, 'compute.googleapis', 'www.googleapis')
        JOIN gcp_dns_policies gdp ON
        gdp.id = gdpn.policy_id
        WHERE gdp.enable_logging = FALSE;
    EOF
    }
  }

  policy "gcp-cis-section-3" {
    description = "GCP CIS Section 3"

    view "gcp_firewall_allowed_rules" {
      description = "firewall allowed rules port ranges dissasembled"
      query "gcp_firewall_allowed_rules" {
        query = file("queries/firewall-allowed-view.sql")
      }
    }

    query "3.1" {
      description = "GCP CIS 3.1 Ensure that the default network does not exist in a project (Automated)"
      query = <<EOF
        SELECT project_id, id, "name", self_link as link
        FROM gcp_compute_networks gcn
        WHERE name = 'default';
    EOF
    }

    query "3.2" {
      description = "GCP CIS 3.2 Ensure legacy networks do not exist for a project (Automated)"
      query = <<EOF
        SELECT gdmz.project_id, gdmz.id, gdmz.name, gdmz.dns_name 
        FROM gcp_dns_managed_zones gdmz
        WHERE gdmz.dnssec_config_state != 'on'
    EOF
    }

    query "3.3" {
      description = "GCP CIS 3.3 Ensure that DNSSEC is enabled for Cloud DNS (Automated)"
      query = <<EOF
        SELECT project_id, id, "name", self_link as link
        FROM gcp_compute_networks gcn
        WHERE ip_v4_range IS NULL
    EOF
    }

    query "3.4" {
      description = "GCP CIS 3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC (Manual)"
      query = <<EOF
        SELECT  gdmz.project_id, gdmz.id, gdmz.name, gdmz.dns_name , gdmzdcdks."key_type" , gdmzdcdks.algorithm
        FROM gcp_dns_managed_zones gdmz
        JOIN gcp_dns_managed_zone_dnssec_config_default_key_specs gdmzdcdks ON
        gdmz.id = gdmzdcdks.managed_zone_id
        WHERE gdmzdcdks."key_type" = 'keySigning'
        AND gdmzdcdks.algorithm = 'rsasha1';
    EOF
    }

    query "3.5" {
      description = "GCP CIS 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC (Manual)"
      query = <<EOF
        SELECT gdmz.id, gdmz.project_id, gdmz.dns_name , gdmzdcdks."key_type" , gdmzdcdks.algorithm
        FROM gcp_dns_managed_zones gdmz
        JOIN gcp_dns_managed_zone_dnssec_config_default_key_specs gdmzdcdks ON
        gdmz.id = gdmzdcdks.managed_zone_id
        WHERE gdmzdcdks."key_type" = 'zoneSigning'
        AND gdmzdcdks.algorithm = 'rsasha1'
    EOF
    }

    query "3.6" {
      description = "GCP CIS 3.6 Ensure that SSH access is restricted from the internet (Automated)"
      query = <<EOF
        SELECT *
        FROM gcp_firewall_allowed_rules
        WHERE direction = 'INGRESS'
        AND ( ip_protocol = 'tcp'
          OR ip_protocol = 'all' )
        AND '0.0.0.0/0' = ANY (source_ranges)
        AND (22 BETWEEN range_start AND range_end
          OR '22' = single_port
          OR CARDINALITY(ports) = 0
          OR ports IS NULL)
    EOF
    }

    query "3.7" {
      description = "GCP CIS 3.7 Ensure that RDP access is restricted from the Internet (Automated)"
      query = <<EOF
        SELECT *
        FROM gcp_firewall_allowed_rules
        WHERE direction = 'INGRESS'
        AND ( ip_protocol = 'tcp'
          OR ip_protocol = 'all' )
        AND '0.0.0.0/0' = ANY (source_ranges)
        AND (3986 BETWEEN range_start AND range_end
          OR '3986' = single_port
          OR CARDINALITY(ports) = 0
          OR ports IS NULL)
    EOF
    }

    query "3.8" {
      description = "GCP CIS 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network (Automated)"
      query = <<EOF
        SELECT gcn.id, gcn.project_id, gcn.self_link AS network, gcs.self_link AS subnetwork, gcs.enable_flow_logs
        FROM gcp_compute_networks gcn
        JOIN gcp_compute_subnetworks gcs ON
        gcn.self_link = gcs.network
        WHERE gcs.enable_flow_logs = FALSE;
    EOF
    }

    query "3.9" {
      description = "GCP CIS 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites (Manual)"
      query = <<EOF
        SELECT gctsp.id, gctsp.project_id, gctsp.name, gctsp.ssl_policy, 'wrong policy' AS reason
        FROM gcp_compute_target_https_proxies gctsp
        WHERE ssl_policy NOT LIKE 'https://www.googleapis.com/compute/v1/projects/%/global/sslPolicies/%'
        UNION ALL SELECT gctsp.id, gctsp.project_id, gctsp.name, gctsp.ssl_policy, 'insecure policy config' AS reason
        FROM gcp_compute_target_https_proxies gctsp
        JOIN gcp_compute_ssl_policies p ON
        gctsp.ssl_policy = p.self_link
        WHERE gctsp.ssl_policy LIKE 'https://www.googleapis.com/compute/v1/projects/%/global/sslPolicies/%'
        AND (p.min_tls_version != 'TLS_1_2' OR  p.min_tls_version != 'TLS_1_3')
        AND (
          (p.profile = 'MODERN' OR p.profile = 'RESTRICTED' )
          OR (p.profile = 'CUSTOM' AND ARRAY ['TLS_RSA_WITH_AES_128_GCM_SHA256' , 'TLS_RSA_WITH_AES_256_GCM_SHA384' , 'TLS_RSA_WITH_AES_128_CBC_SHA' , 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'] @> p.enabled_features )
        );
    EOF
    }

    query "3.10" {
      description = "GCP CIS3.10 Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses (Manual)"
      query = <<EOF
        SELECT gcf.project_id, gcf.id, gcf.name, gcf.self_link AS link, count(*) AS broken_rules
        FROM gcp_compute_firewalls gcf
        JOIN gcp_compute_firewall_allowed gcfa ON
        gcf.cq_id = gcfa.firewall_cq_id
        WHERE NOT ARRAY ['35.191.0.0/16', '130.211.0.0/22'] <@ gcf.source_ranges and  NOT (ip_protocol = 'tcp' and ports @> ARRAY ['80'])
        GROUP BY gcf.project_id, gcf.id
        HAVING count(*) > 0;
    EOF
    }
  }

  policy "gcp-cis-section-4" {
    description = "GCP CIS Section 4"

    query "4.1" {
      description = "GCP CIS 4.1 Ensure that instances are not configured to use the default service account (Automated)"
      query = <<EOF
        SELECT project_id , gci."name", gci.self_link as link
        FROM gcp_compute_instances gci
        JOIN gcp_compute_instance_service_accounts gcisa ON
        gci.id = gcisa.instance_id
        WHERE gci."name" NOT LIKE 'gke-'
        AND gcisa.email = (SELECT default_service_account
        FROM gcp_compute_projects
        WHERE project_id = gci.project_id);
    EOF
    }

    query "4.2" {
      description = "GCP CIS 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs (Automated)"
      query = <<EOF
        SELECT *
        FROM gcp_compute_instances gci
        JOIN gcp_compute_instance_service_accounts gcisa ON
        gci.id = gcisa.instance_id
        WHERE gcisa.email = (SELECT default_service_account
        FROM gcp_compute_projects
        WHERE project_id = gci.project_id)
        AND 'https://www.googleapis.com/auth/cloud-platform' = ANY (gcisa.scopes);
    EOF
    }

    query "4.3" {
      description = "GCP CIS 4.3 Ensure \"Block Project-wide SSH keys\" is enabled for VM instances (Automated)"
      query = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_instances
        WHERE metadata_items IS NULL OR metadata_items ->> 'block-project-ssh-keys' IS NULL
        OR metadata_items ->> 'block-project-ssh-keys' != 'true';
    EOF
    }

    query "4.4" {
      description = "GCP CIS 4.4 Ensure oslogin is enabled for a Project (Automated)"
      query = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_projects
        WHERE common_instance_metadata_items IS NULL 
        OR common_instance_metadata_items ->> 'enable-oslogin' IS NULL
        OR common_instance_metadata_items ->> 'enable-oslogin' != 'true';
    EOF
    }

    query "4.5" {
      description = "GCP CIS 4.5 Ensure 'Enable connecting to serial ports' is not enabled for VM Instance (Automated)"

      query = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_instances
        WHERE metadata_items IS NOT NULL AND 
        metadata_items ->> 'serial-port-enable' = 'true'
        OR metadata_items ->> 'serial-port-enable' = '1';
    EOF
    }

    query "4.6" {
      description = "GCP CIS 4.6 Ensure that IP forwarding is not enabled on Instances (Automated)"
      query = <<EOF
        SELECT project_id , "name", self_link as link
        FROM gcp_compute_instances 
        WHERE can_ip_forward = TRUE;
    EOF
    }

    query "4.7" {
      description = "GCP CIS 4.7 Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK) (Automated)"
      query = <<EOF
        SELECT project_id, id, name, self_link as link
        FROM gcp_compute_disks
        WHERE disk_encryption_key_sha256 IS NULL
        OR disk_encryption_key_sha256 = ''
        OR source_image_encryption_key_kms_key_name IS NULL
        OR source_image_encryption_key_kms_key_name = '';
    EOF
    }


    query "4.8" {
      description = "GCP CIS 4.8 Ensure Compute instances are launched with Shielded VM enabled (Automated)"
      query = <<EOF
        SELECT project_id , gci."name", gci.self_link as link
        FROM gcp_compute_instances gci
        WHERE shielded_instance_config_enable_integrity_monitoring = FALSE
        OR shielded_instance_config_enable_vtpm = FALSE;
    EOF
    }

    query "4.9" {
      description = "GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses (Automated)"
      query = <<EOF
        SELECT project_id , gci."id", gci.self_link AS link
        FROM gcp_compute_instances gci
        LEFT JOIN gcp_compute_instance_network_interfaces gcini ON
                gci.id = gcini.instance_id
        LEFT JOIN gcp_compute_instance_network_interface_access_configs gciniac ON
                gcini.cq_id = gciniac.instance_network_interface_cq_id
        WHERE gci."name" NOT LIKE 'gke-%'
        AND (gciniac.nat_ip IS NOT NULL
          OR gciniac.nat_ip != '')
        GROUP BY project_id , gci."id"
        HAVING count(gciniac.*) > 0;
    EOF
    }

    query "4.10" {
      description = "GCP CIS 4.10 Ensure that App Engine applications enforce HTTPS connections (Manual)"
      query = file("queries/manual.sql")
    }

    query "4.11" {
      description = "GCP CIS 4.11 Ensure that Compute instances have Confidential Computing enabled (Automated)"
      query = <<EOF
        SELECT project_id , "name", gci.self_link as link
        FROM gcp_compute_instances gci
        WHERE confidential_instance_config_enable_confidential_compute = FALSE;
    EOF
    }
  }

  policy "gcp-cis-section-5" {
    description = "GCP CIS Section 5"

    view "gcp_public_buckets_accesses" {
      description = "Aggregated buckets and their access params"
      query "gcp_public_buckets_accesses_query" {
        query = file("queries/public-buckets-check.sql")
      }
    }

    query "5.1" {
      description = "GCP CIS 5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible (Automated)"
      query = <<EOF
        SELECT project_id , "name", self_link as link from gcp_public_buckets_accesses
        WHERE member LIKE '%allUsers%'
        OR member LIKE '%allAuthenticatedUsers%'
        GROUP BY project_id , "name", self_link;
    EOF
    }

    query "5.2" {
      description = "GCP CIS 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled (Automated)"
      query = <<EOF
        SELECT project_id, name, self_link as link
        FROM gcp_storage_buckets
        WHERE iam_configuration_uniform_bucket_level_access_enabled = FALSE;
    EOF
    }
  }

  policy "gcp-cis-section-6" {
    description = "GCP CIS Section 6"

    query "6.1.1" {
      description = "GCP CIS 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges (Automated)"
      query = file("queries/manual.sql")
    }

    query "6.1.2" {
      description = "GCP CIS 6.1.2 Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'MYSQL%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'skip_show_database' != 'on'
            OR settings_database_flags ->> 'skip_show_database' IS NULL);
    EOF
    }

    query "6.1.3" {
      description = "GCP CIS 6.1.3 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'MYSQL%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'local_infile' != 'off'
            OR settings_database_flags ->> 'local_infile' IS NULL);
    EOF
    }

    query "6.2.1" {
      description = "GCP CIS 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_checkpoints' != 'on'
            OR settings_database_flags ->> 'log_checkpoints' IS NULL);
    EOF
    }

    query "6.2.2" {
      description = "GCP CIS 6.2.2 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter (Manual)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_error_verbosity' NOT IN('default', 'terse')
            OR settings_database_flags ->> 'log_error_verbosity' IS NULL);
    EOF
    }

    query "6.2.3" {
      description = "GCP CIS 6.2.3 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_connections' != 'on'
            OR settings_database_flags ->> 'log_connections' IS NULL);
    EOF
    }

    query "6.2.4" {
      description = "GCP CIS 6.2.4 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_disconnections' != 'on'
            OR settings_database_flags ->> 'log_disconnections' IS NULL);
    EOF
    }

    query "6.2.5" {
      description = "GCP CIS 6.2.5 Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Manual)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_duration' != 'on'
            OR settings_database_flags ->> 'log_duration' IS NULL);
    EOF
    }

    query "6.2.6" {
      description = "GCP CIS 6.2.6 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags IS NULL OR settings_database_flags ->> 'log_lock_waits' != 'on'
            OR settings_database_flags ->> 'log_lock_waits' IS NULL);
    EOF
    }

    query "6.2.7" {
      description = "GCP CIS 6.2.7 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately (Manual)"
      query = file("queries/manual.sql")
    }

    query "6.2.8" {
      description = "GCP CIS 6.2.8 Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_hostname' != 'on'
            OR settings_database_flags ->> 'log_hostname' IS NULL);
    EOF
    }

    query "6.2.9" {
      description = "GCP CIS 6.2.9 Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_parser_stats' != 'off'
            OR settings_database_flags ->> 'log_parser_stats' IS NULL);
    EOF
    }

    query "6.2.10" {
      description = "GCP CIS 6.2.10 Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_planner_stats' != 'off'
            OR settings_database_flags ->> 'log_planner_stats' IS NULL);
    EOF
    }

    query "6.2.11" {
      description = "GCP CIS 6.2.11 Ensure 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_executor_stats' != 'off'
            OR settings_database_flags ->> 'log_executor_stats' IS NULL);
    EOF
    }

    query "6.2.12" {
      description = "GCP CIS 6.2.12 Ensure 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_statement_stats' != 'off'
            OR settings_database_flags ->> 'log_statement_stats' IS NULL);
    EOF
    }

    query "6.2.13" {
      description = "GCP CIS 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately (Manual)"
      query = file("queries/manual.sql")
    }

    query "6.2.14" {
      description = "GCP CIS 6.2.14 Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_min_error_statement' NOT IN('error', 'log', 'fatal', 'panic')
            OR settings_database_flags ->> 'log_min_error_statement' IS NULL);
    EOF
    }

    query "6.2.15" {
      description = "GCP CIS 6.2.15 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on) (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_temp_files' != '0'
            OR settings_database_flags ->> 'log_temp_files' IS NULL);
    EOF
    }

    query "6.2.16" {
      description = "GCP CIS 6.2.16 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled) (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_min_duration_statement' != '-1'
            OR settings_database_flags ->> 'log_min_duration_statement' IS NULL);
    EOF
    }

    query "6.3.1" {
      description = "GCP CIS 6.3.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'external scripts enabled' != 'off'
            OR settings_database_flags ->> 'external scripts enabled' IS NULL);
    EOF
    }

    query "6.3.2" {
      description = "GCP CIS 6.3.2 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'cross db ownership chaining' != 'off'
            OR settings_database_flags ->> 'cross db ownership chaining' IS NULL);
    EOF
    }

    query "6.3.3" {
      description = "GCP CIS 6.3.3 Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_database_flags IS NULL 
        OR settings_database_flags ->> 'user connections' IS NULL;
    EOF
    }

    query "6.3.4" {
      description = "GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_database_flags IS NULL 
        OR settings_database_flags ->> 'user options' IS NOT NULL;
    EOF
    }

    query "6.3.5" {
      description = "GCP CIS 6.3.5 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'remote access' != 'off'
            OR settings_database_flags ->> 'remote access' IS NULL);
    EOF
    }

    query "6.3.6" {
      description = "GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> '3625' != 'off'
            OR settings_database_flags ->> '3625' IS NULL);
    EOF
    }

    query "6.3.7" {
      description = "GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'contained database authentication' != 'off'
            OR settings_database_flags ->> 'contained database authentication' IS NULL);
    EOF
    }

    query "6.4" {
      description = "GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_ip_configuration_require_ssl = FALSE;
    EOF
    }

    query "6.5" {
      description = "GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsisican.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        JOIN gcp_sql_instance_settings_ip_config_authorized_networks gsisican ON
        gsi.cq_id = gsisican.instance_cq_id
        WHERE database_version LIKE 'SQLSERVER%'
        AND gsisican.value = '0.0.0.0/0'
    EOF
    }

    query "6.6" {
      description = "GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs (Automated)"
      query = <<EOF
        SELECT gsi.project_id, gsi.name, gsiia."type", gsi.self_link as link
        FROM gcp_sql_instances gsi
        JOIN gcp_sql_instance_ip_addresses gsiia ON
        gsi.cq_id = gsiia.instance_cq_id
        WHERE database_version LIKE 'SQLSERVER%'
        AND gsiia.type = 'PRIMARY' OR backend_type != 'SECOND_GEN';
    EOF
    }

    query "6.7" {
      description = "GCP CIS 6.7 Ensure that Cloud SQL database instances are configured with automated backups (Automated)"
      query = <<EOF
        SELECT project_id, name, self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_backup_enabled = FALSE;
    EOF
    }
  }

  policy "gcp-cis-section-7" {
    description = "GCP CIS Section 7"

    query "7.1" {
      description = "GCP CIS 7.1 Ensure that BigQuery datasets are not anonymously or publicly accessible (Automated)"
      query = <<EOF
        SELECT d.project_id, d.id, d.friendly_name, d.self_link AS dataset_link, a.special_group AS "group" , a."role"
        FROM gcp_bigquery_datasets d
        JOIN gcp_bigquery_dataset_accesses a ON
                d.id = a.dataset_id
        WHERE a."role" = 'allUsers'
        OR a."role" = 'allAuthenticatedUsers';
    EOF
    }

    query "7.2" {
      description = "GCP CIS 7.2 Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK) (Automated)"
      query = <<EOF
        SELECT d.project_id, d.id, d.friendly_name, d.self_link as dataset_link, t.self_link as table_link
        FROM gcp_bigquery_datasets d
        JOIN gcp_bigquery_dataset_tables t ON
        d.id = t.dataset_id
        WHERE encryption_configuration_kms_key_name = '' OR  default_encryption_configuration_kms_key_name IS NULL;
    EOF
    }

    query "7.3" {
      description = "GCP CIS 7.3 Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets (Automated)"
      query = <<EOF
        SELECT project_id, id, friendly_name, self_link as link
        FROM gcp_bigquery_datasets
        WHERE default_encryption_configuration_kms_key_name = '' 
        OR  default_encryption_configuration_kms_key_name IS NULL;
    EOF
    }
  }
}