SELECT gmap.project_id, gmap.enabled, glm."filter"
FROM gcp_monitoring_alert_policies gmap
         JOIN gcp_monitoring_alert_policy_conditions gmapc ON
    gmap.cq_id = gmapc.alert_policy_cq_id
         JOIN gcp_logging_metrics glm ON
        gmapc.threshold_filter LIKE '%metric.type="' || glm.metric_descriptor_type || '"%'