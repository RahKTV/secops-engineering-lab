/*
===============================================================================
Security Telemetry & Anomaly Detection Queries
Author: Rahul Khurana
Description: Analytical SQL rules for detecting statistical data-access spikes
             and unauthorized Role-Based Access Control (RBAC) privilege drift.
===============================================================================
*/

-- ============================================================================
-- DETECTION 1: Statistical Anomaly in High-Volume Data Queries (Z-Score Method)
-- Identifies compromised credentials or insider threat exfiltration by flagging
-- users whose daily queried row volume exceeds 3 standard deviations above
-- their 30-day historical rolling baseline.
-- MITRE ATT&CK: T1530 (Data from Cloud Storage / Enterprise Repositories)
-- ============================================================================

WITH daily_user_telemetry AS (
    SELECT 
        user_id,
        department,
        DATE_TRUNC('day', event_timestamp) AS activity_date,
        COUNT(query_id) AS daily_query_count,
        SUM(rows_exported) AS total_rows_accessed
    FROM enterprise_telemetry.query_audit_logs
    WHERE event_timestamp >= CURRENT_DATE - INTERVAL '30 days'
    GROUP BY user_id, department, DATE_TRUNC('day', event_timestamp)
),
user_historical_baseline AS (
    SELECT 
        user_id,
        department,
        activity_date,
        total_rows_accessed,
        AVG(total_rows_accessed) OVER (
            PARTITION BY user_id 
            ORDER BY activity_date 
            ROWS BETWEEN 29 PRECEDING AND 1 PRECEDING
        ) AS avg_30d_rows,
        STDDEV(total_rows_accessed) OVER (
            PARTITION BY user_id 
            ORDER BY activity_date 
            ROWS BETWEEN 29 PRECEDING AND 1 PRECEDING
        ) AS stddev_30d_rows
    FROM daily_user_telemetry
)
SELECT 
    user_id,
    department,
    activity_date,
    total_rows_accessed,
    ROUND(avg_30d_rows, 2) AS baseline_avg_rows,
    ROUND((total_rows_accessed - avg_30d_rows) / NULLIF(stddev_30d_rows, 0), 2) AS z_score
FROM user_historical_baseline
WHERE activity_date = CURRENT_DATE
  AND total_rows_accessed > 10000
  AND ((total_rows_accessed - avg_30d_rows) / NULLIF(stddev_30d_rows, 0)) >= 3.0
ORDER BY z_score DESC;


-- ============================================================================
-- DETECTION 2: Active Directory / IAM Privilege Creep & Least-Privilege Audit
-- Detects accounts holding privileged RBAC roles that were granted outside of 
-- approved ServiceNow/Jira change tickets OR have remained dormant for >45 days.
-- MITRE ATT&CK: T1078 (Valid Accounts) / CIS Control 5 & 6
-- ============================================================================

SELECT 
    u.user_principal_name,
    u.department,
    r.role_name,
    r.privilege_tier,
    g.assigned_timestamp,
    g.assigned_by,
    g.change_ticket_id,
    u.last_login_timestamp,
    DATEDIFF('day', u.last_login_timestamp, CURRENT_TIMESTAMP) AS days_since_last_login,
    CASE 
        WHEN g.change_ticket_id IS NULL THEN 'UNAPPROVED_PRIVILEGE_ESCALATION'
        WHEN DATEDIFF('day', u.last_login_timestamp, CURRENT_TIMESTAMP) > 45 THEN 'DORMANT_PRIVILEGED_ACCOUNT'
        WHEN u.mfa_enabled = FALSE THEN 'MFA_BYPASS_ON_PRIVILEGED_ROLE'
    END AS violation_type
FROM iam_governance.users u
JOIN iam_governance.role_assignments g 
    ON u.user_id = g.user_id
JOIN iam_governance.roles r 
    ON g.role_id = r.role_id
WHERE r.privilege_tier IN ('TIER_0_DOMAIN_ADMIN', 'TIER_1_SERVER_ADMIN', 'FINANCE_ERP_ADMIN')
  AND (
      g.change_ticket_id IS NULL 
      OR DATEDIFF('day', u.last_login_timestamp, CURRENT_TIMESTAMP) > 45
      OR u.mfa_enabled = FALSE
  )
ORDER BY r.privilege_tier ASC, g.assigned_timestamp DESC;
