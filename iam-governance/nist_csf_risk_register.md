# 📋 Enterprise IAM & Infrastructure Risk Register (NIST CSF)

This document summarizes technical findings and remediation controls from an internal security assessment aligned with the **NIST Cybersecurity Framework (CSF) 2.0**, **CIS Critical Security Controls v8**, and **PCI DSS v4.0**.

## Executive Risk Matrix

| Finding ID | NIST CSF Function | Control Domain | Vulnerability / Gap Identified | Risk Rating | Technical Remediation Engineered |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **IAM-01** | `PR.AA` (Protect) | Active Directory & RBAC | Legacy user accounts retained elevated permissions following role transitions (Privilege Creep). | **HIGH** | Enforced strict Role-Based Access Control (RBAC) groups, automated 45-day dormancy audits via SQL, and revoked standing admin privileges. |
| **IAM-02** | `PR.AA` (Protect) | Multi-Factor Authentication | Service and administrative interfaces lacked hardware/TOTP MFA enforcement on remote sessions. | **CRITICAL** | Mandated MFA across all user tiers and disabled password-based SSH authentication in favor of Ed25519 cryptographic keys. |
| **NET-01** | `DE.CM` (Detect) | Perimeter & Host Telemetry | Unmonitored east-west traffic between virtualized Linux nodes and Network-Attached Storage (NAS). | **MEDIUM** | Configured Fortinet firewall VLAN segmentation rules, disabled legacy port-forwarding, and deployed automated Python `auth.log` anomaly parsing. |
| **DAT-01** | `PR.DS` (Protect) | Data-at-Rest & Transit | Unencrypted legacy storage volumes and cleartext internal service traffic. | **HIGH** | Enforced TLS 1.3 across self-hosted web services and migrated storage volumes to encrypted filesystems aligned with GDPR/PCI DSS standards. |
