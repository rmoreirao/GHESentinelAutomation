# GHESentinelAutomation

## Sample Anomaly Detection Rules

Implement the following detection rules in your SIEM or monitoring platform:

| Rule | Logic | Threshold (Suggested) | Severity |
|---|---|---|---|
| **Mass clone detection** | Count of `git.clone` events per actor per hour | > 10 repos/hour | Critical |
| **Mass artifact download** | Count of `actions.download_artifact` events per actor per hour | > 20 artifacts/hour | Critical |
| **Unusual clone hours** | `git.clone` events outside business hours from non-CI/CD actors | Any activity 00:00–05:00 local time from human accounts | High |
| **New IP address for known user** | `git.clone` from an IP not previously associated with the actor | First-time IP + high-volume activity | High |
| **Geo-impossible travel** | `git.clone` events from geographically distant IPs within a short time window | > 500 miles apart within 1 hour | Critical |
| **API rate limit approach** | Actor approaching GitHub API rate limits (5,000 requests/hour for authenticated users) | > 4,000 requests/hour | Medium |
| **Bulk repository enumeration** | High volume of `GET /orgs/{org}/repos` API calls | > 50 paginated requests in 10 minutes | High |
| **Service account anomalies** | Service account PAT used for actions outside its normal pattern | Any deviation from baseline | Medium |

## How It Works — End-to-End Flow

```
┌─────────────────────┐
│  GitHub Enterprise   │  Every audit event (clone, push, login, API call,
│  Cloud (GHEC)        │  admin action, etc.) generates an audit log entry.
│                      │
│  Enterprise:         │  Streaming is configured via the REST API with
│  rmoreiraoghe4org    │  encrypted credentials (libsodium sealed box).
└────────┬────────────┘
         │ Audit Log Streaming (real-time, JSON)
         │ Stream ID: 6283
         ▼
┌─────────────────────┐
│  Azure Event Hubs    │  Acts as a high-throughput message buffer.
│                      │  GitHub pushes events here continuously.
│  Namespace:          │
│  evhns-ghec-audit-   │  • 4 partitions for parallel processing
│  prod                │  • 168-hour (7-day) message retention
│                      │  • SAS auth (Send rule for GHE, Listen for Function)
│  Hub: ghec-audit-    │  • Consumer group: sentinel-consumer
│  logs                │
└────────┬────────────┘
         │ Event Hub Trigger (automatic, batch processing)
         ▼
┌─────────────────────┐
│  Azure Function      │  eventhub_ingest function consumes events in batches.
│  (Event Hub Trigger) │
│                      │  1. Deserializes JSON from Event Hub
│  func-ghec-sentinel- │  2. Maps GHE fields → GitHubAuditLog_CL schema
│  response            │  3. Authenticates via Managed Identity
│                      │  4. Uploads to Log Analytics via DCR/DCE
│  Runtime: Python 3.11│     (azure-monitor-ingestion SDK)
│  Plan: Consumption   │
└────────┬────────────┘
         │ Logs Ingestion API (HTTPS, Entra ID auth)
         ▼
┌─────────────────────┐
│  Data Collection     │  DCE: Receives the HTTPS ingestion request
│  Endpoint (DCE) +    │  DCR: Routes data to the correct table with
│  Data Collection     │       optional KQL transformation
│  Rule (DCR)          │
│                      │  Stream: Custom-GitHubAuditLog_CL
│  dce-ghec-audit      │  Destination: law-ghec-sentinel-prod
│  dcr-ghec-audit      │
└────────┬────────────┘
         │ Internal Azure Monitor pipeline
         ▼
┌─────────────────────┐
│  Log Analytics       │  Custom table: GitHubAuditLog_CL
│  Workspace           │  19 columns, 365-day retention, Analytics plan
│                      │
│  law-ghec-sentinel-  │  Sentinel queries this table on schedule using
│  prod                │  the 8 analytics rules' KQL queries.
└────────┬────────────┘
         │ Scheduled KQL queries (every 10min–1hr)
         ▼
┌─────────────────────┐
│  Microsoft Sentinel  │  8 analytics rules run on schedule.
│  Analytics Rules     │  When a query returns results → Incident created.
│                      │
│  Example: Mass Clone │  3 automation rules fire on incident creation
│  Detection runs      │  and invoke Logic Apps for response.
│  every 30 min,       │
│  queries last 1 hr   │  Incidents appear in Sentinel's incident queue
│  of data             │  for SecOps triage.
└────────┬────────────┘
         │ 3 Sentinel Automation Rules (on incident creation)
         ▼
┌─────────────────────┐
│  Logic Apps          │  Sentinel-triggered response playbooks:
│  (Automated Response)│
│                      │  • logic-ghec-teams-notify
│  API Connections:    │      → Posts alert to Teams channel + adds comment
│  • azuresentinel     │  • logic-ghec-revoke-pat
│    (Managed Identity)│      → Revokes compromised PATs via GitHub API
│  • teams             │  • logic-ghec-enrich-incident
│    (OAuth)           │      → Adds GitHub user profile to incident
│                      │
│                      │  Triggered automatically by Sentinel automation
│                      │  rules. Each uses a native Sentinel trigger.
└─────────────────────┘
```

## Sentinel

#### Microsoft Defender Portal

https://security.microsoft.com/sentinel/

#### Configured Detection Rules

Microsoft Sentinel → Configuration → Detection rules

#### Automation (Logic Apps)

Microsoft Sentinel → Configuration → Automation -> Standard Rules

#### Check Alerts Triggered

Investigation & response → Incidents & Alerts → Incidents → [Filter by rule name]