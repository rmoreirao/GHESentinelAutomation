# GHE → Sentinel Anomaly Detection — Solution Architecture

> **Status:** Deployed and operational
> **Incident Verified:** ✅ "GHE - Mass Clone Detection" triggered on 2026-03-24

---

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

---

## Components

### 1. GitHub Enterprise Audit Log Streaming

| Property | Value |
|----------|-------|
| Enterprise | `rmoreiraoghe4org` |
| Stream ID | 6283 |
| Stream Type | Azure Event Hubs |
| Status | ✅ Enabled |
| Events Streamed | All audit events (web + git) |

**How it works:** GitHub Enterprise Cloud continuously streams every audit event as a JSON message to the configured Event Hub. This includes `git.clone`, `git.push`, `repo.create`, `org.add_member`, `oauth_access.*`, `api.request`, and hundreds of other event types. The streaming is near-real-time (typically <60 seconds latency).

**Key learnings from deployment:**
- The REST API requires credentials encrypted with the enterprise's stream public key (`/audit-log/stream-key` endpoint) using libsodium sealed box encryption — plaintext credentials are rejected.
- The Event Hub namespace must have **local authentication (SAS) enabled** (`disableLocalAuth: false`). Standard-tier namespaces default to SAS disabled.

---

### 2. Azure Event Hubs

| Property | Value |
|----------|-------|
| Namespace | `evhns-ghec-audit-prod` |
| Event Hub | `ghec-audit-logs` |
| Partitions | 4 |
| Retention | 168 hours (7 days) |
| SKU | Standard (auto-inflate to 10 TU) |

**Authorization Rules:**

| Rule | Scope | Rights | Used By |
|------|-------|--------|---------|
| `ghec-audit-send` | Event Hub | Send | GitHub Enterprise (streaming) |
| `sentinel-listen` | Namespace | Listen | Azure Function (consumer) |
| `RootManageSharedAccessKey` | Namespace | Manage/Send/Listen | Admin operations |

**Consumer Groups:**

| Group | Purpose |
|-------|---------|
| `$Default` | Default (unused) |
| `sentinel-consumer` | Used by the `eventhub_ingest` Azure Function |

**How it works:** Event Hubs acts as a durable message buffer between GitHub and the ingestion function. Messages are partitioned across 4 partitions for parallel processing. The consumer group ensures the function tracks its own read position (offset) independently. If the function is down, messages are retained for up to 7 days and processed when the function recovers.

---

### 3. Azure Function App — Ingestion

| Property | Value |
|----------|-------|
| Name | `func-ghec-sentinel-response` |
| Runtime | Python 3.11, Functions v4 |
| Plan | Linux Consumption (serverless) |
| Managed Identity | `ea0e1aa5-1dae-473d-8fc9-bf8d615276fd` (system-assigned) |
| Host | `func-ghec-sentinel-response.azurewebsites.net` |

**Functions:**

| Function | Trigger | Purpose |
|----------|---------|---------|
| `eventhub_ingest` | Event Hub Trigger | **Core pipeline** — Consumes audit log events from Event Hub, transforms them, and ingests into Log Analytics via DCR |

> **Note:** Response actions (Teams notification, PAT revocation, incident enrichment) have been moved
> to dedicated Logic Apps (see Component 3b below). The Function App now handles ingestion only.

#### `eventhub_ingest` — The Core Pipeline Function

This is the critical function that bridges Event Hub → Log Analytics:

```
Event Hub Message (JSON)           GitHubAuditLog_CL Table Row
┌─────────────────────────┐        ┌──────────────────────────────┐
│ {                        │        │ TimeGenerated  = 2026-03-24  │
│   "action": "git.clone", │  ───▶  │ Action         = git.clone   │
│   "actor": "admin_rm4",  │  map   │ Actor          = admin_rm4   │
│   "repo": "org/repo",    │        │ Repository     = org/repo    │
│   "actor_ip": "1.2.3.4", │        │ ActorIP        = 1.2.3.4    │
│   "created_at": 17...    │        │ ActorCountry   = US          │
│   ...                    │        │ Organization   = org         │
│ }                        │        │ RawEvent       = {full json} │
└─────────────────────────┘        └──────────────────────────────┘
```

**Processing flow:**
1. Event Hub trigger fires with a **batch** of events (cardinality: many)
2. Each JSON event is parsed and mapped to the 19-column `GitHubAuditLog_CL` schema
3. Timestamps are converted from Unix milliseconds to ISO 8601
4. The function authenticates to Azure Monitor using its **Managed Identity** (no secrets!)
5. Events are uploaded via the `LogsIngestionClient` SDK → DCE → DCR → Log Analytics

**Key configuration:**

| Setting | Value | Purpose |
|---------|-------|---------|
| `EVENTHUB_CONNECTION` | Namespace listen connection string | Event Hub trigger binding |
| `DCE_ENDPOINT` | `https://dce-ghec-audit-....ingest.monitor.azure.com` | Logs Ingestion API endpoint |
| `DCR_IMMUTABLE_ID` | `dcr-4d574641707742f...` | Identifies which DCR to use |
| `AzureWebJobsFeatureFlags` | `EnableWorkerIndexing` | Required for Python v2 model |

**RBAC:** The function's managed identity has the **Monitoring Metrics Publisher** role on the DCR, which grants permission to upload logs via the Logs Ingestion API.

---

### 3b. Logic Apps — Automated Response

Response actions are handled by 3 dedicated Logic Apps, each with a native **Microsoft Sentinel incident trigger**. Sentinel automation rules invoke them automatically when incidents are created.

**API Connections (shared):**

| Connection | Auth Method | Used By |
|-----------|-------------|---------|
| `azuresentinel-connection` | Managed Identity | All 3 Logic Apps (Sentinel trigger + incident comments) |
| `teams-connection` | OAuth (portal-authorized) | `logic-ghec-teams-notify` |

#### `logic-ghec-teams-notify` — Teams Notification

```
Sentinel Incident ──▶ Automation Rule 1 ──▶ Logic App ──▶ Teams Channel
  (created)             (all incidents)       │              (Adaptive Card)
                                              └──▶ Add incident comment
                                                   "📢 Teams notification posted"
```

Uses the Sentinel incident trigger to receive the full incident payload, then posts an alert to a Teams channel via the `teams` API connection. After posting, adds a comment to the Sentinel incident confirming the notification was sent.

#### `logic-ghec-revoke-pat` — Automated PAT Revocation

```
Sentinel Incident ──▶ Automation Rule 3 ──▶ Logic App ──▶ GitHub API
  (High severity)       (High only)          │              GET  /enterprises/{slug}/personal-access-tokens?owner={actor}
                                             │              DELETE /enterprises/{slug}/personal-access-tokens/{id}
                                             └──▶ Add incident comment
                                                  "🔒 PAT revocation completed"
```

Triggered only for **High severity** incidents. Extracts `Account` entities from the incident, queries the GitHub Enterprise API for each user's active PATs, revokes them all via DELETE, and adds a summary comment to the incident.

**Configuration:** GitHub token (with `admin:enterprise` scope) and enterprise slug are stored as Logic App parameters (use Key Vault references for production).

#### `logic-ghec-enrich-incident` — Incident Enrichment

```
Sentinel Incident ──▶ Automation Rule 2 ──▶ Logic App ──▶ GitHub API
  (created)             (all incidents)       │              GET /users/{actor}
                                              └──▶ Add enrichment comment
                                                   "🔍 GitHub Profile: name, company, type, created_at"
```

Extracts `Account` entities from the incident, fetches each user's GitHub profile (name, company, account type, creation date, public repos), and adds a structured enrichment comment to the incident.

**RBAC for all Logic Apps:**

| Principal | Role | Scope |
|-----------|------|-------|
| Each Logic App's managed identity | Microsoft Sentinel Responder | Log Analytics workspace |
| Azure Security Insights SP | Microsoft Sentinel Automation Contributor | Each Logic App |
| Admin user/group | Logic App Contributor | Each Logic App |

---

### 4. Data Collection Endpoint (DCE) & Rule (DCR)

| Component | Name | Purpose |
|-----------|------|---------|
| DCE | `dce-ghec-audit` | HTTPS endpoint that receives log ingestion API calls |
| DCR | `dcr-ghec-audit` | Defines the stream schema, transformation, and destination table |

**How they work together:**

```
Azure Function                          DCE                    DCR                 Log Analytics
     │                                  │                      │                       │
     │  POST /dataCollectionRules/      │                      │                       │
     │  {dcrImmutableId}/streams/       │                      │                       │
     │  Custom-GitHubAuditLog_CL        │                      │                       │
     │ ─────────────────────────────▶   │                      │                       │
     │                                  │  Route to DCR        │                       │
     │                                  │ ──────────────────▶  │                       │
     │                                  │                      │  transformKql:        │
     │                                  │                      │  "source" (passthru)  │
     │                                  │                      │ ─────────────────────▶│
     │                                  │                      │                       │  Write to
     │                                  │                      │                       │  GitHubAuditLog_CL
```

The DCR's `streamDeclarations` defines the expected column schema (matching the 19 columns of `GitHubAuditLog_CL`). The `transformKql` is set to `"source"` (passthrough — no transformation). The `dataFlows` routes `Custom-GitHubAuditLog_CL` stream to the `law-ghec-dest` destination.

---

### 5. Log Analytics Workspace & Custom Table

| Property | Value |
|----------|-------|
| Workspace | `law-ghec-sentinel-prod` |
| Table | `GitHubAuditLog_CL` |
| Plan | Analytics (supports KQL queries from Sentinel) |
| Retention | 365 days |
| Columns | 19 |

**Table Schema:**

| Column | Type | Source Field |
|--------|------|-------------|
| `TimeGenerated` | datetime | `created_at` / `@timestamp` (converted from Unix ms) |
| `Action` | string | `action` (e.g., `git.clone`, `repo.create`) |
| `Actor` | string | `actor` (GitHub username) |
| `ActorIP` | string | `actor_ip` or `actor_location.ip` |
| `ActorCountry` | string | `actor_location.country_code` |
| `Organization` | string | `org` |
| `Repository` | string | `repo` (format: `org/repo`) |
| `TargetUser` | string | `user` (affected user) |
| `Team` | string | `team` |
| `Visibility` | string | `visibility` (public/private/internal) |
| `Permission` | string | `permission` |
| `TransportProtocol` | string | `transport_protocol_name` (http/ssh) |
| `OperationType` | string | `operation_type` (read/write/admin) |
| `AccessType` | string | `programmatic_access_type` (PAT/OAuth/etc.) |
| `TokenScopes` | string | `token_scopes` |
| `UserAgent` | string | `user_agent` |
| `ExternalIdentity` | string | `external_identity_nameid` (SSO identity) |
| `EventData` | string | Remaining fields as JSON |
| `RawEvent` | string | Complete original event as JSON |

**Current data:** 306 events ingested, 7 unique action types, 2 unique actors.

---

### 6. Microsoft Sentinel — Analytics Rules

Sentinel sits on top of the Log Analytics workspace and runs scheduled KQL queries against the `GitHubAuditLog_CL` table.

**How a Scheduled Analytics Rule works:**

```
Every [queryFrequency]:
  1. Sentinel executes the KQL query against [queryPeriod] of data
  2. If results > [triggerThreshold] → Create Incident
  3. Entity mappings extract Actor/IP from results for investigation
  4. Incident grouping merges related alerts (same actor within 24h)
  5. Automation rules fire on incident creation
```

**Deployed Rules:**

| Rule | Severity | Frequency | Lookback | What It Detects |
|------|----------|-----------|----------|-----------------|
| Mass Clone Detection | High | 30 min | 1 hr | Actor clones >10 unique repos in 1 hour |
| Mass Artifact Download | High | 30 min | 1 hr | Actor downloads >20 workflow artifacts in 1 hour |
| Unusual Clone Hours | High | 1 hr | 24 hr | Human accounts cloning repos between 00:00–05:00 UTC |
| New IP for Known User | High | 30 min | 1 hr | Known user clones from never-before-seen IP (14-day baseline) |
| Geo-Impossible Travel | High | 30 min | 2 hr | Same actor clones from IPs >500 miles apart within 1 hour |
| API Rate Limit Approach | Medium | 15 min | 1 hr | Actor makes >4,000 API requests in 1 hour |
| Bulk Repo Enumeration | High | 10 min | 15 min | >50 repo-listing API calls in 10 minutes |
| Service Account Anomalies | Medium | 30 min | 1 hr | Service account activity >3 standard deviations from 7-day baseline |

**Example — Mass Clone Detection KQL:**

```kql
let Threshold = 10;
let TimeWindow = 1h;
GitHubAuditLog_CL
| where TimeGenerated >= ago(TimeWindow)
| where Action == "git.clone"
| where isnotempty(Actor)
| summarize
    CloneCount = dcount(Repository),
    ClonedRepos = make_set(Repository, 50),
    IPs = make_set(ActorIP),
    FirstClone = min(TimeGenerated),
    LastClone = max(TimeGenerated)
    by Actor, bin(TimeGenerated, TimeWindow)
| where CloneCount > Threshold
| project TimeGenerated, Actor, CloneCount, ClonedRepos, IPs, FirstClone, LastClone
```

This query aggregates `git.clone` events by actor over a 1-hour window, counts unique repositories cloned, and fires when any actor exceeds 10.

---

### 7. Sentinel Automation Rules

| # | Rule | Trigger | Condition | Actions |
|---|------|---------|-----------|---------|
| 1 | GHE - Notify Teams + Set Active | Incident Created | All incidents | Set status → Active; Run `logic-ghec-teams-notify` |
| 2 | GHE - Enrich All Incidents | Incident Created | All incidents | Run `logic-ghec-enrich-incident` |
| 3 | GHE - Revoke PATs (High Severity) | Incident Created | Severity = High | Run `logic-ghec-revoke-pat` |

**How Sentinel → Logic Apps integration works:**

Sentinel automation rules invoke Logic Apps as **playbook actions** via the `RunPlaybook` action type. The flow is:

```
1. Analytics rule KQL query returns results
2. Sentinel creates an Incident
3. All 3 automation rules evaluate against the new incident:
   a. Rule 1 (all incidents): Sets status to "Active" + triggers logic-ghec-teams-notify
   b. Rule 2 (all incidents): Triggers logic-ghec-enrich-incident
   c. Rule 3 (High only):    Triggers logic-ghec-revoke-pat
4. Each Logic App's Sentinel trigger receives the full incident object
5. Logic App executes its workflow (Teams post / GitHub API / enrichment)
6. Logic App adds a comment back to the Sentinel incident via the azuresentinel connector
```

> **RBAC prerequisite:** The "Azure Security Insights" service principal (app ID `98785600-1bb7-4fb9-b9fa-19afe2c8a360`) must have the **Microsoft Sentinel Automation Contributor** role on each Logic App. Each Logic App's managed identity must have **Microsoft Sentinel Responder** on the workspace. Without these, the automation rules cannot trigger the Logic Apps.

---

### 8. Archive Storage

| Property | Value |
|----------|-------|
| Account | `stghecauditarchive` |
| Container | `ghec-audit-archive` |
| SKU | Standard GRS (geo-redundant) |
| Immutability | 2,556 days (7 years) — WORM policy |
| Purpose | Long-term audit log retention for SOX/PCI-DSS compliance |

---

## Resource Inventory

| # | Resource | Type | Role in Pipeline |
|---|----------|------|-----------------|
| 1 | `evhns-ghec-audit-prod` | Event Hub Namespace | Message buffer between GHE and ingestion |
| 2 | `ghec-audit-logs` | Event Hub | Receives streamed audit events |
| 3 | `func-ghec-sentinel-response` | Function App | Ingests events (eventhub_ingest only) |
| 4 | `stfuncghecsentinel` | Storage Account | Function App internal storage |
| 5 | `EastUS2LinuxDynamicPlan` | App Service Plan | Consumption plan for Function App |
| 6 | `dce-ghec-audit` | Data Collection Endpoint | HTTPS ingestion endpoint |
| 7 | `dcr-ghec-audit` | Data Collection Rule | Schema + routing to LAW table |
| 8 | `law-ghec-sentinel-prod` | Log Analytics Workspace | Stores `GitHubAuditLog_CL` table |
| 9 | `SecurityInsights(...)` | Sentinel Solution | Analytics rules + automation |
| 10 | `stghecauditarchive` | Storage Account | 7-year compliance archive |
| 11 | `func-ghec-sentinel-response` | Application Insights | Function monitoring & diagnostics |
| 12 | `logic-ghec-teams-notify` | Logic App | Sentinel → Teams notification + incident comment |
| 13 | `logic-ghec-revoke-pat` | Logic App | Sentinel → PAT revocation via GitHub API |
| 14 | `logic-ghec-enrich-incident` | Logic App | Sentinel → GitHub profile enrichment comment |
| 15 | `azuresentinel-connection` | API Connection | Managed Identity auth for Sentinel connector |
| 16 | `teams-connection` | API Connection | OAuth auth for Teams connector |

---

## Data Flow Timing

| Stage | Typical Latency | Notes |
|-------|-----------------|-------|
| GHE event → Event Hub | < 60 seconds | GitHub streams in near-real-time |
| Event Hub → Function trigger | < 30 seconds | Consumption plan cold start may add 30-60s |
| Function → Log Analytics | < 30 seconds | Logs Ingestion API + internal processing |
| Log Analytics → Sentinel query | Per rule schedule | 10 min (fastest) to 1 hr (slowest) |
| **End-to-end: Event → Incident** | **2–90 minutes** | Depends on rule frequency |

---

## Security Model

| Component | Authentication | Authorization |
|-----------|---------------|---------------|
| GHE → Event Hub | SAS Key (encrypted, Send-only) | Event Hub auth rule: Send |
| Function → Event Hub | SAS Key (Listen-only) | Namespace auth rule: Listen |
| Function → Log Analytics | **Managed Identity** (no secrets) | RBAC: Monitoring Metrics Publisher on DCR |
| Logic Apps → Sentinel | **Managed Identity** (azuresentinel connector) | RBAC: Microsoft Sentinel Responder on workspace |
| Logic App → Teams | OAuth (teams connector, portal-authorized) | Delegated permission to post messages |
| Logic Apps → GitHub API | GitHub token (Logic App parameter) | `admin:enterprise` scope |
| Sentinel → Logic Apps | Azure Security Insights SP | RBAC: Sentinel Automation Contributor on each Logic App |

---

## Verified Incident

The pipeline has been validated end-to-end with a real incident:

```
🚨 Incident: GHE - Mass Clone Detection
   Severity: High
   Status:   Active
   Created:  2026-03-24T13:33:23Z
   
   Trigger:  22 git.clone events from actor "admin_rm4"
             across 13 unique repositories within 1 hour
             (threshold: >10)
```

---

*Solution deployed: 2026-03-24 | Resource Group: rg-ghec-sentinel-prod | Region: East US 2*
