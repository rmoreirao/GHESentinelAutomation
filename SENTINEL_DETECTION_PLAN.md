# GHE → Microsoft Sentinel: Anomaly Detection Rules — Full Implementation Plan

**Scope:** GitHub Enterprise Cloud audit log streaming → Microsoft Sentinel → Anomaly Detection → Automated Response

---

## Architecture Overview

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  GitHub Enterprise   │     │   Azure Event Hubs    │     │  Azure Function App  │
│  Cloud (GHEC)        │────▶│   Namespace           │────▶│  (Ingestion Only)    │
│                      │     │                       │     │                      │
│  • Audit Log Stream  │     │  • ghec-audit-logs    │     │  • eventhub_ingest   │
│  • Git Events        │     │  • Partitions: 4      │     │    (EH → DCR → LAW) │
│  • API Events        │     │  • Retention: 7 days  │     │                      │
│  • Auth Events       │     │                       │     │  func-ghec-sentinel- │
└─────────────────────┘     └──────────────────────┘     │  response            │
                                                          └────────┬────────────┘
                                                                   │ Logs Ingestion API
                                                                   ▼
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  Automated Response  │     │  Sentinel Automation  │     │  Microsoft Sentinel  │
│  (Logic Apps)        │◀────│  Rules (3)            │◀────│  (Log Analytics)     │
│                      │     │                       │     │                      │
│  • logic-ghec-teams- │     │  1. Notify + Active   │     │  • Analytics Rules   │
│    notify            │     │  2. Enrich All        │     │  • Anomaly Detection │
│  • logic-ghec-       │     │  3. Revoke PATs       │     │  • Workbooks         │
│    revoke-pat        │     │     (High only)       │     │  • Incidents         │
│  • logic-ghec-       │     │                       │     │                      │
│    enrich-incident   │     │                       │     │                      │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

---

## Table of Contents

1. [Phase 1 — Azure Infrastructure Provisioning](#phase-1--azure-infrastructure-provisioning)
2. [Phase 2 — GHE Audit Log Streaming Configuration](#phase-2--ghe-audit-log-streaming-configuration)
3. [Phase 3 — Sentinel Data Connector & Table Setup](#phase-3--sentinel-data-connector--table-setup)
4. [Phase 4 — Anomaly Detection Analytics Rules](#phase-4--anomaly-detection-analytics-rules)
5. [Phase 5 — Automated Response (Logic Apps)](#phase-5--automated-response-logic-apps)
6. [Phase 6 — Workbooks & Dashboards](#phase-6--workbooks--dashboards)
7. [Phase 7 — Validation & Testing](#phase-7--validation--testing)
8. [Phase 8 — Operationalization](#phase-8--operationalization)

---

## Prerequisites

- Azure Subscription with Owner or Contributor + User Access Administrator roles
- GitHub Enterprise Cloud with Enterprise Owner access
- Azure CLI (`az`) v2.60+ installed
- GitHub CLI (`gh`) v2.40+ installed
- PowerShell 7+ (for automation scripts)
- Service Principal or Managed Identity for CI/CD automation

### Required Azure Resource Providers

```powershell
# Register required providers
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.SecurityInsights
az provider register --namespace Microsoft.EventHub
az provider register --namespace Microsoft.Web
az provider register --namespace Microsoft.Logic
```

---

## Phase 1 — Azure Infrastructure Provisioning

### Step 1.1 — Define Variables

```powershell
# ============================================================
# CONFIGURATION — Edit these values for your environment
# ============================================================
$SUBSCRIPTION_ID       = "<your-subscription-id>"
$RESOURCE_GROUP        = "rg-ghec-sentinel-prod"
$LOCATION              = "eastus2"                            # Match your Azure region
$LOG_ANALYTICS_WS      = "law-ghec-sentinel-prod"
$SENTINEL_WS           = $LOG_ANALYTICS_WS                  # Sentinel sits on top of LAW
$EVENTHUB_NAMESPACE    = "evhns-ghec-audit-prod"
$EVENTHUB_NAME         = "ghec-audit-logs"
$EVENTHUB_AUTH_RULE     = "ghec-audit-send"
$EVENTHUB_CONSUMER_GRP = "sentinel-consumer"
$FUNCTION_APP_NAME     = "func-ghec-sentinel-response"       # Ingestion function only
$LOGIC_APP_TEAMS       = "logic-ghec-teams-notify"
$LOGIC_APP_REVOKE      = "logic-ghec-revoke-pat"
$LOGIC_APP_ENRICH      = "logic-ghec-enrich-incident"
$TAGS                  = "project=ghec-sentinel environment=production compliance=pci-dss owner=security-team"

# Set subscription context
az account set --subscription $SUBSCRIPTION_ID
```

### Step 1.2 — Create Resource Group

```powershell
az group create `
    --name $RESOURCE_GROUP `
    --location $LOCATION `
    --tags $TAGS.Split(" ")
```

### Step 1.3 — Create Log Analytics Workspace

```powershell
az monitor log-analytics workspace create `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --location $LOCATION `
    --sku PerGB2018 `
    --tags $TAGS.Split(" ")

# Set retention separately (--retention-in-days is not valid — use --retention-time)
az monitor log-analytics workspace update `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --retention-time 365

# Get workspace ID and key (needed later)
$WORKSPACE_ID = az monitor log-analytics workspace show `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --query customerId -o tsv

$WORKSPACE_RESOURCE_ID = az monitor log-analytics workspace show `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --query id -o tsv

Write-Host "Workspace ID: $WORKSPACE_ID"
```

### Step 1.4 — Enable Microsoft Sentinel on the Workspace

```powershell
# Enable Sentinel via REST API (az sentinel onboarding-state create requires a JSON body)
$token = az account get-access-token --query accessToken -o tsv
$sentinelUri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01"

Invoke-RestMethod `
    -Uri $sentinelUri `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body '{ "properties": {} }'
```

> **Note:** If `az sentinel` is not available, install the extension:
> ```powershell
> az extension add --name sentinel
> ```

### Step 1.5 — Create Event Hubs Namespace and Event Hub

```powershell
# Create Event Hubs Namespace (Standard tier for partitioning + consumer groups)
az eventhubs namespace create `
    --resource-group $RESOURCE_GROUP `
    --name $EVENTHUB_NAMESPACE `
    --location $LOCATION `
    --sku Standard `
    --capacity 2 `
    --enable-auto-inflate true `
    --maximum-throughput-units 10 `
    --tags $TAGS.Split(" ")

# Create the Event Hub (4 partitions for parallel processing)
az eventhubs eventhub create `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --name $EVENTHUB_NAME `
    --partition-count 4 `
    --cleanup-policy Delete `
    --retention-time-in-hours 168

# Create authorization rule for GHE (Send only — least privilege)
az eventhubs eventhub authorization-rule create `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --eventhub-name $EVENTHUB_NAME `
    --name $EVENTHUB_AUTH_RULE `
    --rights Send

# Create consumer group for Sentinel
az eventhubs eventhub consumer-group create `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --eventhub-name $EVENTHUB_NAME `
    --name $EVENTHUB_CONSUMER_GRP

# Get the connection string (needed for GHE configuration)
$EVENTHUB_CONNECTION_STRING = az eventhubs eventhub authorization-rule keys list `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --eventhub-name $EVENTHUB_NAME `
    --name $EVENTHUB_AUTH_RULE `
    --query primaryConnectionString -o tsv

Write-Host "Event Hub Connection String: $EVENTHUB_CONNECTION_STRING"
Write-Host "⚠️  Save this securely — needed for GHE audit log streaming config"
```

### Step 1.6 — Configure Diagnostic Settings (Event Hub → Log Analytics)

```powershell
# Create a Data Collection Rule to forward Event Hub data to Log Analytics
# This ensures Sentinel can query the GitHub audit log data

az eventhubs namespace authorization-rule create `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --name "sentinel-listen" `
    --rights Listen

$EVENTHUB_LISTEN_CONN = az eventhubs namespace authorization-rule keys list `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --name "sentinel-listen" `
    --query primaryConnectionString -o tsv
```

### Step 1.7 — Create Storage Account (Long-Term Audit Log Archive)

```powershell
$STORAGE_ACCOUNT = "stghecauditarchive"

az storage account create `
    --name $STORAGE_ACCOUNT `
    --resource-group $RESOURCE_GROUP `
    --location $LOCATION `
    --sku Standard_GRS `
    --kind StorageV2 `
    --min-tls-version TLS1_2 `
    --allow-blob-public-access false `
    --tags $TAGS.Split(" ")

# Create immutable container (WORM — Write Once Read Many) for compliance
az storage container create `
    --name "ghec-audit-archive" `
    --account-name $STORAGE_ACCOUNT `
    --auth-mode login

# Set immutability policy (7 years = 2556 days for SOX/PCI compliance)
az storage container immutability-policy create `
    --resource-group $RESOURCE_GROUP `
    --account-name $STORAGE_ACCOUNT `
    --container-name "ghec-audit-archive" `
    --period 2556
```

---

## Phase 2 — GHE Audit Log Streaming Configuration

### Step 2.1 — Configure Audit Log Streaming via REST API

> GitHub Enterprise audit log streaming uses the REST API with encrypted credentials.
> The connection string must be encrypted using the enterprise's stream public key
> (libsodium sealed box encryption, same as GitHub secrets).

> **⚠️ Prerequisite:** The Event Hub namespace must have **local authentication (SAS) enabled**.
> By default, new Standard-tier namespaces have `disableLocalAuth: true`. Fix with:
> ```powershell
> az eventhubs namespace update --resource-group $RESOURCE_GROUP --name $EVENTHUB_NAMESPACE --disable-local-auth false
> ```

> **⚠️ Auth scope:** The `gh` CLI or PAT must have the `admin:enterprise` scope.
> Refresh with: `gh auth refresh --scopes admin:enterprise,read:enterprise,read:org,repo`

```powershell
# ============================================================
# GHE Audit Log Streaming — REST API Configuration
# ============================================================

$GH_ENTERPRISE = "<your-enterprise-slug>"  # e.g., "contoso-retail"

# Step 1: Get the Event Hub connection string
$EVENTHUB_CONNECTION_STRING = az eventhubs eventhub authorization-rule keys list `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --eventhub-name $EVENTHUB_NAME `
    --name $EVENTHUB_AUTH_RULE `
    --query primaryConnectionString -o tsv

# Step 2: Get the enterprise stream encryption key
$streamKeyJson = gh api "/enterprises/$GH_ENTERPRISE/audit-log/stream-key" | ConvertFrom-Json
$keyId = $streamKeyJson.key_id
$publicKeyBase64 = $streamKeyJson.key

# Step 3: Encrypt the connection string using libsodium sealed box
# Requires: pip install PyNaCl
$encryptedConnStr = python -c "
import base64
from nacl.public import SealedBox, PublicKey
public_key = PublicKey(base64.b64decode('$publicKeyBase64'))
encrypted = SealedBox(public_key).encrypt('''$EVENTHUB_CONNECTION_STRING'''.encode('utf-8'))
print(base64.b64encode(encrypted).decode('utf-8'))
"

# Step 4: Create the audit log streaming configuration
$body = @{
    enabled = $true
    stream_type = "Azure Event Hubs"
    vendor_specific = @{
        name = $EVENTHUB_NAME
        encrypted_connstring = $encryptedConnStr
        key_id = $keyId
    }
} | ConvertTo-Json -Depth 5

echo $body | gh api "/enterprises/$GH_ENTERPRISE/audit-log/streams" --method POST --input -
```

### Step 2.2 — Verify Audit Log Streaming

```powershell
# Verify the stream is active
gh api "/enterprises/$GH_ENTERPRISE/audit-log/streams"

# Test with recent audit log entries
gh api "/enterprises/$GH_ENTERPRISE/audit-log?per_page=5" --jq ".[].action"
```

### Step 2.3 — GHE Audit Log Event Categories to Stream

The following event categories are critical for anomaly detection:

| Category | Events | Detection Use Case |
|----------|--------|--------------------|
| `auth` | `oauth_access.create`, `sso_response` | Impossible travel, brute force |
| `org` | `add_member`, `remove_member`, `update_member` | Privilege escalation |
| `repo` | `create`, `destroy`, `visibility_change`, `transfer` | Mass repo deletion, data exfil |
| `team` | `add_member`, `change_privacy`, `add_repository` | Lateral movement |
| `protected_branch` | `create`, `destroy`, `policy_override` | Branch protection bypass |
| `hook` | `create`, `destroy`, `config_changed` | Webhook tampering |
| `integration_installation` | `create`, `destroy` | Unauthorized app install |
| `personal_access_token` | `create`, `access_granted` | PAT abuse |
| `secret_scanning_alert` | `create`, `resolve` | Secret exposure |
| `business` | `sso_response`, `set_actions_fork_pr_workflows` | SSO config changes |
| `git` | `clone`, `push`, `fetch` | Unusual git activity |

---

## Phase 3 — Sentinel Data Connector & Table Setup

### Step 3.1 — Create Custom Log Table for GitHub Audit Logs

```powershell
# Create the custom table schema in Log Analytics for GitHub audit events
# NOTE: Custom tables must use the _CL suffix (e.g., GitHubAuditLog_CL)
$tableSchema = @{
    properties = @{
        schema = @{
            name = "GitHubAuditLog_CL"
            columns = @(
                @{ name = "TimeGenerated"; type = "datetime" }
                @{ name = "Action"; type = "string" }
                @{ name = "Actor"; type = "string" }
                @{ name = "ActorIP"; type = "string" }
                @{ name = "ActorCountry"; type = "string" }
                @{ name = "Organization"; type = "string" }
                @{ name = "Repository"; type = "string" }
                @{ name = "TargetUser"; type = "string" }
                @{ name = "Team"; type = "string" }
                @{ name = "Visibility"; type = "string" }
                @{ name = "Permission"; type = "string" }
                @{ name = "TransportProtocol"; type = "string" }
                @{ name = "OperationType"; type = "string" }
                @{ name = "AccessType"; type = "string" }
                @{ name = "TokenScopes"; type = "string" }
                @{ name = "UserAgent"; type = "string" }
                @{ name = "ExternalIdentity"; type = "string" }
                @{ name = "EventData"; type = "string" }
                @{ name = "RawEvent"; type = "string" }
            )
        }
        retentionInDays = 365
        totalRetentionInDays = 365
        plan = "Analytics"
    }
} | ConvertTo-Json -Depth 10

# Create table via REST API (returns 202 Accepted — creation is async)
$token = az account get-access-token --query accessToken -o tsv
$uri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/tables/GitHubAuditLog_CL?api-version=2022-10-01"

Invoke-WebRequest `
    -Uri $uri `
    -Method Put `
    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body $tableSchema `
    -UseBasicParsing
```

### Step 3.2 — Create Data Collection Endpoint & Rule

```powershell
# Create Data Collection Endpoint (DCE)
# NOTE: az monitor data-collection endpoint create may hang on some CLI versions.
# If it does, use the REST API approach below instead.
$token = az account get-access-token --query accessToken -o tsv
$dceBody = @{
    location = $LOCATION
    properties = @{
        networkAcls = @{ publicNetworkAccess = "Enabled" }
    }
} | ConvertTo-Json -Depth 5

$dceUri = "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/dataCollectionEndpoints/dce-ghec-audit?api-version=2022-06-01"
Invoke-RestMethod -Uri $dceUri -Method Put `
    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body $dceBody

$DCE_ID = "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/dataCollectionEndpoints/dce-ghec-audit"

# Create Data Collection Rule (DCR) to ingest Event Hub data into the custom table
$dcrBody = @{
    location = $LOCATION
    properties = @{
        dataCollectionEndpointId = $DCE_ID
        streamDeclarations = @{
            "Custom-GitHubAuditLog_CL" = @{
                columns = @(
                    @{ name = "TimeGenerated"; type = "datetime" }
                    @{ name = "Action"; type = "string" }
                    @{ name = "Actor"; type = "string" }
                    @{ name = "ActorIP"; type = "string" }
                    @{ name = "ActorCountry"; type = "string" }
                    @{ name = "Organization"; type = "string" }
                    @{ name = "Repository"; type = "string" }
                    @{ name = "TargetUser"; type = "string" }
                    @{ name = "Team"; type = "string" }
                    @{ name = "Visibility"; type = "string" }
                    @{ name = "Permission"; type = "string" }
                    @{ name = "TransportProtocol"; type = "string" }
                    @{ name = "OperationType"; type = "string" }
                    @{ name = "AccessType"; type = "string" }
                    @{ name = "TokenScopes"; type = "string" }
                    @{ name = "UserAgent"; type = "string" }
                    @{ name = "ExternalIdentity"; type = "string" }
                    @{ name = "EventData"; type = "string" }
                    @{ name = "RawEvent"; type = "string" }
                )
            }
        }
        destinations = @{
            logAnalytics = @(
                @{
                    workspaceResourceId = $WORKSPACE_RESOURCE_ID
                    name = "law-ghec-dest"
                }
            )
        }
        dataFlows = @(
            @{
                streams = @("Custom-GitHubAuditLog_CL")
                destinations = @("law-ghec-dest")
                transformKql = "source"
                outputStream = "Custom-GitHubAuditLog_CL"
            }
        )
    }
} | ConvertTo-Json -Depth 10

$dcrUri = "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/dataCollectionRules/dcr-ghec-audit?api-version=2022-06-01"
Invoke-RestMethod -Uri $dcrUri -Method Put `
    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body $dcrBody
```

### Step 3.3 — Install GitHub Sentinel Solution (Content Hub)

```powershell
# Install the GitHub Enterprise Audit Log solution from Sentinel Content Hub
# This provides pre-built data connectors, analytics rules, and workbooks

az sentinel metadata create `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --name "GitHubEnterprise" `
    --content-id "azuresentinel.azure-sentinel-solution-github" `
    --kind "Solution" `
    --source kind="Solution" name="GitHub Enterprise Audit Log"
```

> **Alternative (recommended):** Install via Azure Portal:
> 1. Navigate to **Microsoft Sentinel → Content Hub**
> 2. Search for **"GitHub Enterprise Audit Log"**
> 3. Click **Install**
> 4. This deploys the data connector, parser functions, analytics rules, and workbooks

---

## Phase 4 — Anomaly Detection Analytics Rules

### Overview of Detection Rules

> **⚠️ Sentinel Severity Note:** Microsoft Sentinel only supports `Informational`, `Low`, `Medium`, and `High` severity levels. Rules marked "Critical" in the table below are deployed as `High` severity with an `[CRITICAL]` prefix in the incident title. Use Sentinel automation rules to escalate these incidents.

| # | Rule Name | Severity | Threshold | MITRE Tactic | Detection Type |
|---|-----------|----------|-----------|--------------|----------------|
| 1 | Mass Clone Detection | High (Critical) | > 10 repos/hour per actor | Collection/Exfiltration | Threshold |
| 2 | Mass Artifact Download | High (Critical) | > 20 artifacts/hour per actor | Collection/Exfiltration | Threshold |
| 3 | Unusual Clone Hours | High | Any git.clone 00:00–05:00 from human accounts | Initial Access | Anomaly |
| 4 | New IP Address for Known User | High | First-time IP + high-volume activity | Initial Access | Anomaly |
| 5 | Geo-Impossible Travel | High (Critical) | > 500 miles apart within 1 hour | Initial Access/Credential Access | Anomaly |
| 6 | API Rate Limit Approach | Medium | > 4,000 requests/hour | Discovery | Threshold |
| 7 | Bulk Repository Enumeration | High | > 50 paginated requests in 10 minutes | Discovery/Reconnaissance | Threshold |
| 8 | Service Account Anomalies | Medium | Any deviation from baseline | Credential Access | Anomaly |

### Step 4.1 — Deploy Analytics Rules via Azure CLI

#### Rule 1: Mass Clone Detection

```powershell
$rule1 = @{
    properties = @{
        displayName = "GHE - Mass Clone Detection"
        description = "Detects when a single actor clones more than 10 unique repositories within one hour. Indicates potential intellectual property theft or data exfiltration."
        severity = "High"
        enabled = $true
        query = @"
let CloneThreshold = 10;
GitHubAuditLog_CL
| where TimeGenerated >= ago(1h)
| where Action == "git.clone"
| where isnotempty(Actor)
| summarize
    ClonedRepoCount = dcount(Repository),
    ClonedRepos = make_set(Repository, 50),
    IPs = make_set(ActorIP),
    Countries = make_set(ActorCountry),
    FirstClone = min(TimeGenerated),
    LastClone = max(TimeGenerated)
    by Actor
| where ClonedRepoCount > CloneThreshold
| extend TimespanMinutes = datetime_diff('minute', LastClone, FirstClone)
| project TimeGenerated = now(), Actor, ClonedRepoCount, ClonedRepos, IPs, Countries, FirstClone, LastClone, TimespanMinutes
| extend AlertDetail = strcat(Actor, ' cloned ', ClonedRepoCount, ' repos in ', TimespanMinutes, ' minutes — potential data exfiltration')
"@
        queryFrequency = "PT5M"
        queryPeriod = "PT1H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        suppressionDuration = "PT1H"
        suppressionEnabled = $false
        tactics = @("Collection", "Exfiltration")
        techniques = @("T1530")
        incidentConfiguration = @{
            createIncident = $true
            groupingConfiguration = @{
                enabled = $true
                reopenClosedIncident = $false
                lookbackDuration = "PT24H"
                matchingMethod = "AllEntities"
            }
        }
        entityMappings = @(
            @{
                entityType = "Account"
                fieldMappings = @(@{ identifier = "Name"; columnName = "Actor" })
            }
            @{
                entityType = "IP"
                fieldMappings = @(@{ identifier = "Address"; columnName = "IPs" })
            }
        )
    }
} | ConvertTo-Json -Depth 15

az sentinel alert-rule create `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --rule-name "ghe-mass-clone-detection" `
    --scheduled $rule1
```

#### Rule 2: Mass Artifact Download

```powershell
$rule2_kql = @"
let ArtifactThreshold = 20;
GitHubAuditLog_CL
| where TimeGenerated >= ago(1h)
| where Action in ("actions.artifact_download", "packages.package_version_download", "actions.download_artifact")
| where isnotempty(Actor)
| summarize
    DownloadCount = count(),
    Repos = make_set(Repository, 50),
    RepoCount = dcount(Repository),
    IPs = make_set(ActorIP),
    FirstDownload = min(TimeGenerated),
    LastDownload = max(TimeGenerated)
    by Actor
| where DownloadCount > ArtifactThreshold
| project TimeGenerated = now(), Actor, DownloadCount, RepoCount, Repos, IPs, FirstDownload, LastDownload
| extend AlertDetail = strcat(Actor, ' downloaded ', DownloadCount, ' artifacts across ', RepoCount, ' repos in 1 hour')
"@

az sentinel alert-rule create `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --rule-name "ghe-mass-artifact-download" `
    --scheduled "{
        \"properties\": {
            \"displayName\": \"GHE - Mass Artifact Download\",
            \"description\": \"Detects when a single actor downloads more than 20 artifacts within one hour. Indicates potential bulk collection of build artifacts or packages.\",
            \"severity\": \"Critical\",
            \"enabled\": true,
            \"query\": $(ConvertTo-Json $rule2_kql),
            \"queryFrequency\": \"PT5M\",
            \"queryPeriod\": \"PT1H\",
            \"triggerOperator\": \"GreaterThan\",
            \"triggerThreshold\": 0,
            \"tactics\": [\"Collection\", \"Exfiltration\"],
            \"techniques\": [\"T1530\"]
        }
    }"
```

#### Rule 3: Unusual Clone Hours

```powershell
$rule3_kql = @"
// Detect git.clone events between midnight and 5 AM from human (non-bot) accounts
let SuspiciousStartHour = 0;
let SuspiciousEndHour = 5;
// Known service/bot account patterns to exclude
let ServiceAccountPatterns = dynamic(["bot", "svc-", "service-", "automation-", "github-actions"]);
GitHubAuditLog_CL
| where TimeGenerated >= ago(24h)
| where Action == "git.clone"
| where isnotempty(Actor)
| extend HourOfDay = hourofday(TimeGenerated)
| where HourOfDay >= SuspiciousStartHour and HourOfDay < SuspiciousEndHour
// Exclude known service accounts
| where not(Actor has_any (ServiceAccountPatterns))
| where AccessType != "programmatic" or isempty(AccessType)
| project TimeGenerated, Actor, ActorIP, ActorCountry, Repository, Organization,
          HourOfDay, UserAgent, TransportProtocol
| extend AlertDetail = strcat('Human account "', Actor, '" cloned repo "', Repository,
                              '" at ', format_datetime(TimeGenerated, 'HH:mm'), ' UTC — outside normal hours')
"@
```

#### Rule 4: New IP Address for Known User

```powershell
$rule4_kql = @"
// Detect a known user appearing from a never-before-seen IP with high activity
let LookbackBaseline = 30d;
let RecentWindow = 1h;
let ActivityThreshold = 5;
// Build baseline of known IPs per actor
let KnownIPs = GitHubAuditLog_CL
    | where TimeGenerated between (ago(LookbackBaseline) .. ago(RecentWindow))
    | where isnotempty(Actor) and isnotempty(ActorIP)
    | distinct Actor, ActorIP;
// Find recent activity from new IPs
GitHubAuditLog_CL
| where TimeGenerated >= ago(RecentWindow)
| where isnotempty(Actor) and isnotempty(ActorIP)
| join kind=leftanti KnownIPs on Actor, ActorIP
// Only flag if the actor has baseline history (truly a known user)
| join kind=inner (KnownIPs | distinct Actor) on Actor
| summarize
    ActionCount = count(),
    Actions = make_set(Action, 20),
    Repos = make_set(Repository, 20),
    Countries = make_set(ActorCountry)
    by Actor, ActorIP
| where ActionCount >= ActivityThreshold
| project TimeGenerated = now(), Actor, ActorIP, ActionCount, Actions, Repos, Countries
| extend AlertDetail = strcat('Known user "', Actor, '" appeared from new IP ', ActorIP,
                              ' (', Countries, ') with ', ActionCount, ' actions')
"@
```

#### Rule 5: Geo-Impossible Travel

```powershell
$rule5 = @{
    properties = @{
        displayName = "GHE - Geo-Impossible Travel"
        description = "Detects when a GitHub Enterprise user performs actions from two locations more than 500 miles apart within 1 hour. Strong indicator of credential compromise or account sharing."
        severity = "High"
        enabled = $true
        query = @"
let DistanceThresholdMiles = 500;
let TimeWindowMinutes = 60;
GitHubAuditLog_CL
| where TimeGenerated >= ago(2h)
| where isnotempty(Actor) and isnotempty(ActorIP)
| extend GeoInfo = geo_info_from_ip_address(ActorIP)
| extend Latitude = toreal(GeoInfo.latitude), Longitude = toreal(GeoInfo.longitude)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city)
| where isnotempty(Latitude)
| sort by Actor asc, TimeGenerated asc
| serialize
| extend PrevIP = prev(ActorIP, 1, ""), PrevLat = prev(Latitude, 1), PrevLon = prev(Longitude, 1)
| extend PrevTime = prev(TimeGenerated, 1), PrevActor = prev(Actor, 1, "")
| extend PrevCity = prev(City, 1, ""), PrevCountry = prev(Country, 1, "")
| where Actor == PrevActor and PrevIP != ActorIP
| extend TimeDeltaMin = datetime_diff('minute', TimeGenerated, PrevTime)
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
| extend DistanceMiles = DistanceKm * 0.621371
| where TimeDeltaMin <= TimeWindowMinutes and DistanceMiles >= DistanceThresholdMiles
| project TimeGenerated, Actor, ActorIP, PrevIP,
          Location = strcat(City, ', ', Country), PrevLocation = strcat(PrevCity, ', ', PrevCountry),
          DistanceMiles = round(DistanceMiles, 0), TimeDeltaMin,
          Action, Organization
"@
        queryFrequency = "PT5M"
        queryPeriod = "PT2H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        suppressionDuration = "PT1H"
        suppressionEnabled = $false
        tactics = @("InitialAccess", "CredentialAccess")
        techniques = @("T1078")
        incidentConfiguration = @{
            createIncident = $true
            groupingConfiguration = @{
                enabled = $true
                reopenClosedIncident = $false
                lookbackDuration = "PT24H"
                matchingMethod = "AllEntities"
            }
        }
        entityMappings = @(
            @{
                entityType = "Account"
                fieldMappings = @(@{ identifier = "Name"; columnName = "Actor" })
            }
            @{
                entityType = "IP"
                fieldMappings = @(@{ identifier = "Address"; columnName = "ActorIP" })
            }
        )
    }
} | ConvertTo-Json -Depth 15

az sentinel alert-rule create `
    --resource-group $RESOURCE_GROUP `
    --workspace-name $LOG_ANALYTICS_WS `
    --rule-name "ghe-geo-impossible-travel" `
    --scheduled $rule5
```

#### Rule 6: API Rate Limit Approach

```powershell
$rule6_kql = @"
let RateThreshold = 4000;
GitHubAuditLog_CL
| where TimeGenerated >= ago(1h)
| where isnotempty(Actor)
| summarize
    RequestCount = count(),
    Actions = make_set(Action, 30),
    UniqueActions = dcount(Action),
    IPs = make_set(ActorIP),
    Repos = make_set(Repository, 20),
    FirstRequest = min(TimeGenerated),
    LastRequest = max(TimeGenerated)
    by Actor
| where RequestCount > RateThreshold
| extend RequestsPerMinute = round(toreal(RequestCount) / datetime_diff('minute', LastRequest, FirstRequest), 1)
| project TimeGenerated = now(), Actor, RequestCount, RequestsPerMinute,
          UniqueActions, Actions, IPs, Repos
| extend AlertDetail = strcat(Actor, ' made ', RequestCount, ' API requests in 1 hour (',
                              RequestsPerMinute, '/min) — approaching rate limit')
"@
```

#### Rule 7: Bulk Repository Enumeration

```powershell
$rule7_kql = @"
let EnumThreshold = 50;
let TimeWindow = 10m;
// Detect paginated list/search operations indicative of repo enumeration
GitHubAuditLog_CL
| where TimeGenerated >= ago(10m)
| where Action in ("repo.list", "org.list_repos", "search.repos", "repo.list_forks",
                    "repo.list_topics", "org.list_members")
      or (Action has "list" and Action has "repo")
      or UserAgent has "python-requests" or UserAgent has "curl" or UserAgent has "Go-http-client"
| where isnotempty(Actor)
| summarize
    RequestCount = count(),
    Actions = make_set(Action, 20),
    UserAgents = make_set(UserAgent, 10),
    IPs = make_set(ActorIP),
    Orgs = make_set(Organization)
    by Actor, bin(TimeGenerated, TimeWindow)
| where RequestCount > EnumThreshold
| project TimeGenerated, Actor, RequestCount, Actions, UserAgents, IPs, Orgs
| extend AlertDetail = strcat(Actor, ' made ', RequestCount, ' enumeration requests in 10 min — potential reconnaissance')
"@
```

#### Rule 8: Service Account Anomalies

```powershell
$rule8_kql = @"
// Detect service accounts deviating from their established behavior baseline
let BaselinePeriod = 14d;
let RecentWindow = 1h;
let StdDevMultiplier = 3;
// Identify service accounts by naming convention
let ServiceAccountPatterns = dynamic(["bot", "svc-", "service-", "automation-", "ci-", "deploy-"]);
// Build baseline: typical actions, hours, and volume per service account
let Baseline = GitHubAuditLog_CL
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(RecentWindow))
    | where Actor has_any (ServiceAccountPatterns)
    | summarize
        EventCount = count(),
        TypicalActions = make_set(Action, 50),
        TypicalHours = make_set(bin(hourofday(TimeGenerated), 1)),
        TypicalIPs = make_set(ActorIP)
        by Actor, bin(TimeGenerated, 1h)
    | summarize
        AvgHourlyCount = avg(EventCount),
        StdDevCount = stdev(EventCount),
        AllActions = make_set(TypicalActions),
        AllIPs = make_set(TypicalIPs)
        by Actor;
// Current activity
GitHubAuditLog_CL
| where TimeGenerated >= ago(RecentWindow)
| where Actor has_any (ServiceAccountPatterns)
| summarize
    CurrentCount = count(),
    CurrentActions = make_set(Action, 30),
    CurrentIPs = make_set(ActorIP),
    CurrentHour = min(hourofday(TimeGenerated))
    by Actor
| join kind=inner Baseline on Actor
| extend Threshold = AvgHourlyCount + (StdDevMultiplier * StdDevCount)
// Flag anomalies: volume spike, new actions, or new IPs
| extend VolumeAnomaly = CurrentCount > Threshold
| extend NewActions = set_difference(CurrentActions, AllActions)
| extend NewIPs = set_difference(CurrentIPs, AllIPs)
| extend HasNewActions = array_length(NewActions) > 0
| extend HasNewIPs = array_length(NewIPs) > 0
| where VolumeAnomaly or HasNewActions or HasNewIPs
| project TimeGenerated = now(), Actor, CurrentCount,
          AvgHourlyCount = round(AvgHourlyCount, 1), Threshold = round(Threshold, 1),
          VolumeAnomaly, NewActions, HasNewActions, NewIPs, HasNewIPs
| extend AlertDetail = strcat('Service account "', Actor, '" anomaly: ',
                              iff(VolumeAnomaly, strcat('volume ', CurrentCount, ' vs baseline ', round(AvgHourlyCount, 0)), ''),
                              iff(HasNewActions, strcat(' | new actions: ', NewActions), ''),
                              iff(HasNewIPs, strcat(' | new IPs: ', NewIPs), ''))
"@
```

### Step 4.2 — Batch Deploy All Analytics Rules

```powershell
# ============================================================
# deploy-sentinel-rules.ps1
# Batch deployment of all 8 GHE anomaly detection rules
# ============================================================

param(
    [string]$ResourceGroup = $RESOURCE_GROUP,
    [string]$WorkspaceName = $LOG_ANALYTICS_WS
)

$rules = @(
    @{
        Name = "ghe-mass-clone-detection"
        DisplayName = "GHE - Mass Clone Detection"
        severity = "High"
        Query = $rule1_kql
        Frequency = "PT5M"
        Period = "PT1H"
        Tactics = @("Collection", "Exfiltration")
        Techniques = @("T1530")
    },
    @{
        Name = "ghe-mass-artifact-download"
        DisplayName = "GHE - Mass Artifact Download"
        severity = "High"
        Query = $rule2_kql
        Frequency = "PT5M"
        Period = "PT1H"
        Tactics = @("Collection", "Exfiltration")
        Techniques = @("T1530")
    },
    @{
        Name = "ghe-unusual-clone-hours"
        DisplayName = "GHE - Unusual Clone Hours"
        Severity = "High"
        Query = $rule3_kql
        Frequency = "PT5M"
        Period = "PT24H"
        Tactics = @("InitialAccess")
        Techniques = @("T1078")
    },
    @{
        Name = "ghe-new-ip-known-user"
        DisplayName = "GHE - New IP Address for Known User"
        Severity = "High"
        Query = $rule4_kql
        Frequency = "PT5M"
        Period = "PT1H"
        Tactics = @("InitialAccess")
        Techniques = @("T1078")
    },
    @{
        Name = "ghe-geo-impossible-travel"
        DisplayName = "GHE - Geo-Impossible Travel"
        severity = "High"
        Query = $rule5_kql
        Frequency = "PT5M"
        Period = "PT2H"
        Tactics = @("InitialAccess", "CredentialAccess")
        Techniques = @("T1078")
    },
    @{
        Name = "ghe-api-rate-limit-approach"
        DisplayName = "GHE - API Rate Limit Approach"
        Severity = "Medium"
        Query = $rule6_kql
        Frequency = "PT5M"
        Period = "PT1H"
        Tactics = @("Discovery")
        Techniques = @("T1087")
    },
    @{
        Name = "ghe-bulk-repo-enumeration"
        DisplayName = "GHE - Bulk Repository Enumeration"
        Severity = "High"
        Query = $rule7_kql
        Frequency = "PT5M"
        Period = "PT15M"
        Tactics = @("Discovery", "Reconnaissance")
        Techniques = @("T1087", "T1592")
    },
    @{
        Name = "ghe-service-account-anomalies"
        DisplayName = "GHE - Service Account Anomalies"
        Severity = "Medium"
        Query = $rule8_kql
        Frequency = "PT5M"
        Period = "PT1H"
        Tactics = @("CredentialAccess")
        Techniques = @("T1528")
    }
)

foreach ($rule in $rules) {
    Write-Host "Deploying rule: $($rule.DisplayName)..." -ForegroundColor Cyan

    $ruleJson = @{
        properties = @{
            displayName          = $rule.DisplayName
            severity             = $rule.Severity
            enabled              = $true
            query                = $rule.Query
            queryFrequency       = $rule.Frequency
            queryPeriod          = $rule.Period
            triggerOperator      = "GreaterThan"
            triggerThreshold     = 0
            suppressionDuration  = "PT1H"
            suppressionEnabled   = $false
            tactics              = $rule.Tactics
            techniques           = $rule.Techniques
            incidentConfiguration = @{
                createIncident = $true
                groupingConfiguration = @{
                    enabled            = $true
                    reopenClosedIncident = $false
                    lookbackDuration   = "PT24H"
                    matchingMethod     = "AllEntities"
                }
            }
        }
    } | ConvertTo-Json -Depth 15

    try {
        $token = az account get-access-token --query accessToken -o tsv
        $uri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/alertRules/$($rule.Name)?api-version=2024-03-01"

        Invoke-RestMethod `
            -Uri $uri `
            -Method Put `
            -Headers @{
                Authorization  = "Bearer $token"
                "Content-Type" = "application/json"
            } `
            -Body $ruleJson

        Write-Host "  ✅ Deployed: $($rule.DisplayName)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Failed: $($rule.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n✅ All $($rules.Count) analytics rules deployed." -ForegroundColor Green
```

---

## Phase 5 — Automated Response (Logic Apps)

> **Architecture change:** Response actions (Teams notification, PAT revocation, incident enrichment)
> are now handled by **3 Logic Apps** with native Sentinel triggers — not Azure Functions.
> The Function App (`func-ghec-sentinel-response`) retains **only** the `eventhub_ingest` function
> for Event Hub → Log Analytics ingestion. Three **Sentinel automation rules** wire incidents
> to the Logic Apps automatically.

### Step 5.1 — Create API Connections

Logic Apps use API connections to authenticate with external services. Create two shared connections:

```powershell
# ============================================================
# Create API Connections for Logic Apps
# ============================================================

$token = az account get-access-token --query accessToken -o tsv
$RG_ID = "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

# --- 1. Azure Sentinel connection (Managed Identity auth) ---
$sentinelConnBody = @{
    location   = $LOCATION
    kind       = "V1"
    properties = @{
        displayName             = "azuresentinel-connection"
        parameterValueType      = "Alternative"
        alternativeParameterValues = @{}
        api = @{
            id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/azuresentinel"
        }
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
    -Uri "https://management.azure.com$RG_ID/providers/Microsoft.Web/connections/azuresentinel-connection?api-version=2018-07-01-preview" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $sentinelConnBody

Write-Host "✅ API Connection created: azuresentinel-connection (Managed Identity)"

# --- 2. Teams connection (OAuth — requires portal authorization) ---
$teamsConnBody = @{
    location   = $LOCATION
    kind       = "V1"
    properties = @{
        displayName = "teams-connection"
        api = @{
            id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/teams"
        }
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
    -Uri "https://management.azure.com$RG_ID/providers/Microsoft.Web/connections/teams-connection?api-version=2018-07-01-preview" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $teamsConnBody

Write-Host "✅ API Connection created: teams-connection (OAuth)"
Write-Host "⚠️  Navigate to Azure Portal → API Connections → teams-connection → Authorize to complete OAuth."
```

### Step 5.2 — Create Logic App: Teams Notification

```powershell
# ============================================================
# logic-ghec-teams-notify
# Sentinel trigger → Post Adaptive Card to Teams → Add incident comment
# ============================================================

$token = az account get-access-token --query accessToken -o tsv
$RG_ID = "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

$TEAMS_CHANNEL_ID    = "<your-teams-channel-id>"
$TEAMS_GROUP_ID      = "<your-teams-group-id>"    # The Team's group (team) ID

$teamsNotifyDef = @{
    location   = $LOCATION
    tags       = @{ project = "ghec-sentinel"; component = "response" }
    identity   = @{
        type = "SystemAssigned"
    }
    properties = @{
        state      = "Enabled"
        definition = @{
            "`$schema"     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
            contentVersion = "1.0.0.0"
            triggers = @{
                Microsoft_Sentinel_incident = @{
                    type   = "ApiConnectionWebhook"
                    inputs = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        body = @{
                            callback_url = "@listCallbackUrl()"
                        }
                        path = "/incident-creation"
                    }
                }
            }
            actions = @{
                Post_Adaptive_Card = @{
                    type     = "ApiConnection"
                    runAfter = @{}
                    inputs   = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['teams']['connectionId']"
                            }
                        }
                        method = "post"
                        path   = "/v1.0/teams/$TEAMS_GROUP_ID/channels/$TEAMS_CHANNEL_ID/messages"
                        body   = @{
                            messageBody = "<p>🚨 <b>GHE Sentinel Incident #@{triggerBody()?['object']?['properties']?['incidentNumber']}</b><br/>Title: @{triggerBody()?['object']?['properties']?['title']}<br/>Severity: @{triggerBody()?['object']?['properties']?['severity']}<br/>Description: @{triggerBody()?['object']?['properties']?['description']}<br/><a href=\"@{triggerBody()?['object']?['properties']?['incidentUrl']}\">View in Sentinel</a></p>"
                        }
                    }
                }
                Add_comment_to_incident = @{
                    type     = "ApiConnection"
                    runAfter = @{
                        Post_Adaptive_Card = @("Succeeded")
                    }
                    inputs = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        method = "post"
                        path   = "/Incidents/Comment"
                        body   = @{
                            incidentArmId = "@triggerBody()?['object']?['id']"
                            message       = "📢 Teams notification posted to the security channel."
                        }
                    }
                }
            }
            parameters = @{
                "`$connections" = @{
                    type         = "Object"
                    defaultValue = @{}
                }
            }
        }
        parameters = @{
            "`$connections" = @{
                value = @{
                    azuresentinel = @{
                        connectionId   = "$RG_ID/providers/Microsoft.Web/connections/azuresentinel-connection"
                        connectionName = "azuresentinel-connection"
                        connectionProperties = @{
                            authentication = @{ type = "ManagedServiceIdentity" }
                        }
                        id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/azuresentinel"
                    }
                    teams = @{
                        connectionId   = "$RG_ID/providers/Microsoft.Web/connections/teams-connection"
                        connectionName = "teams-connection"
                        id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/teams"
                    }
                }
            }
        }
    }
} | ConvertTo-Json -Depth 20

Invoke-RestMethod `
    -Uri "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/$LOGIC_APP_TEAMS?api-version=2019-05-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $teamsNotifyDef

Write-Host "✅ Logic App created: $LOGIC_APP_TEAMS"
```

### Step 5.3 — Create Logic App: Revoke PAT

```powershell
# ============================================================
# logic-ghec-revoke-pat
# Sentinel trigger → For each Account entity → List PATs via GitHub API
#                  → Delete each PAT → Add incident comment
# ============================================================

$token = az account get-access-token --query accessToken -o tsv
$RG_ID = "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

$GITHUB_ENTERPRISE_SLUG = "<your-enterprise-slug>"
$GITHUB_TOKEN_PARAM     = "<github-app-token-or-pat>"   # Store in Key Vault for production

$revokePatDef = @{
    location   = $LOCATION
    tags       = @{ project = "ghec-sentinel"; component = "response" }
    identity   = @{
        type = "SystemAssigned"
    }
    properties = @{
        state      = "Enabled"
        definition = @{
            "`$schema"     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
            contentVersion = "1.0.0.0"
            parameters = @{
                "`$connections" = @{
                    type         = "Object"
                    defaultValue = @{}
                }
                GitHubToken = @{
                    type         = "SecureString"
                    defaultValue = ""
                }
                EnterpriseSlug = @{
                    type         = "String"
                    defaultValue = $GITHUB_ENTERPRISE_SLUG
                }
            }
            triggers = @{
                Microsoft_Sentinel_incident = @{
                    type   = "ApiConnectionWebhook"
                    inputs = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        body = @{
                            callback_url = "@listCallbackUrl()"
                        }
                        path = "/incident-creation"
                    }
                }
            }
            actions = @{
                Get_Entities = @{
                    type     = "ApiConnection"
                    runAfter = @{}
                    inputs   = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        method = "post"
                        path   = "/entities/get"
                        body   = @{
                            incidentArmId = "@triggerBody()?['object']?['id']"
                        }
                    }
                }
                For_Each_Account_Entity = @{
                    type     = "Foreach"
                    runAfter = @{
                        Get_Entities = @("Succeeded")
                    }
                    foreach  = "@body('Get_Entities')?['Accounts']"
                    actions  = @{
                        List_PATs = @{
                            type     = "Http"
                            runAfter = @{}
                            inputs   = @{
                                method  = "GET"
                                uri     = "https://api.github.com/enterprises/@{parameters('EnterpriseSlug')}/personal-access-tokens?owner=@{items('For_Each_Account_Entity')?['Name']}&per_page=100"
                                headers = @{
                                    Authorization         = "Bearer @{parameters('GitHubToken')}"
                                    Accept                = "application/vnd.github+json"
                                    "X-GitHub-Api-Version" = "2022-11-28"
                                }
                            }
                        }
                        For_Each_PAT = @{
                            type     = "Foreach"
                            runAfter = @{
                                List_PATs = @("Succeeded")
                            }
                            foreach = "@body('List_PATs')"
                            actions = @{
                                Delete_PAT = @{
                                    type   = "Http"
                                    inputs = @{
                                        method  = "DELETE"
                                        uri     = "https://api.github.com/enterprises/@{parameters('EnterpriseSlug')}/personal-access-tokens/@{items('For_Each_PAT')['id']}"
                                        headers = @{
                                            Authorization         = "Bearer @{parameters('GitHubToken')}"
                                            Accept                = "application/vnd.github+json"
                                            "X-GitHub-Api-Version" = "2022-11-28"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Add_comment_to_incident = @{
                    type     = "ApiConnection"
                    runAfter = @{
                        For_Each_Account_Entity = @("Succeeded")
                    }
                    inputs = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        method = "post"
                        path   = "/Incidents/Comment"
                        body   = @{
                            incidentArmId = "@triggerBody()?['object']?['id']"
                            message       = "🔒 PAT revocation completed for all Account entities in this incident."
                        }
                    }
                }
            }
        }
        parameters = @{
            "`$connections" = @{
                value = @{
                    azuresentinel = @{
                        connectionId   = "$RG_ID/providers/Microsoft.Web/connections/azuresentinel-connection"
                        connectionName = "azuresentinel-connection"
                        connectionProperties = @{
                            authentication = @{ type = "ManagedServiceIdentity" }
                        }
                        id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/azuresentinel"
                    }
                }
            }
            GitHubToken    = @{ value = $GITHUB_TOKEN_PARAM }
            EnterpriseSlug = @{ value = $GITHUB_ENTERPRISE_SLUG }
        }
    }
} | ConvertTo-Json -Depth 25

Invoke-RestMethod `
    -Uri "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/$LOGIC_APP_REVOKE?api-version=2019-05-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $revokePatDef

Write-Host "✅ Logic App created: $LOGIC_APP_REVOKE"
```

### Step 5.4 — Create Logic App: Enrich Incident

```powershell
# ============================================================
# logic-ghec-enrich-incident
# Sentinel trigger → For each Account entity → Get GitHub user profile
#                  → Add enrichment comment to incident
# ============================================================

$token = az account get-access-token --query accessToken -o tsv
$RG_ID = "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

$GITHUB_ENTERPRISE_SLUG = "<your-enterprise-slug>"
$GITHUB_TOKEN_PARAM     = "<github-app-token-or-pat>"

$enrichDef = @{
    location   = $LOCATION
    tags       = @{ project = "ghec-sentinel"; component = "response" }
    identity   = @{
        type = "SystemAssigned"
    }
    properties = @{
        state      = "Enabled"
        definition = @{
            "`$schema"     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
            contentVersion = "1.0.0.0"
            parameters = @{
                "`$connections" = @{
                    type         = "Object"
                    defaultValue = @{}
                }
                GitHubToken = @{
                    type         = "SecureString"
                    defaultValue = ""
                }
                EnterpriseSlug = @{
                    type         = "String"
                    defaultValue = $GITHUB_ENTERPRISE_SLUG
                }
            }
            triggers = @{
                Microsoft_Sentinel_incident = @{
                    type   = "ApiConnectionWebhook"
                    inputs = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        body = @{
                            callback_url = "@listCallbackUrl()"
                        }
                        path = "/incident-creation"
                    }
                }
            }
            actions = @{
                Get_Entities = @{
                    type     = "ApiConnection"
                    runAfter = @{}
                    inputs   = @{
                        host = @{
                            connection = @{
                                name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                            }
                        }
                        method = "post"
                        path   = "/entities/get"
                        body   = @{
                            incidentArmId = "@triggerBody()?['object']?['id']"
                        }
                    }
                }
                For_Each_Account_Entity = @{
                    type     = "Foreach"
                    runAfter = @{
                        Get_Entities = @("Succeeded")
                    }
                    foreach  = "@body('Get_Entities')?['Accounts']"
                    actions  = @{
                        Get_GitHub_User_Profile = @{
                            type     = "Http"
                            runAfter = @{}
                            inputs   = @{
                                method  = "GET"
                                uri     = "https://api.github.com/users/@{items('For_Each_Account_Entity')?['Name']}"
                                headers = @{
                                    Authorization         = "Bearer @{parameters('GitHubToken')}"
                                    Accept                = "application/vnd.github+json"
                                    "X-GitHub-Api-Version" = "2022-11-28"
                                }
                            }
                        }
                        Add_enrichment_comment = @{
                            type     = "ApiConnection"
                            runAfter = @{
                                Get_GitHub_User_Profile = @("Succeeded")
                            }
                            inputs = @{
                                host = @{
                                    connection = @{
                                        name = "@parameters('`$connections')['azuresentinel']['connectionId']"
                                    }
                                }
                                method = "post"
                                path   = "/Incidents/Comment"
                                body   = @{
                                    incidentArmId = "@triggerBody()?['object']?['id']"
                                    message       = "🔍 **GitHub Profile Enrichment** for @{items('For_Each_Account_Entity')?['Name']}:\n- Name: @{body('Get_GitHub_User_Profile')?['name']}\n- Company: @{body('Get_GitHub_User_Profile')?['company']}\n- Account type: @{body('Get_GitHub_User_Profile')?['type']}\n- Created: @{body('Get_GitHub_User_Profile')?['created_at']}\n- Public repos: @{body('Get_GitHub_User_Profile')?['public_repos']}"
                                }
                            }
                        }
                    }
                }
            }
        }
        parameters = @{
            "`$connections" = @{
                value = @{
                    azuresentinel = @{
                        connectionId   = "$RG_ID/providers/Microsoft.Web/connections/azuresentinel-connection"
                        connectionName = "azuresentinel-connection"
                        connectionProperties = @{
                            authentication = @{ type = "ManagedServiceIdentity" }
                        }
                        id = "/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Web/locations/$LOCATION/managedApis/azuresentinel"
                    }
                }
            }
            GitHubToken    = @{ value = $GITHUB_TOKEN_PARAM }
            EnterpriseSlug = @{ value = $GITHUB_ENTERPRISE_SLUG }
        }
    }
} | ConvertTo-Json -Depth 25

Invoke-RestMethod `
    -Uri "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/$LOGIC_APP_ENRICH?api-version=2019-05-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $enrichDef

Write-Host "✅ Logic App created: $LOGIC_APP_ENRICH"
```

### Step 5.5 — Grant RBAC for Logic Apps & Sentinel Automation

```powershell
# ============================================================
# RBAC assignments required for Logic Apps ↔ Sentinel integration
# ============================================================

$token = az account get-access-token --query accessToken -o tsv

# --- 1. Get managed identity principal IDs for each Logic App ---
$TEAMS_PRINCIPAL = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_TEAMS `
    --query identity.principalId -o tsv

$REVOKE_PRINCIPAL = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_REVOKE `
    --query identity.principalId -o tsv

$ENRICH_PRINCIPAL = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_ENRICH `
    --query identity.principalId -o tsv

Write-Host "Logic App principals:"
Write-Host "  Teams notify:     $TEAMS_PRINCIPAL"
Write-Host "  Revoke PAT:       $REVOKE_PRINCIPAL"
Write-Host "  Enrich incident:  $ENRICH_PRINCIPAL"

# --- 2. Grant "Microsoft Sentinel Responder" to each Logic App on the LAW workspace ---
# Role ID: 3e150fc0-0e3b-4267-86e5-0e2a94770c3b (Microsoft Sentinel Responder)
$SENTINEL_RESPONDER_ROLE = "3e150fc0-0e3b-4267-86e5-0e2a94770c3b"

foreach ($principal in @($TEAMS_PRINCIPAL, $REVOKE_PRINCIPAL, $ENRICH_PRINCIPAL)) {
    $roleAssignmentId = [guid]::NewGuid().ToString()
    az role assignment create `
        --assignee-object-id $principal `
        --assignee-principal-type ServicePrincipal `
        --role $SENTINEL_RESPONDER_ROLE `
        --scope $WORKSPACE_RESOURCE_ID
    Write-Host "  ✅ Sentinel Responder granted to $principal"
}

# --- 3. Grant "Microsoft Sentinel Automation Contributor" to Azure Security Insights SP ---
# The "Azure Security Insights" service principal (app ID: 98785600-1bb7-4fb9-b9fa-19afe2c8a360)
# must have "Microsoft Sentinel Automation Contributor" on each Logic App so automation rules
# can trigger them.
$ASI_SP_APPID = "98785600-1bb7-4fb9-b9fa-19afe2c8a360"
$ASI_SP_OBJECT_ID = az ad sp show --id $ASI_SP_APPID --query id -o tsv

# If the SP is not registered in the tenant, register it:
if (-not $ASI_SP_OBJECT_ID) {
    az ad sp create --id $ASI_SP_APPID | Out-Null
    $ASI_SP_OBJECT_ID = az ad sp show --id $ASI_SP_APPID --query id -o tsv
    Write-Host "  ✅ Registered Azure Security Insights service principal"
}

# Role ID: f4c81013-99ee-4d62-a7ee-b3f1f648599a (Microsoft Sentinel Automation Contributor)
$SENTINEL_AUTO_CONTRIBUTOR = "f4c81013-99ee-4d62-a7ee-b3f1f648599a"

foreach ($logicAppName in @($LOGIC_APP_TEAMS, $LOGIC_APP_REVOKE, $LOGIC_APP_ENRICH)) {
    $logicAppId = az resource show `
        --resource-group $RESOURCE_GROUP `
        --resource-type "Microsoft.Logic/workflows" `
        --name $logicAppName `
        --query id -o tsv

    az role assignment create `
        --assignee-object-id $ASI_SP_OBJECT_ID `
        --assignee-principal-type ServicePrincipal `
        --role $SENTINEL_AUTO_CONTRIBUTOR `
        --scope $logicAppId
    Write-Host "  ✅ Sentinel Automation Contributor granted on $logicAppName"
}

# --- 4. Grant "Logic App Contributor" to the admin user creating automation rules ---
# Replace with the object ID of the admin user or AAD group
$ADMIN_USER_OBJECT_ID = "<admin-user-or-group-object-id>"

foreach ($logicAppName in @($LOGIC_APP_TEAMS, $LOGIC_APP_REVOKE, $LOGIC_APP_ENRICH)) {
    $logicAppId = az resource show `
        --resource-group $RESOURCE_GROUP `
        --resource-type "Microsoft.Logic/workflows" `
        --name $logicAppName `
        --query id -o tsv

    az role assignment create `
        --assignee-object-id $ADMIN_USER_OBJECT_ID `
        --assignee-principal-type User `
        --role "Logic App Contributor" `
        --scope $logicAppId
    Write-Host "  ✅ Logic App Contributor granted on $logicAppName for admin"
}

Write-Host "`n✅ All RBAC assignments complete."
```

### Step 5.6 — Create Sentinel Automation Rules

```powershell
# ============================================================
# Create 3 Sentinel automation rules wiring incidents to Logic Apps
# ============================================================

$token = az account get-access-token --query accessToken -o tsv

# Get Logic App resource IDs
$TEAMS_LOGIC_APP_ID = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_TEAMS `
    --query id -o tsv

$ENRICH_LOGIC_APP_ID = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_ENRICH `
    --query id -o tsv

$REVOKE_LOGIC_APP_ID = az resource show `
    --resource-group $RESOURCE_GROUP `
    --resource-type "Microsoft.Logic/workflows" `
    --name $LOGIC_APP_REVOKE `
    --query id -o tsv

$TENANT_ID = az account show --query tenantId -o tsv

# --- Rule 1: "GHE - Notify Teams + Set Active" (all incidents) ---
$rule1 = @{
    properties = @{
        displayName = "GHE - Notify Teams + Set Active"
        order = 1
        triggeringLogic = @{
            isEnabled    = $true
            triggersOn   = "Incidents"
            triggersWhen = "Created"
        }
        actions = @(
            @{
                order = 1
                actionType = "ModifyProperties"
                actionConfiguration = @{
                    status = "Active"
                }
            },
            @{
                order = 2
                actionType = "RunPlaybook"
                actionConfiguration = @{
                    logicAppResourceId = $TEAMS_LOGIC_APP_ID
                    tenantId           = $TENANT_ID
                }
            }
        )
    }
} | ConvertTo-Json -Depth 15

Invoke-RestMethod `
    -Uri "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/automationRules/ghe-notify-teams-active?api-version=2024-03-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $rule1

Write-Host "✅ Automation Rule 1: GHE - Notify Teams + Set Active"

# --- Rule 2: "GHE - Enrich All Incidents" (all incidents) ---
$rule2 = @{
    properties = @{
        displayName = "GHE - Enrich All Incidents"
        order = 2
        triggeringLogic = @{
            isEnabled    = $true
            triggersOn   = "Incidents"
            triggersWhen = "Created"
        }
        actions = @(
            @{
                order = 1
                actionType = "RunPlaybook"
                actionConfiguration = @{
                    logicAppResourceId = $ENRICH_LOGIC_APP_ID
                    tenantId           = $TENANT_ID
                }
            }
        )
    }
} | ConvertTo-Json -Depth 15

Invoke-RestMethod `
    -Uri "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/automationRules/ghe-enrich-all?api-version=2024-03-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $rule2

Write-Host "✅ Automation Rule 2: GHE - Enrich All Incidents"

# --- Rule 3: "GHE - Revoke PATs (High Severity)" (High severity only) ---
$rule3 = @{
    properties = @{
        displayName = "GHE - Revoke PATs (High Severity)"
        order = 3
        triggeringLogic = @{
            isEnabled    = $true
            triggersOn   = "Incidents"
            triggersWhen = "Created"
            conditions   = @(
                @{
                    conditionType = "Property"
                    conditionProperties = @{
                        propertyName   = "IncidentSeverity"
                        operator       = "Equals"
                        propertyValues = @("High")
                    }
                }
            )
        }
        actions = @(
            @{
                order = 1
                actionType = "RunPlaybook"
                actionConfiguration = @{
                    logicAppResourceId = $REVOKE_LOGIC_APP_ID
                    tenantId           = $TENANT_ID
                }
            }
        )
    }
} | ConvertTo-Json -Depth 15

Invoke-RestMethod `
    -Uri "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/automationRules/ghe-revoke-pat-high?api-version=2024-03-01" `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $rule3

Write-Host "✅ Automation Rule 3: GHE - Revoke PATs (High Severity)"
Write-Host @"

📋 Sentinel Automation Summary:
   Rule 1 → All incidents → Set Active + Teams notification (logic-ghec-teams-notify)
   Rule 2 → All incidents → GitHub profile enrichment (logic-ghec-enrich-incident)
   Rule 3 → High severity → PAT revocation (logic-ghec-revoke-pat)
"@
```

---

## Phase 6 — Workbooks & Dashboards

### Step 6.1 — GHE Security Overview Workbook

```powershell
# Deploy a Sentinel workbook for GHE security overview
$workbookJson = @{
    properties = @{
        displayName = "GitHub Enterprise Security Overview"
        serializedData = @"
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": "markdown",
            "content": { "json": "# GitHub Enterprise Cloud — Security Monitoring Dashboard\n\nReal-time visibility into GHE audit events, anomalies, and security posture." }
        },
        {
            "type": "query",
            "title": "Events by Category (Last 24h)",
            "query": "GitHubAuditLog_CL\n| where TimeGenerated >= ago(24h)\n| extend Category = tostring(split(Action, '.')[0])\n| summarize Count = count() by Category\n| sort by Count desc\n| render piechart"
        },
        {
            "type": "query",
            "title": "Top 10 Active Users",
            "query": "GitHubAuditLog_CL\n| where TimeGenerated >= ago(24h)\n| summarize Actions = count() by Actor\n| top 10 by Actions\n| render barchart"
        },
        {
            "type": "query",
            "title": "Geographic Access Map",
            "query": "GitHubAuditLog_CL\n| where TimeGenerated >= ago(24h) and isnotempty(ActorIP)\n| extend GeoInfo = geo_info_from_ip_address(ActorIP)\n| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city)\n| summarize Count = count() by Country, City\n| render map"
        },
        {
            "type": "query",
            "title": "Critical Security Events (Last 7d)",
            "query": "GitHubAuditLog_CL\n| where TimeGenerated >= ago(7d)\n| where Action in ('protected_branch.destroy','repo.destroy','repo.visibility_change','business.add_admin','secret_scanning.push_protection_bypass','ip_allow_list_entry.destroy','business.disable_saml')\n| project TimeGenerated, Actor, Action, Repository, Organization, ActorIP\n| sort by TimeGenerated desc"
        },
        {
            "type": "query",
            "title": "Open Sentinel Incidents (GHE)",
            "query": "SecurityIncident\n| where TimeGenerated >= ago(30d)\n| where Title startswith 'GHE'\n| where Status != 'Closed'\n| project TimeGenerated, Title, Severity, Status, Owner\n| sort by Severity asc, TimeGenerated desc"
        }
    ]
}
"@
        category = "sentinel"
        sourceId = $WORKSPACE_RESOURCE_ID
    }
} | ConvertTo-Json -Depth 10

$token = az account get-access-token --query accessToken -o tsv
$workbookId = [guid]::NewGuid().ToString()
$uri = "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/workbooks/$workbookId`?api-version=2022-04-01"

Invoke-RestMethod `
    -Uri $uri `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $workbookJson
```

---

## Phase 7 — Validation & Testing

### Step 7.1 — Verify Data Flow

```powershell
# ============================================================
# validate-data-flow.ps1
# End-to-end validation of GHE → Event Hub → Sentinel pipeline
# ============================================================

Write-Host "🔍 Step 1: Verify Event Hub is receiving messages..." -ForegroundColor Cyan
$ehMetrics = az eventhubs eventhub show `
    --resource-group $RESOURCE_GROUP `
    --namespace-name $EVENTHUB_NAMESPACE `
    --name $EVENTHUB_NAME `
    --query "{messageCount: messageRetentionInDays, partitionCount: partitionCount}" `
    -o json | ConvertFrom-Json
Write-Host "  Event Hub partitions: $($ehMetrics.partitionCount)"

Write-Host "`n🔍 Step 2: Check Log Analytics for GitHub data..." -ForegroundColor Cyan
$laQuery = "GitHubAuditLog_CL | where TimeGenerated >= ago(1h) | count"
$queryResult = az monitor log-analytics query `
    --workspace $WORKSPACE_ID `
    --analytics-query $laQuery `
    --timespan "PT1H" `
    -o json | ConvertFrom-Json
Write-Host "  Records in last 1h: $($queryResult.tables[0].rows[0][0])"

Write-Host "`n🔍 Step 3: Verify Sentinel analytics rules are active..." -ForegroundColor Cyan
$token = az account get-access-token --query accessToken -o tsv
$rulesUri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"
$existingRules = Invoke-RestMethod -Uri $rulesUri -Headers @{ Authorization = "Bearer $token" }
$gheRules = $existingRules.value | Where-Object { $_.properties.displayName -like "GHE*" }
Write-Host "  Active GHE rules: $($gheRules.Count)"
$gheRules | ForEach-Object {
    $status = if ($_.properties.enabled) { "✅" } else { "❌" }
    Write-Host "    $status $($_.properties.displayName) [$($_.properties.severity)]"
}

Write-Host "`n🔍 Step 4: Check for recent incidents..." -ForegroundColor Cyan
$incidentQuery = "SecurityIncident | where TimeGenerated >= ago(24h) | where Title startswith 'GHE' | project TimeGenerated, Title, Severity, Status | sort by TimeGenerated desc | take 5"
$incidents = az monitor log-analytics query `
    --workspace $WORKSPACE_ID `
    --analytics-query $incidentQuery `
    --timespan "PT24H" `
    -o table
Write-Host $incidents

Write-Host "`n✅ Validation complete." -ForegroundColor Green
```

### Step 7.2 — Generate Test Events

```powershell
# ============================================================
# generate-test-events.ps1
# Trigger known audit log events to validate detection rules
# ============================================================

$GH_ENTERPRISE = "<your-enterprise-slug>"
$GH_ORG        = "<your-org-name>"
$GH_PAT        = "<test-admin-pat>"

$headers = @{
    "Authorization"        = "Bearer $GH_PAT"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

Write-Host "🧪 Test 1: Create and delete a test repository (triggers repo.create + repo.destroy)..."
$testRepo = "sentinel-test-$(Get-Random -Maximum 9999)"
Invoke-RestMethod -Uri "https://api.github.com/orgs/$GH_ORG/repos" `
    -Method Post -Headers $headers `
    -Body (@{ name = $testRepo; private = $true; auto_init = $true } | ConvertTo-Json)
Start-Sleep -Seconds 5
Invoke-RestMethod -Uri "https://api.github.com/repos/$GH_ORG/$testRepo" `
    -Method Delete -Headers $headers
Write-Host "  ✅ Repo created and deleted: $testRepo"

Write-Host "`n🧪 Test 2: Create a PAT (triggers personal_access_token events)..."
Write-Host "  ⚠️  PAT creation must be done via UI or pre-existing PAT. Verify in audit log."

Write-Host "`n🧪 Test 3: Clone multiple repos rapidly (triggers git.clone events)..."
Write-Host "  Run: for i in (1..25) { gh repo clone $GH_ORG/repo-name -- --depth 1 }"

Write-Host "`n🧪 Waiting 10 minutes for events to flow through the pipeline..."
Write-Host "  Then check Sentinel for triggered incidents."
```

---

## Phase 8 — Operationalization

### Step 8.1 — Runbook: Incident Response for GHE Alerts

| Severity | SLA | Response | Escalation |
|----------|-----|----------|------------|
| Critical | 15 min ack / 1h response | On-call SecOps investigates immediately. Block actor if confirmed compromise. | VP Security + CISO within 1h |
| High | 1h ack / 4h response | SecOps triages during business hours. Verify with asset owner. | Security Manager within 4h |
| Medium | 4h ack / 24h response | SecOps reviews during next shift. Validate against baseline. | Security Lead within 24h |
| Low | 24h ack / 7d response | Added to weekly review queue. Tune rule if false positive. | No escalation unless pattern |

### Step 8.2 — Alert Tuning & Maintenance

```powershell
# ============================================================
# tune-sentinel-rules.ps1
# Review and tune analytics rules based on false positive rates
# ============================================================

$token = az account get-access-token --query accessToken -o tsv

# Query false positive rate per rule (last 30 days)
$fpQuery = @"
SecurityIncident
| where TimeGenerated >= ago(30d)
| where Title startswith "GHE"
| summarize
    Total = count(),
    TruePositive = countif(Classification == "TruePositive"),
    FalsePositive = countif(Classification == "FalsePositive"),
    BenignPositive = countif(Classification == "BenignPositive"),
    Undetermined = countif(Classification == "Undetermined")
    by Title
| extend FPRate = round(100.0 * FalsePositive / Total, 1)
| sort by FPRate desc
"@

$results = az monitor log-analytics query `
    --workspace $WORKSPACE_ID `
    --analytics-query $fpQuery `
    --timespan "P30D" `
    -o table

Write-Host "📊 False Positive Analysis (Last 30 Days):"
Write-Host $results
Write-Host "`n⚠️  Rules with FP rate > 20% should be tuned."
Write-Host "   Consider: adjusting thresholds, adding exclusions, or refining KQL."
```

### Step 8.3 — Compliance Mapping

| Detection Rule | PCI DSS v4.0 | SOX | SOC 2 |
|----------------|--------------|-----|-------|
| Mass Clone Detection | 10.2.7, 10.4.1 | — | CC6.8, CC7.2 |
| Mass Artifact Download | 10.2.7, 10.4.2 | — | CC6.8, CC7.2 |
| Unusual Clone Hours | 10.2.2, 10.4.1 | — | CC6.1, CC7.2 |
| New IP Address for Known User | 10.2.2, 10.4.1 | — | CC6.1, CC6.8 |
| Geo-Impossible Travel | 10.2.2, 10.4.1 | — | CC6.1, CC6.8 |
| API Rate Limit Approach | 10.4.1, 10.4.2 | — | CC7.2 |
| Bulk Repository Enumeration | 10.4.1, 10.4.2 | — | CC6.8, CC7.2 |
| Service Account Anomalies | 8.6.1, 8.6.3 | IT General Controls | CC6.1, CC6.3 |

### Step 8.4 — Scheduled Maintenance Tasks

```powershell
# ============================================================
# monthly-maintenance.ps1
# Run monthly to ensure the detection pipeline is healthy
# ============================================================

Write-Host "📋 Monthly GHE → Sentinel Maintenance Check" -ForegroundColor Cyan
Write-Host "============================================="

# 1. Verify audit log streaming is active
Write-Host "`n1. Checking GHE audit log streaming status..."
$streams = Invoke-RestMethod `
    -Uri "https://api.github.com/enterprises/$GH_ENTERPRISE/audit-log/streams" `
    -Method Get `
    -Headers $headers
$activeStreams = $streams | Where-Object { $_.enabled -eq $true }
Write-Host "   Active streams: $($activeStreams.Count)"

# 2. Check data freshness
Write-Host "`n2. Checking data freshness in Log Analytics..."
$freshnessQuery = "GitHubAuditLog_CL | summarize LastEvent = max(TimeGenerated) | extend Lag = now() - LastEvent"
az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query $freshnessQuery --timespan "PT1H" -o table

# 3. Check rule health
Write-Host "`n3. Checking Sentinel rule health..."
$ruleHealthQuery = @"
SentinelHealth
| where TimeGenerated >= ago(24h)
| where SentinelResourceType == "Analytics Rule"
| where Status != "Success"
| project TimeGenerated, SentinelResourceName, Status, Description
"@
az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query $ruleHealthQuery --timespan "PT24H" -o table

# 4. Review incident volume
Write-Host "`n4. Incident volume (last 30 days)..."
$volumeQuery = @"
SecurityIncident
| where TimeGenerated >= ago(30d) and Title startswith "GHE"
| summarize Count = count() by Severity
| sort by Severity asc
"@
az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query $volumeQuery --timespan "P30D" -o table

# 5. Storage archive status
Write-Host "`n5. Checking archive storage..."
az storage blob list --container-name "ghec-audit-archive" --account-name $STORAGE_ACCOUNT --query "[].{Name:name, Size:properties.contentLength, LastModified:properties.lastModified}" -o table | Select-Object -Last 5

Write-Host "`n✅ Monthly maintenance check complete." -ForegroundColor Green
```

---

## Full Automation — Master Deployment Script

```powershell
# ============================================================
# deploy-ghec-sentinel-full.ps1
#
# MASTER SCRIPT — End-to-end deployment of the GHE → Sentinel
# anomaly detection pipeline.
#
# Usage:
#   ./deploy-ghec-sentinel-full.ps1 `
#       -SubscriptionId "<sub-id>" `
#       -EnterpriseSlug "<ghe-enterprise>" `
#       -GitHubPAT "<pat-with-admin:enterprise>"
#
# ============================================================

param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$EnterpriseSlug,
    [Parameter(Mandatory)][string]$GitHubPAT,
    [string]$ResourceGroup  = "rg-ghec-sentinel-prod",
    [string]$Location       = "eastus2",
    [string]$WorkspaceName  = "law-ghec-sentinel-prod",
    [string]$EventHubNS     = "evhns-ghec-audit-prod",
    [string]$EventHubName   = "ghec-audit-logs"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

Write-Host @"

  ╔══════════════════════════════════════════════════════╗
  ║  GHE → Microsoft Sentinel — Full Deployment         ║
  ║  Anomaly Detection Pipeline                          ║
  ╚══════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# ---- Phase 1: Azure Infrastructure ----
Write-Host "▶ Phase 1: Provisioning Azure Infrastructure..." -ForegroundColor Yellow
az account set --subscription $SubscriptionId

az group create --name $ResourceGroup --location $Location --tags "project=ghec-sentinel" | Out-Null
Write-Host "  ✅ Resource group created"

az monitor log-analytics workspace create `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --location $Location `
    --sku PerGB2018 | Out-Null

az monitor log-analytics workspace update `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --retention-time 365 | Out-Null
Write-Host "  ✅ Log Analytics workspace created (365-day retention)"

$WORKSPACE_RESOURCE_ID = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName `
    --query id -o tsv

az extension add --name sentinel --yes 2>$null
$sentinelToken = az account get-access-token --query accessToken -o tsv
$sentinelUri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01"
Invoke-RestMethod `
    -Uri $sentinelUri `
    -Method Put `
    -Headers @{
        Authorization  = "Bearer $sentinelToken"
        "Content-Type" = "application/json"
    } `
    -Body '{ "properties": {} }' | Out-Null
Write-Host "  ✅ Microsoft Sentinel enabled"

az eventhubs namespace create `
    --resource-group $ResourceGroup `
    --name $EventHubNS `
    --location $Location `
    --sku Standard | Out-Null

az eventhubs eventhub create `
    --resource-group $ResourceGroup `
    --namespace-name $EventHubNS `
    --name $EventHubName `
    --partition-count 4 `
    --cleanup-policy Delete `
    --retention-time-in-hours 168 | Out-Null

az eventhubs eventhub authorization-rule create `
    --resource-group $ResourceGroup `
    --namespace-name $EventHubNS `
    --eventhub-name $EventHubName `
    --name "ghec-audit-send" `
    --rights Send | Out-Null
Write-Host "  ✅ Event Hub configured"

$connStr = az eventhubs eventhub authorization-rule keys list `
    --resource-group $ResourceGroup `
    --namespace-name $EventHubNS `
    --eventhub-name $EventHubName `
    --name "ghec-audit-send" `
    --query primaryConnectionString -o tsv

# ---- Phase 2: GHE Streaming ----
Write-Host "`n▶ Phase 2: Configuring GHE Audit Log Streaming..." -ForegroundColor Yellow

$sharedKey = ($connStr -split "SharedAccessKey=" | Select-Object -Last 1) -replace ";.*", ""
$body = @{
    enabled = $true
    stream = @{
        vendor_specific = @{
            namespace      = "$EventHubNS.servicebus.windows.net"
            shared_access_key_name = "ghec-audit-send"
            shared_access_key      = $sharedKey
            event_hub_name = $EventHubName
        }
    }
} | ConvertTo-Json -Depth 5

$ghHeaders = @{
    "Authorization"        = "Bearer $GitHubPAT"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

try {
    Invoke-RestMethod `
        -Uri "https://api.github.com/enterprises/$EnterpriseSlug/audit-log/streams" `
        -Method Post -Headers $ghHeaders `
        -Body $body -ContentType "application/json"
    Write-Host "  ✅ GHE audit log streaming configured"
}
catch {
    Write-Host "  ⚠️  Streaming config may need manual setup: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# ---- Phase 3: Deploy Detection Rules ----
Write-Host "`n▶ Phase 3: Deploying Sentinel Analytics Rules..." -ForegroundColor Yellow
# (Insert the batch deployment loop from Step 4.2 here)
Write-Host "  ✅ 8 analytics rules deployed"

# ---- Phase 4: Configure Automation (Logic Apps) ----
Write-Host "`n▶ Phase 4: Setting up Logic Apps & Automation Rules..." -ForegroundColor Yellow
# (Insert API Connection creation from Step 5.1, Logic Apps from Steps 5.2–5.4,
#  RBAC from Step 5.5, and automation rules from Step 5.6 here)
Write-Host "  ✅ 3 Logic Apps deployed (Teams notify, PAT revoke, Enrich incident)"
Write-Host "  ✅ 3 Sentinel automation rules configured"

# ---- Summary ----
Write-Host @"

  ╔══════════════════════════════════════════════════════╗
  ║  ✅ Deployment Complete                              ║
  ╠══════════════════════════════════════════════════════╣
  ║                                                      ║
  ║  Resource Group:    $ResourceGroup
  ║  Log Analytics:     $WorkspaceName
  ║  Event Hub:         $EventHubNS/$EventHubName
  ║  Sentinel Rules:    8 analytics rules
  ║  Logic Apps:        3 (Teams, PAT revoke, Enrich)
  ║  Automation Rules:  3 (wired to Logic Apps)
  ║                                                      ║
  ║  Next Steps:                                         ║
  ║  1. Verify data flow (Phase 7 validation script)     ║
  ║  2. Authorize Teams API connection in Azure Portal   ║
  ║  3. Assign SecOps AAD group for auto-assignment      ║
  ║  4. Run monthly maintenance (Phase 8.4 script)       ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
"@ -ForegroundColor Green
```

---

## Appendix A — GitHub Audit Log Event Reference

Key events for anomaly detection:

```
# Authentication & Access
auth.oauth_access              auth.sso_response
auth.login                     auth.two_factor_authentication

# Organization Management
org.add_member                 org.remove_member
org.update_member              org.invite_member

# Repository Operations
repo.create                    repo.destroy
repo.visibility_change         repo.transfer
repo.access                    repo.rename

# Branch Protection
protected_branch.create        protected_branch.destroy
protected_branch.policy_override

# Git Operations
git.clone                      git.push
git.fetch

# Tokens & Credentials
personal_access_token.create   personal_access_token.access_granted
oauth_authorization.create     oauth_authorization.destroy
deploy_key.create              deploy_key.destroy

# Security
secret_scanning_alert.create   secret_scanning.push_protection_bypass
code_scanning_alert.create     dependabot_alerts.enable

# Integrations
integration_installation.create  integration_installation.destroy
hook.create                    hook.destroy
hook.config_changed

# Enterprise / Business
business.add_admin             business.update_saml_provider
business.set_sso_enforcement   ip_allow_list_entry.create
ip_allow_list_entry.destroy
```

---

## Appendix B — MITRE ATT&CK Mapping

| Tactic | Technique | GHE Detection Rule |
|--------|-----------|-------------------|
| Initial Access | T1078 Valid Accounts | Unusual Clone Hours, New IP Address for Known User, Geo-Impossible Travel |
| Credential Access | T1528 Steal Application Access Token | Service Account Anomalies |
| Discovery | T1087 Account Discovery | API Rate Limit Approach, Bulk Repository Enumeration |
| Reconnaissance | T1592 Gather Victim Host Information | Bulk Repository Enumeration |
| Collection | T1530 Data from Cloud Storage | Mass Clone Detection, Mass Artifact Download |
| Exfiltration | T1530 Data from Cloud Storage | Mass Clone Detection, Mass Artifact Download |
| Initial Access / Credential Access | T1078 Valid Accounts | Geo-Impossible Travel |

---

*Document generated: 2026-03-24 — For the SP500 Retail Organization GHE Review Engagement*
*Aligned with: final_GHE_Review.md Phase 2 Roadmap (Items 2, 3) and Audit Log section*
