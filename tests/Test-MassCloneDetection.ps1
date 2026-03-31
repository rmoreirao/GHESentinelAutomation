#!/usr/bin/env pwsh
# ============================================================
# Test-MassCloneDetection.ps1
# End-to-end validation: Generate mass clone events -> Verify
# Sentinel alert -> Verify Logic Apps -> Verify PAT revocation
#
# Based on SENTINEL_DETECTION_PLAN.md Phase 7 and the
# "GHE - Mass Clone Detection" analytics rule (Rule 1).
# ============================================================

[CmdletBinding()]
param(
    # -- GitHub Configuration --
    [Parameter(Mandatory = $true)]
    [string]$GitHubPAT,

    [string]$GitHubEnterprise = "rmoreiraoghe4org",

    [Parameter(Mandatory = $true)]
    [string]$GitHubOrg,

    # -- Azure Configuration --
    [string]$SubscriptionId,
    [string]$ResourceGroup = "rg-ghec-sentinel-prod",
    [string]$LogAnalyticsWorkspace = "law-ghec-sentinel-prod",

    # -- Test Parameters --
    [int]$CloneCount = 15,               # Must be > 10 to exceed threshold
    [int]$MaxWaitMinutes = 30,           # Max time to wait for Sentinel incident
    [int]$PollIntervalSeconds = 60,      # How often to check for incident

    # -- Step Control --
    [switch]$SkipEventGeneration,        # Skip Step 1 if events already generated
    [switch]$SkipSentinelCheck,          # Skip Step 2
    [switch]$SkipLogicAppCheck,          # Skip Step 3
    [switch]$SkipPATRevocationCheck      # Skip Step 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# PREREQUISITES CHECK
# ============================================================

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Mass Clone Detection -- End-to-End Validation" -ForegroundColor Cyan
Write-Host "  Rule: GHE - Mass Clone Detection (Severity: High)" -ForegroundColor Cyan
Write-Host "  Threshold: > 10 unique repos cloned/hour/actor" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow

# Check required tools
$prereqsFailed = $false
foreach ($tool in @("az", "gh", "git")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "  [FAIL] '$tool' CLI not found. Please install it." -ForegroundColor Red
        $prereqsFailed = $true
    } else {
        $toolVersion = ""
        switch ($tool) {
            "az"  { $toolVersion = (az version 2>$null | ConvertFrom-Json).'azure-cli' }
            "gh"  { $toolVersion = (gh --version 2>$null | Select-Object -First 1) }
            "git" { $toolVersion = (git --version 2>$null) }
        }
        Write-Host "  [OK] $tool found: $toolVersion" -ForegroundColor Green
    }
}

if ($prereqsFailed) {
    Write-Error "Missing prerequisites. Install required CLIs before running."
    exit 1
}

# Verify Azure login
$azAccount = az account show 2>$null | ConvertFrom-Json
if (-not $azAccount) {
    Write-Host "  [FAIL] Not logged into Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Azure account: $($azAccount.name) ($($azAccount.id))" -ForegroundColor Green

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId 2>$null
    Write-Host "  [OK] Subscription set: $SubscriptionId" -ForegroundColor Green
} else {
    $SubscriptionId = $azAccount.id
}

# Verify GitHub PAT (enterprise-scoped, used for PAT revocation checks)
$ghHeaders = @{
    "Authorization"        = "Bearer $GitHubPAT"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

try {
    $ghUser = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $ghHeaders
    Write-Host "  [OK] GitHub PAT authenticated as: $($ghUser.login)" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] GitHub PAT authentication failed: $_" -ForegroundColor Red
    exit 1
}

# Verify gh CLI auth (used for repo creation and cloning — needs repo scope)
$ghCliStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [FAIL] GitHub CLI not authenticated. Run 'gh auth login' first." -ForegroundColor Red
    exit 1
}
$ghCliUser = gh api user --jq '.login' 2>$null
Write-Host "  [OK] GitHub CLI authenticated as: $ghCliUser (used for repo ops)" -ForegroundColor Green

# Get workspace resource ID
$WORKSPACE_ID = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $LogAnalyticsWorkspace `
    --query customerId -o tsv 2>$null

$WORKSPACE_RESOURCE_ID = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $LogAnalyticsWorkspace `
    --query id -o tsv 2>$null

if (-not $WORKSPACE_ID) {
    Write-Host "  [FAIL] Log Analytics workspace '$LogAnalyticsWorkspace' not found." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Workspace ID: $WORKSPACE_ID" -ForegroundColor Green

Write-Host "`n[OK] All prerequisites met.`n" -ForegroundColor Green

$testStartTime = [DateTime]::UtcNow
$testStartTimeISO = $testStartTime.ToString("o")
Write-Host "Test start time (UTC): $testStartTimeISO" -ForegroundColor Cyan

# Track created temp repos for cleanup
$createdRepos = @()

# ============================================================
# STEP 1: GENERATE MASS CLONE EVENTS
# ============================================================

if (-not $SkipEventGeneration) {
    Write-Host "`n--------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  STEP 1: Generate mass clone events ($CloneCount repos)" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------" -ForegroundColor Yellow

    # List available repos in the org using gh CLI (has repo scope)
    Write-Host "`n  Fetching repositories from org '$GitHubOrg'..." -ForegroundColor Cyan
    $repoListJson = gh repo list $GitHubOrg --limit 100 --json name,nameWithOwner,url 2>$null
    if ($LASTEXITCODE -eq 0 -and $repoListJson) {
        $repos = @($repoListJson | ConvertFrom-Json)
    } else {
        Write-Host "  [INFO] Cannot list org repos (may need admin:org scope). Will use user repos." -ForegroundColor DarkGray
        $repos = @()
    }

    $repoCount = $repos.Count
    if ($repoCount -lt $CloneCount) {
        $reposToCreate = $CloneCount - $repoCount
        Write-Host "  [INFO] Have $repoCount repos, need $CloneCount. Creating $reposToCreate temporary repos under '$ghCliUser' account." -ForegroundColor Yellow

        for ($i = 1; $i -le $reposToCreate; $i++) {
            $tempRepoName = "sentinel-test-clone-$(Get-Random -Maximum 99999)"
            $ghOutput = gh repo create "$tempRepoName" --private --add-readme 2>&1
            if ($LASTEXITCODE -eq 0) {
                $createdRepos += $tempRepoName
                Write-Host "    Created: $ghCliUser/$tempRepoName" -ForegroundColor DarkGray
            } else {
                Write-Host "    [WARN] Failed to create ${tempRepoName}: $ghOutput" -ForegroundColor Yellow
            }
        }

        # Wait for repos to be ready, then build list from user repos
        Start-Sleep -Seconds 3
        $userRepoJson = gh repo list $ghCliUser --limit 100 --json name,nameWithOwner,url 2>$null
        if ($userRepoJson) {
            $userRepos = @($userRepoJson | ConvertFrom-Json | Where-Object { $_.name -like "sentinel-test-clone-*" })
            $repos = @($repos) + @($userRepos)
        }
    }

    $reposToClone = @($repos | Select-Object -First $CloneCount)
    $cloneDir = Join-Path $env:TEMP "sentinel-mass-clone-test-$(Get-Random -Maximum 99999)"
    New-Item -ItemType Directory -Path $cloneDir -Force | Out-Null

    $cloneTotal = $reposToClone.Count
    Write-Host "`n  Cloning $cloneTotal repos (shallow, depth=1) to trigger git.clone audit events..." -ForegroundColor Cyan
    Write-Host "  Clone directory: $cloneDir" -ForegroundColor DarkGray

    $clonedCount = 0
    $clonedRepos = @()
    foreach ($repo in $reposToClone) {
        $repoFullName = $repo.nameWithOwner
        $destDir = Join-Path $cloneDir $repo.name

        try {
            # Use gh repo clone (uses gh CLI auth which has repo scope)
            gh repo clone $repoFullName $destDir -- --depth 1 --quiet 2>$null
            if ($LASTEXITCODE -eq 0) {
                $clonedCount++
                $clonedRepos += $repoFullName
                Write-Host "    [$clonedCount/$cloneTotal] [OK] $repoFullName" -ForegroundColor Green
            } else {
                Write-Host "    [$($clonedCount+1)/$cloneTotal] [FAIL] $repoFullName (exit code $LASTEXITCODE)" -ForegroundColor Red
            }
        } catch {
            Write-Host "    [$($clonedCount+1)/$cloneTotal] [FAIL] ${repoFullName}: $_" -ForegroundColor Red
        }

        # Small delay to avoid API rate limiting (but still within 1 hour window)
        Start-Sleep -Milliseconds 500
    }

    # Cleanup clone directory
    Remove-Item -Recurse -Force $cloneDir -ErrorAction SilentlyContinue

    Write-Host "`n  Clone summary:" -ForegroundColor Cyan
    Write-Host "    Actor:           $ghCliUser (gh CLI user)" -ForegroundColor White
    Write-Host "    Repos cloned:    $clonedCount / $cloneTotal" -ForegroundColor White
    Write-Host "    Threshold:       > 10 (rule triggers at 11+)" -ForegroundColor White

    if ($clonedCount -gt 10) {
        Write-Host "    Expected result: Should trigger alert" -ForegroundColor Red
    } else {
        Write-Host "    Expected result: Below threshold - alert will NOT trigger" -ForegroundColor Yellow
    }

    if ($clonedCount -le 10) {
        Write-Host "`n  [FAIL] Not enough repos cloned to trigger the detection rule. Need > 10." -ForegroundColor Red
        exit 1
    }

    # Clean up temp repos (created under user account via gh CLI)
    if ($createdRepos.Count -gt 0) {
        Write-Host "`n  Cleaning up $($createdRepos.Count) temporary test repos..." -ForegroundColor DarkGray
        $deleteFailCount = 0
        foreach ($tempRepo in $createdRepos) {
            $delOutput = gh repo delete "$ghCliUser/$tempRepo" --yes 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    Deleted: $ghCliUser/$tempRepo" -ForegroundColor DarkGray
            } else {
                $deleteFailCount++
            }
        }
        if ($deleteFailCount -gt 0) {
            Write-Host "    [WARN] Could not delete $deleteFailCount repos. Run to add scope:" -ForegroundColor Yellow
            Write-Host "      gh auth refresh -h github.com -s delete_repo" -ForegroundColor Yellow
            Write-Host "    Then delete manually:" -ForegroundColor Yellow
            Write-Host "      gh repo list $ghCliUser -L 100 --json name -q '.[].name' | Select-String 'sentinel-test-clone' | ForEach-Object { gh repo delete `"$ghCliUser/`$_`" --yes }" -ForegroundColor Yellow
        }
    }

    Write-Host "`n  Events generated. Pipeline latency:" -ForegroundColor Yellow
    Write-Host "    GHE -> Event Hub:         < 60 seconds" -ForegroundColor DarkGray
    Write-Host "    Event Hub -> Function:    < 30 seconds" -ForegroundColor DarkGray
    Write-Host "    Function -> Log Analytics:< 30 seconds" -ForegroundColor DarkGray
    Write-Host "    Sentinel rule frequency:  every 15 minutes" -ForegroundColor DarkGray
    Write-Host "    Expected total:           2-20 minutes" -ForegroundColor DarkGray

} else {
    Write-Host "`n  [SKIP] Skipping event generation (--SkipEventGeneration)" -ForegroundColor DarkGray
}


# ============================================================
# STEP 2: CHECK SENTINEL ALERT IS TRIGGERED
# ============================================================

if (-not $SkipSentinelCheck) {
    Write-Host "`n--------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  STEP 2: Verify Sentinel alert is triggered" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------" -ForegroundColor Yellow

    # First verify the analytics rule exists and is enabled
    Write-Host "`n  Checking analytics rule status..." -ForegroundColor Cyan
    $token = az account get-access-token --query accessToken -o tsv
    $rulesUri = "https://management.azure.com$WORKSPACE_RESOURCE_ID/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"

    try {
        $existingRules = Invoke-RestMethod -Uri $rulesUri -Headers @{ Authorization = "Bearer $token" }
        $massCloneRule = $existingRules.value | Where-Object { $_.properties.displayName -like "*Mass Clone*" }

        if ($massCloneRule) {
            $ruleEnabled = $massCloneRule.properties.enabled
            Write-Host "    Rule:      $($massCloneRule.properties.displayName)" -ForegroundColor White
            Write-Host "    Severity:  $($massCloneRule.properties.severity)" -ForegroundColor White
            if ($ruleEnabled) {
                Write-Host "    Enabled:   Yes" -ForegroundColor Green
            } else {
                Write-Host "    Enabled:   No" -ForegroundColor Red
            }
            Write-Host "    Frequency: $($massCloneRule.properties.queryFrequency)" -ForegroundColor White
            Write-Host "    Lookback:  $($massCloneRule.properties.queryPeriod)" -ForegroundColor White

            if (-not $ruleEnabled) {
                Write-Host "    [WARN] Rule is disabled! Enable it in Sentinel -> Analytics." -ForegroundColor Red
            }
        } else {
            Write-Host "    [FAIL] 'Mass Clone Detection' rule not found in Sentinel." -ForegroundColor Red
        }
    } catch {
        Write-Host "    [WARN] Could not query analytics rules: $_" -ForegroundColor Yellow
    }

    # Poll for the incident
    Write-Host "`n  Polling for Sentinel incident (max $MaxWaitMinutes min, every $PollIntervalSeconds sec)..." -ForegroundColor Cyan

    $incidentFound = $false
    $incidentDetails = $null
    $elapsed = 0

    while (-not $incidentFound -and $elapsed -lt ($MaxWaitMinutes * 60)) {
        $incidentKql = @"
SecurityIncident
| where TimeGenerated >= datetime('$testStartTimeISO')
| where Title has "Mass Clone"
| project TimeGenerated, IncidentNumber, Title, Severity, Status,
          Owner = tostring(Owner.assignedTo)
| sort by TimeGenerated desc
| take 1
"@

        try {
            $result = az monitor log-analytics query `
                --workspace $WORKSPACE_ID `
                --analytics-query $incidentKql `
                --timespan "PT2H" `
                -o json 2>$null | ConvertFrom-Json

            if ($result.tables[0].rows.Count -gt 0) {
                $incidentFound = $true
                $row = $result.tables[0].rows[0]
                $incidentDetails = @{
                    TimeGenerated  = $row[0]
                    IncidentNumber = $row[1]
                    Title          = $row[2]
                    Severity       = $row[3]
                    Status         = $row[4]
                    Owner          = $row[5]
                }

                Write-Host "`n  INCIDENT DETECTED!" -ForegroundColor Red
                Write-Host "    Time:     $($incidentDetails.TimeGenerated)" -ForegroundColor White
                Write-Host "    Number:   $($incidentDetails.IncidentNumber)" -ForegroundColor White
                Write-Host "    Title:    $($incidentDetails.Title)" -ForegroundColor White
                Write-Host "    Severity: $($incidentDetails.Severity)" -ForegroundColor White
                Write-Host "    Status:   $($incidentDetails.Status)" -ForegroundColor White
                Write-Host "`n  [OK] STEP 2 PASSED: Sentinel alert triggered successfully." -ForegroundColor Green
            }
        } catch {
            Write-Host "    [WARN] Query error (will retry): $_" -ForegroundColor Yellow
        }

        if (-not $incidentFound) {
            $remaining = $MaxWaitMinutes - [math]::Floor($elapsed / 60)
            Write-Host "    Waiting... no incident yet ($PollIntervalSeconds sec poll, ~$remaining min remaining)" -ForegroundColor DarkGray
            Start-Sleep -Seconds $PollIntervalSeconds
            $elapsed += $PollIntervalSeconds
        }
    }

    if (-not $incidentFound) {
        Write-Host "`n  [FAIL] STEP 2 FAILED: No Mass Clone Detection incident after $MaxWaitMinutes minutes." -ForegroundColor Red
        Write-Host "    Troubleshooting:" -ForegroundColor Yellow
        Write-Host "    1. Check if git.clone events are in GitHubAuditLog_CL table" -ForegroundColor Yellow
        Write-Host "    2. Verify the analytics rule is enabled" -ForegroundColor Yellow
        Write-Host "    3. Check the rule query manually in Log Analytics" -ForegroundColor Yellow

        # Run a diagnostic query
        Write-Host "`n  Diagnostic - recent git.clone events:" -ForegroundColor Cyan
        $diagKql = @"
GitHubAuditLog_CL
| where TimeGenerated >= ago(2h)
| where Action == "git.clone"
| summarize CloneCount = dcount(Repository), Repos = make_set(Repository, 10) by Actor
| sort by CloneCount desc
| take 5
"@
        try {
            $diagResult = az monitor log-analytics query `
                --workspace $WORKSPACE_ID `
                --analytics-query $diagKql `
                --timespan "PT2H" `
                -o table 2>$null
            Write-Host $diagResult
        } catch {
            Write-Host "    Could not run diagnostic query." -ForegroundColor Yellow
        }
    }

} else {
    Write-Host "`n  [SKIP] Skipping Sentinel check (--SkipSentinelCheck)" -ForegroundColor DarkGray
}


# ============================================================
# STEP 3: CHECK LOGIC APPS ARE TRIGGERED
# ============================================================

if (-not $SkipLogicAppCheck) {
    Write-Host "`n--------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  STEP 3: Verify Logic Apps are triggered" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------" -ForegroundColor Yellow

    $logicApps = @(
        @{ Name = "logic-ghec-teams-notify";    Description = "Teams Notification";  ExpectedFor = "All incidents" }
        @{ Name = "logic-ghec-enrich-incident"; Description = "Incident Enrichment"; ExpectedFor = "All incidents" }
        @{ Name = "logic-ghec-revoke-pat";      Description = "PAT Revocation";      ExpectedFor = "High severity only" }
    )

    $allLogicAppsTriggered = $true

    foreach ($la in $logicApps) {
        Write-Host "`n  $($la.Name) ($($la.Description))" -ForegroundColor Cyan
        Write-Host "    Expected trigger: $($la.ExpectedFor)" -ForegroundColor DarkGray

        try {
            $token = az account get-access-token --query accessToken -o tsv
            $RG_ID = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
            $runsUri = "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/$($la.Name)/runs?api-version=2016-06-01&`$top=5&`$filter=startTime ge $testStartTimeISO"

            $runs = Invoke-RestMethod -Uri $runsUri -Headers @{
                Authorization  = "Bearer $token"
                "Content-Type" = "application/json"
            }

            if ($runs.value.Count -gt 0) {
                $latestRun = $runs.value[0]
                $runStatus = $latestRun.properties.status
                $runStart = $latestRun.properties.startTime
                $runEnd = $latestRun.properties.endTime

                $statusLabel = switch ($runStatus) {
                    "Succeeded" { "[OK]" }
                    "Running"   { "[RUNNING]" }
                    "Failed"    { "[FAIL]" }
                    "Cancelled" { "[CANCELLED]" }
                    default     { "[UNKNOWN]" }
                }

                $statusColor = switch ($runStatus) {
                    "Succeeded" { "Green" }
                    "Failed"    { "Red" }
                    default     { "Yellow" }
                }

                Write-Host "    $statusLabel Status: $runStatus" -ForegroundColor $statusColor
                Write-Host "    Started: $runStart" -ForegroundColor White
                if ($runEnd) {
                    Write-Host "    Ended:   $runEnd" -ForegroundColor White
                }
                Write-Host "    Runs since test start: $($runs.value.Count)" -ForegroundColor White

                if ($runStatus -ne "Succeeded") {
                    $allLogicAppsTriggered = $false
                }
            } else {
                Write-Host "    [WARN] No runs found since test start." -ForegroundColor Yellow
                $allLogicAppsTriggered = $false
            }
        } catch {
            Write-Host "    [WARN] Could not check Logic App runs: $_" -ForegroundColor Yellow
            $allLogicAppsTriggered = $false
        }
    }

    # Check incident comments as secondary verification
    Write-Host "`n  Checking incident comments for Logic App confirmations..." -ForegroundColor Cyan

    $commentKql = @"
SecurityIncident
| where TimeGenerated >= datetime('$testStartTimeISO')
| where Title has "Mass Clone"
| take 1
| mv-expand Comment = Comments
| project CommentMessage = tostring(Comment.message), CommentTime = todatetime(Comment.createdTimeUtc)
| sort by CommentTime desc
"@

    try {
        $commentResult = az monitor log-analytics query `
            --workspace $WORKSPACE_ID `
            --analytics-query $commentKql `
            --timespan "PT2H" `
            -o json 2>$null | ConvertFrom-Json

        if ($commentResult.tables[0].rows.Count -gt 0) {
            foreach ($comment in $commentResult.tables[0].rows) {
                Write-Host "    Comment: $($comment[0]) ($($comment[1]))" -ForegroundColor White
            }
        } else {
            Write-Host "    No incident comments found yet." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    Could not query incident comments." -ForegroundColor Yellow
    }

    if ($allLogicAppsTriggered) {
        Write-Host "`n  [OK] STEP 3 PASSED: All Logic Apps triggered and succeeded." -ForegroundColor Green
    } else {
        Write-Host "`n  [WARN] STEP 3 PARTIAL: Some Logic Apps did not run or did not succeed." -ForegroundColor Yellow
    }

} else {
    Write-Host "`n  [SKIP] Skipping Logic App check (--SkipLogicAppCheck)" -ForegroundColor DarkGray
}


# ============================================================
# STEP 4: CHECK PAT IS REVOKED
# ============================================================

if (-not $SkipPATRevocationCheck) {
    Write-Host "`n--------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  STEP 4: Verify PAT is revoked" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------------" -ForegroundColor Yellow

    # Method 1: Check the revoke-pat Logic App's latest run actions
    Write-Host "`n  Checking logic-ghec-revoke-pat execution..." -ForegroundColor Cyan

    try {
        $token = az account get-access-token --query accessToken -o tsv
        $RG_ID = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $revokeRunsUri = "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/logic-ghec-revoke-pat/runs?api-version=2016-06-01&`$top=3&`$filter=startTime ge $testStartTimeISO"

        $revokeRuns = Invoke-RestMethod -Uri $revokeRunsUri -Headers @{
            Authorization  = "Bearer $token"
            "Content-Type" = "application/json"
        }

        if ($revokeRuns.value.Count -gt 0) {
            $latestRevokeRun = $revokeRuns.value[0]
            $revokeStatus = $latestRevokeRun.properties.status

            $revokeColor = if ($revokeStatus -eq "Succeeded") { "Green" } else { "Red" }
            Write-Host "    Logic App run status: $revokeStatus" -ForegroundColor $revokeColor

            if ($revokeStatus -eq "Succeeded") {
                # Check individual actions within the run
                $runName = $latestRevokeRun.name
                $actionsUri = "https://management.azure.com$RG_ID/providers/Microsoft.Logic/workflows/logic-ghec-revoke-pat/runs/$runName/actions?api-version=2016-06-01"
                $actions = Invoke-RestMethod -Uri $actionsUri -Headers @{
                    Authorization  = "Bearer $token"
                    "Content-Type" = "application/json"
                }

                foreach ($action in $actions.value) {
                    $actionName = $action.name
                    $actionStatus = $action.properties.status
                    $actionColor = if ($actionStatus -eq "Succeeded") { "White" } else { "Yellow" }
                    $actionLabel = if ($actionStatus -eq "Succeeded") { "[OK]" } elseif ($actionStatus -eq "Skipped") { "[SKIP]" } else { "[FAIL]" }
                    Write-Host "    $actionLabel Action '$actionName': $actionStatus" -ForegroundColor $actionColor
                }
            }
        } else {
            Write-Host "    [WARN] No revoke-pat Logic App runs found since test start." -ForegroundColor Yellow
            Write-Host "    Note: This Logic App only triggers for High severity incidents." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    [WARN] Could not check Logic App actions: $_" -ForegroundColor Yellow
    }

    # Method 2: Verify via GitHub API - check if the test PAT still works
    Write-Host "`n  Verifying PAT status via GitHub API..." -ForegroundColor Cyan
    try {
        $patCheck = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $ghHeaders -ErrorAction Stop
        Write-Host "    [WARN] PAT is still valid (user: $($patCheck.login))." -ForegroundColor Yellow
        Write-Host "    Note: The PAT used for this test may differ from the one revoked." -ForegroundColor DarkGray
        Write-Host "    The Logic App revokes PATs associated with the actor's Account entity." -ForegroundColor DarkGray
    } catch {
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Host "    [OK] PAT has been revoked (401 Unauthorized returned)." -ForegroundColor Green
        } else {
            Write-Host "    [WARN] Unexpected error checking PAT: $_" -ForegroundColor Yellow
        }
    }

    # Method 3: Check incident comment for revocation confirmation
    Write-Host "`n  Checking incident comments for revocation confirmation..." -ForegroundColor Cyan

    $revokeCommentKql = @"
SecurityIncident
| where TimeGenerated >= datetime('$testStartTimeISO')
| where Title has "Mass Clone"
| take 1
| mv-expand Comment = Comments
| where tostring(Comment.message) has "PAT" or tostring(Comment.message) has "revok"
| project CommentMessage = tostring(Comment.message), CommentTime = todatetime(Comment.createdTimeUtc)
| sort by CommentTime desc
"@

    try {
        $revokeComment = az monitor log-analytics query `
            --workspace $WORKSPACE_ID `
            --analytics-query $revokeCommentKql `
            --timespan "PT2H" `
            -o json 2>$null | ConvertFrom-Json

        if ($revokeComment.tables[0].rows.Count -gt 0) {
            $msg = $revokeComment.tables[0].rows[0][0]
            Write-Host "    Revocation comment: $msg" -ForegroundColor Green
            Write-Host "`n  [OK] STEP 4 PASSED: PAT revocation confirmed via incident comment." -ForegroundColor Green
        } else {
            Write-Host "    No PAT revocation comment found yet." -ForegroundColor Yellow
            Write-Host "`n  [WARN] STEP 4 INCONCLUSIVE: Could not verify PAT revocation from incident comments." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Could not query incident comments." -ForegroundColor Yellow
    }

} else {
    Write-Host "`n  [SKIP] Skipping PAT revocation check (--SkipPATRevocationCheck)" -ForegroundColor DarkGray
}


# ============================================================
# SUMMARY
# ============================================================

$testEndTime = [DateTime]::UtcNow
$testDuration = $testEndTime - $testStartTime

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host "  Test Complete -- Mass Clone Detection E2E Validation" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Duration:   $([math]::Round($testDuration.TotalMinutes, 1)) minutes" -ForegroundColor White
Write-Host "  Started:    $testStartTimeISO" -ForegroundColor White
Write-Host "  Ended:      $($testEndTime.ToString('o'))" -ForegroundColor White
Write-Host ""
Write-Host "  Portal links:" -ForegroundColor Cyan
Write-Host "    Sentinel:  https://security.microsoft.com/sentinel/" -ForegroundColor DarkGray
Write-Host "    Incidents: https://portal.azure.com/#blade/Microsoft_Azure_Security_Insights/IncidentsBlade" -ForegroundColor DarkGray
Write-Host ""
