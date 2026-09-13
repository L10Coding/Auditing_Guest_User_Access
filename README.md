# Auditing_Guest_User_Access

# Guest User Access Auditor
### Microsoft Entra ID | PowerShell | Microsoft Graph API

# Description
Automatically audits every guest user in a Microsoft Entra ID tenant identifying who was invited, when they last signed in, and whether their access is still justified. Flags stale and inactive accounts that represent unnecessary security risk and exports a prioritized remediation report.

## Executive Summary

**Problem:** Organizations invite external users — vendors, contractors, partners — 
and have no automated way to track whether those accounts are still active or 
still needed. Guest accounts accumulate over time creating a growing attack surface 
that nobody is watching.

**Solution:** This script provides automated, repeatable guest access auditing 
with four risk classifications. It identifies who has never signed in, who has 
gone inactive, and generates audit evidence — all in a single run.

**Result:** Complete visibility into guest access posture in under 5 minutes 
with a prioritized report showing exactly which accounts need immediate review.

**Time to value:** Under 5 minutes from first run to actionable report.

### Why Guest Accounts Are High Risk
Guest accounts are one of the most overlooked attack surfaces in Microsoft 365:
- Vendors and contractors leave but their accounts stay active
- Nobody tracks when a guest last signed in
- IT has no visibility without manual portal checks
- Compliance audits flag unreviewed guest access as a finding
- A compromised guest account can pivot into internal resources

### What This Script Delivers
- Complete guest access inventory in under 5 minutes
- Automatic classification by risk level — no manual review needed
- Timestamped CSV report for compliance evidence
- Recurring capability — run weekly to maintain continuous visibility

**Step 1 — Connected to Microsoft Graph**
- Connected to Entra ID tenant using two scopes
- User.Read.All — permission to read all user accounts including guest accounts
- AuditLog.Read.All — permission to read sign-in activity per user
- Without AuditLog.Read.All the SignInActivity property returns empty for every user
```powershell
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All" -NoWelcome
```
**Step 2 — Pulled all guest users only using server-side filter**
- Used OData -Filter "userType eq 'Guest'" to pull only guest accounts directly from Graph
- Server-side filtering is more efficient than pulling all 102 users and filtering locally
- -All flag ensures every guest is returned not just the first page of results
- SignInActivity property contains LastSignInDateTime — when the guest last signed in
- CreatedDateTime — when the guest account was created in the tenant
- $today captured once before the loop so every calculation uses the same reference point
```powershell
$guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity,AccountEnabled,Mail"
$today  = Get-Date
```
**Step 3 — Created empty results list**
- Created empty list to collect flagged guest accounts as the scan runs
- Only inactive and stale guests get added — active guests are skipped
```powershell
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
```
**Step 4 — Calculated days since invite and days since last sign-in**
- $daysSinceInvite — subtracts invite date from today to get how long the guest has had access
- $lastSignIn — pulls the last sign-in date from the SignInActivity nested object
- $daysSinceSignIn — calculates days since last sign-in using inline if
- If $lastSignIn is null the guest has never signed in — sentinel value 999 is assigned
- 999 is used because it is larger than any real threshold so it always gets flagged correctly
- [int] drops the decimal from .TotalDays to give a clean whole number
```powershell
$daysSinceInvite = [int]($today - $guest.CreatedDateTime).TotalDays
$lastSignIn      = $guest.SignInActivity.LastSignInDateTime
$daysSinceSignIn = if ($lastSignIn) { [int]($today - $lastSignIn).TotalDays } else { 999 }
```
**Step 5 — Classified each guest by risk level**
- Four classifications checked in priority order
- First checks for never signed in AND invited more than 30 days ago — -and requires both conditions true
- A guest invited yesterday who hasn't signed in yet is not stale — the 30 day buffer prevents false positives
- Then checks days since last sign-in against 90 and 30 day thresholds
- Anything else is classified as Active — no action needed
- Thresholds checked largest first so 90+ days is caught before 30+ days
```powershell
$status = if (-not $lastSignIn -and $daysSinceInvite -gt 30) { "Stale - Never Used" }
          elseif ($daysSinceSignIn -gt 90)                    { "Inactive 90+" }
          elseif ($daysSinceSignIn -gt 30)                    { "Inactive 30+" }
          else                                                 { "Active" }
```
**Step 6 — Skipped active guests**
- continue skips the rest of the current loop iteration and moves to the next guest
- Active guests never get printed or added to results
- Only flagged guests proceed past this point
```powershell
if ($status -eq "Active") { continue }
```
**Step 7 — Set color based on status**
- Inline if assigns a console color matching the urgency of each status
- Red for stale never used — highest risk
- Yellow for 90+ days inactive — high risk
- Cyan for 30+ days inactive — medium risk
```powershell
$color = if ($status -eq "Stale - Never Used") { "Red" }
         elseif ($status -eq "Inactive 90+")    { "Yellow" }
         elseif ($status -eq "Inactive 30+")    { "Cyan" }
         else                                    { "Green" }
```
**Step 8 — Printed flagged guest details**
- Printed one color coded line per flagged guest
- $(if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }) — inline if inside subexpression handles the null date case cleanly
- Single quotes used inside because the outer string already uses double quotes — avoids quote conflicts
- -ForegroundColor $color uses the color variable set in the previous step
```powershell
Write-Host "Guest: $($guest.DisplayName) | Invited: $daysSinceInvite days ago | Last Sign In: $(if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }) | Status: $status" -ForegroundColor $color
```
**Step 9 — Added flagged guest to results list**
- Built a custom object with seven properties per guest
- Inline if on LastSignInDate — formats date if it exists saves "Never" if null
- Inline if on DaysSinceSignIn — converts sentinel value 999 to readable "Never signed in"
- CreatedDateTime.ToString("yyyy-MM-dd") formats the invite date cleanly for the CSV
```powershell
$results.Add([PSCustomObject]@{
    DisplayName     = $guest.DisplayName
    Mail            = $guest.Mail
    CreatedDate     = $guest.CreatedDateTime.ToString("yyyy-MM-dd")
    DaysSinceInvite = $daysSinceInvite
    LastSignInDate  = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
    DaysSinceSignIn = if ($daysSinceSignIn -eq 999) { "Never signed in" } else { $daysSinceSignIn }
    Status          = $status
})
```
**Step 10 — Exported flagged guests to CSV**
- Exported all flagged guests to GuestAudit_Report.csv on Desktop
- -NoTypeInformation removes the ugly header line PowerShell adds by default
- Report includes all seven properties — DisplayName, Mail, CreatedDate, DaysSinceInvite, LastSignInDate, DaysSinceSignIn, Status
```powershell
$results | Export-Csv -Path "$HOME/Desktop/GuestAudit_Report.csv" -NoTypeInformation
```
**Step 11 — Calculated summary counts**
- Filtered results by each status using Where-Object and counted with .Count
- Active count calculated by subtracting all flagged counts from total guest count
- Active guests were skipped in the loop so they are not in $results — math handles this
```powershell
$staleNeverUsed = ($results | Where-Object Status -eq "Stale - Never Used").Count
$inactive90     = ($results | Where-Object Status -eq "Inactive 90+").Count
$inactive30     = ($results | Where-Object Status -eq "Inactive 30+").Count
$active         = $guests.Count - $staleNeverUsed - $inactive90 - $inactive30
```
**Step 12 — Printed formatted summary**
- Printed clean summary box showing full guest access posture at a glance
- Green for active, red for stale, yellow for 90+ inactive, cyan for 30+ inactive
```powershell
Write-Host "  Total guests found : $($guests.Count)"
Write-Host "  Active             : $active"
Write-Host "  Stale - Never Used : $staleNeverUsed"
Write-Host "  Inactive 90+       : $inactive90"
Write-Host "  Inactive 30+       : $inactive30"
```
# Results from printed results in PowerShell

<img width="682" height="306" alt="Screenshot 2026-08-25 at 21 20 02" src="https://github.com/user-attachments/assets/659d402a-50f4-46f9-bf54-0fb990997a38" />

# Results from CSV file created - GuestAudit_Report.csv

<img width="808" height="149" alt="Screenshot 2026-08-25 at 21 20 19" src="https://github.com/user-attachments/assets/e5780995-17bd-46df-82f5-0b6b63562986" />
