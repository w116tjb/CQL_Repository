# TeamViewer Usage & Decommissioning Dashboard
## Implementation and Usage Guide

---

## 📋 Table of Contents
1. [Dashboard Overview](#dashboard-overview)
2. [Installation Instructions](#installation-instructions)
3. [Dashboard Sections](#dashboard-sections)
4. [Weekly Workflow](#weekly-workflow)
5. [Interactive Features](#interactive-features)
6. [Exporting Data](#exporting-data)
7. [Customization Options](#customization-options)
8. [Troubleshooting](#troubleshooting)

---

## Dashboard Overview

### Purpose
This dashboard provides comprehensive visibility into TeamViewer usage across your enterprise environment to support the migration to your new RMM solution. It distinguishes between systems that merely have TeamViewer installed versus those actively using it for remote access sessions.

### Key Capabilities
- **Real-time Monitoring**: Track active TeamViewer sessions with process and network correlation
- **Usage Analytics**: Daily, weekly, and trend analysis of TeamViewer activity
- **Installation vs. Usage**: Identify cleanup candidates (installed but not used)
- **User Outreach**: Generate prioritized lists for migration communications
- **Investigation Tools**: Deep-dive capabilities with RTR and Process Explorer integration

### Data Sources
- **ProcessRollup2**: TeamViewer process execution events
- **NetworkConnectIP4**: Network connection telemetry
- **DnsRequest**: DNS resolution to TeamViewer infrastructure

---

## Installation Instructions

### Step 1: Upload Dashboard to LogScale
1. **Access LogScale UI**: Log into your CrowdStrike Falcon LogScale instance
2. **Navigate to Dashboards**: Click on "Dashboards" in the left navigation
3. **Create New Dashboard**: Click "New Dashboard" → "Import from YAML"
4. **Upload File**: Paste the contents of `teamviewer_usage_dashboard.yaml` or upload the file
5. **Save**: Click "Save" to create the dashboard

### Step 2: Verify Data Availability
Before using the dashboard, ensure your environment is collecting the required telemetry:

```cql
// Test query - should return results
#event_simpleName=ProcessRollup2 
| FileName=/(teamviewer|tv_w32|tv_x64)\.exe/i
| groupBy([aid], limit=10)
```

If this returns no results, TeamViewer may not be actively used in your environment or process execution logging may need to be enabled.

### Step 3: Set Default Time Range
- Default time range: **7 days** (recommended for weekly reporting)
- Adjust via the time selector at the top of the dashboard
- For baseline analysis, consider extending to **30 days**

---

## Dashboard Sections

### 📊 Section 1: Executive Summary
**Purpose**: High-level metrics for leadership reporting

**Widgets**:
- **Active Hosts (7d)**: Count of systems with active TeamViewer sessions
- **Active Users (7d)**: Unique user count actively using TeamViewer
- **Total Connection Events**: Volume of TeamViewer network connections
- **Hosts by Usage Status**: Pie chart showing distribution (Active vs. Installed Only)
- **Activity Trend**: Hourly timeline of TeamViewer usage
- **Top 10 Users**: Bar chart of most active users

**Use Case**: Include these metrics in weekly status reports to track migration progress.

---

### 🔴 Section 2: Active TeamViewer Sessions
**Purpose**: Real-time visibility into current TeamViewer usage

**Widgets**:

1. **Active Sessions - Detailed View**
   - Shows systems with BOTH process execution AND network activity
   - Columns: Computer Name, User, Process Details, Connection Count, Timestamps
   - Links: RTR Console, Process Explorer (click to investigate)
   - **Color Coding**: 
     - 🔴 Red (50+ events): Heavy usage
     - 🟠 Orange (20-49 events): Moderate usage
     - 🟢 Green (<20 events): Light usage

2. **Network Connections (Inbound/Outbound)**
   - Direction indicators:
     - ⬇ **Inbound**: Remote user connecting TO this system
     - ⬆ **Outbound**: This system connecting TO remote system
   - Filters out internal network traffic (RFC1918 addresses)

3. **DNS Activity**
   - Shows DNS queries to TeamViewer infrastructure
   - Indicators of connection attempts even if full session didn't establish

**Use Case**: Daily monitoring of active usage; identify systems for immediate user outreach.

---

### 💾 Section 3: Installation vs. Active Usage Analysis
**Purpose**: Identify cleanup candidates and measure installation footprint

**Widgets**:

1. **Installation vs. Active Usage Comparison**
   - **Status Indicators**:
     - ✓ **Actively Used** (Green): Has network activity in timeframe
     - ⚠ **Installed Only** (Orange): Process exists but no network activity
     - ❌ **Unknown** (Red): Anomalous state
   - **Columns**: Status, Active Connections, Last Seen, Last Activity
   - **Color Coding**: Visual distinction between active vs. inactive

2. **Cleanup Candidates**
   - Systems with TeamViewer installed but NO network activity in 7 days
   - **Recommendation**: "✓ Safe to Remove"
   - **Action**: Use RTR links to initiate removal process
   - Export this list for batch cleanup operations

**Use Case**: 
- Prioritize systems for TeamViewer uninstallation
- Measure reduction in installation footprint over time
- Identify low-hanging fruit for quick wins

---

### 📅 Section 4: Weekly Usage Report
**Purpose**: Track migration progress and usage trends over time

**Widgets**:

1. **Daily Usage Summary (Last 7 Days)**
   - Metrics per day:
     - Active Hosts
     - Active Users
     - Unique Connections
     - **Usage Score**: Calculated metric (hosts × connections)
   - **Color Coding**:
     - 🔴 Red (>100 score): High usage day
     - 🟠 Orange (50-100 score): Moderate usage
     - 🟢 Green (<50 score): Low usage
   
2. **User Activity Distribution**
   - Bar chart showing top 20 users by activity count
   - Helps identify power users requiring priority migration support

**Use Case**: 
- Generate weekly trending reports for stakeholder updates
- Track week-over-week reduction in usage
- Identify if migration efforts are effective

---

### 🔍 Section 5: Investigation & Remediation Tools
**Purpose**: Deep-dive analysis and user outreach list generation

**Widgets**:

1. **Process Prevalence Analysis**
   - Shows TeamViewer executable variants found in environment
   - Columns: Filename, File Path, SHA256 Hash, Execution Count, Unique Endpoints
   - **Use Case**: Identify different TeamViewer versions requiring cleanup

2. **📧 User Outreach List**
   - **EXPORTABLE**: Primary list for weekly user communications
   - **Urgency Classification**:
     - 🔴 **High**: Frequent users (50+ sessions) - Priority outreach
     - 🟡 **Medium**: Regular users (20-49 sessions) - Standard outreach
     - 🟢 **Low**: Occasional users (<20 sessions) - Optional outreach
   - **Columns**: User Name, Computer, Session Count, Last Activity, Urgency
   - **Action**: Export → Email users → Track responses

**Use Case**: 
- Generate weekly contact list for migration communications
- Prioritize which users need immediate attention
- Track user engagement with migration efforts

---

## Weekly Workflow

### Monday Morning: Review & Report Generation
1. **Access Dashboard**: Open the TeamViewer Usage Dashboard
2. **Check Executive Summary**:
   - Note Active Hosts and Active Users metrics
   - Compare to previous week (manually for now, or screenshot comparison)
3. **Review Usage Trend**: Check if usage is declining week-over-week
4. **Export Weekly Report Data**: 
   - Navigate to "Weekly Usage Report" section
   - Click export icon on "Daily Usage Summary" table
   - Save as CSV: `TeamViewer_Weekly_Report_YYYY-MM-DD.csv`

### Monday Afternoon: User Outreach
1. **Generate Outreach List**:
   - Go to "Investigation & Remediation Tools" section
   - Export "User Outreach List" widget
   - Filter by urgency in Excel/CSV
2. **Send Communications**:
   - **High Priority** (🔴): Personal email with migration timeline
   - **Medium Priority** (🟡): Standard migration notification
   - **Low Priority** (🟢): Include in general communications
3. **Track Responses**: Use spreadsheet to mark users contacted

### Mid-Week: Active Session Monitoring
1. **Check Active Sessions** (Wednesday):
   - Review "Active TeamViewer Sessions - Detailed View"
   - Identify any new heavy users not in previous week's outreach
2. **Investigate Anomalies**:
   - Click RTR Console links for unusual activity
   - Use Process Explorer for deep-dive analysis

### Friday: Cleanup Operations
1. **Review Cleanup Candidates**:
   - Check "Cleanup Candidates" table
   - Verify systems have had no activity for 7+ days
2. **Initiate Removals**:
   - Use RTR Console links to connect to systems
   - Execute TeamViewer uninstallation commands
   - Document removals in tracking spreadsheet

### Monthly: Trend Analysis
1. **Compare Month-over-Month**:
   - Export 4 weeks of "Daily Usage Summary"
   - Create Excel chart showing usage decline
   - Include in monthly stakeholder presentation
2. **Adjust Strategy**:
   - If usage not declining: Increase outreach frequency
   - If usage declining rapidly: Plan final decommissioning date

---

## Interactive Features

### Time Selector
- **Location**: Top of dashboard
- **Default**: Last 7 days
- **Options**: Custom range, quick selects (24h, 7d, 30d, 90d)
- **Best Practice**: Keep at 7 days for consistent weekly reporting

### Parameter Filters

#### 1. Computer Name Filter
- **Type**: Query-based dropdown (autocomplete)
- **Usage**: Focus on specific host or hostname pattern
- **Example**: Filter to "LAPTOP-*" to see only laptops
- **Wildcard Support**: Use `*` for pattern matching

#### 2. User Name Filter
- **Type**: Query-based dropdown (autocomplete)
- **Usage**: Track specific user's activity
- **Example**: Filter to investigate "john.smith" after user inquiry
- **Best Practice**: Use for individual investigations, not weekly reports

#### 3. Usage Status Filter
- **Type**: Static dropdown
- **Options**:
  - **All**: Show everything (default)
  - **Active**: Only systems with network activity
  - **Installed Only**: Only systems without recent network activity
- **Use Case**: 
  - Select "Active" when reviewing current sessions
  - Select "Installed Only" when planning cleanup operations

### How to Use Filters Together
**Example Scenario**: Investigate user "Jane Doe" who reported TeamViewer issues

1. Set **User Name** = `jane.doe`
2. Set **Usage Status** = `Active`
3. Set **Time Range** = `Last 24 hours`
4. Review "Active Sessions - Detailed View" widget
5. Click **Process Explorer** link to see full process tree
6. Click **RTR Console** if live investigation needed

---

## Exporting Data

### Method 1: Widget-Level Export
1. **Hover** over any table widget
2. **Click** the three-dot menu (⋮) in top-right corner
3. **Select** "Download as CSV"
4. **Save** file for external analysis

### Method 2: Scheduled Reports (Recommended for Weekly Reports)
1. **Navigate** to "Scheduled Searches" in LogScale
2. **Create New** scheduled search
3. **Use Query** from "Daily Usage Summary" widget
4. **Schedule**: Every Monday at 8:00 AM
5. **Email**: Send CSV to distribution list
6. **Automation**: No manual export needed!

### Method 3: API Integration
For advanced users, query the LogScale API programmatically:
```bash
# Example using curl
curl -X POST https://YOUR-LOGSCALE-INSTANCE/api/v1/repositories/YOUR-REPO/query \
  -H "Authorization: Bearer YOUR-API-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "queryString": "YOUR QUERY HERE",
    "start": "7d",
    "end": "now"
  }'
```

### Recommended Exports for Weekly Reporting
1. **Executive Summary Metrics**: Screenshot of Section 1
2. **User Outreach List**: CSV from "Investigation Tools" section
3. **Daily Usage Summary**: CSV for trending analysis
4. **Cleanup Candidates**: CSV for planning removal operations

---

## Customization Options

### Adjusting Detection Logic

#### Include Additional TeamViewer Processes
If your environment uses different TeamViewer variants, modify the filename regex:

**Original**:
```cql
| FileName=/(teamviewer|tv_w32|tv_x64)\.exe/i
```

**Modified** (add TeamViewer Portable, etc.):
```cql
| FileName=/(teamviewer|tv_w32|tv_x64|teamviewer_portable|teamviewerqs)\.exe/i
```

#### Exclude Sanctioned IT Support Usage
If your IT support team legitimately uses TeamViewer, exclude them:

**Add After File Filter**:
```cql
| FileName=/(teamviewer|tv_w32|tv_x64)\.exe/i
| UserName!=/^(IT-Support|Admin-|SVC-)/i
```

#### Adjust Network Filter (Include/Exclude Subnets)
Currently excludes private networks. To include internal connections:

**Original**:
```cql
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
```

**Modified** (include internal):
```cql
// Remove the cidr filter line entirely
```

### Adjusting Thresholds

#### Change "High Usage" Threshold
Currently 50+ events = High. To change to 100:

**Find This**:
```cql
- color: '#C93637'
  condition:
    arg: 50
    type: GreaterThan
```

**Change To**:
```cql
- color: '#C93637'
  condition:
    arg: 100
    type: GreaterThan
```

#### Change Urgency Classifications
Currently:
- High: 50+ sessions
- Medium: 20-49 sessions
- Low: <20 sessions

**Find in "User Outreach List" query**:
```cql
| urgency:=case {
    sessionCount > 50 | "🔴 High - Frequent User";
    sessionCount > 20 | "🟡 Medium - Regular User";
    * | "🟢 Low - Occasional User";
}
```

**Modify Values**:
```cql
| urgency:=case {
    sessionCount > 100 | "🔴 High - Frequent User";
    sessionCount > 30 | "🟡 Medium - Regular User";
    * | "🟢 Low - Occasional User";
}
```

### Adding Custom Widgets

#### Example: Add "TeamViewer by Department" Widget
If you have department information in your asset data:

```yaml
widget-by-department:
  x: 0
  y: 10
  height: 4
  width: 6
  type: query
  title: "TeamViewer Usage by Department"
  queryString: |
    #event_simpleName=/^(ProcessRollup2|NetworkConnectIP4)$/
    | FileName=/(teamviewer|tv_w32|tv_x64)\.exe/i
    | falconPID:=TargetProcessId | falconPID:=ContextProcessId
    | selfJoinFilter(field=[aid, falconPID], where=[
        {#event_simpleName=ProcessRollup2},
        {#event_simpleName=NetworkConnectIP4}
      ])
    // Join with asset data to get department
    | join({
        readFile([asset_inventory.csv])
      }, field=aid, include=[Department])
    | groupBy([Department], function=count(aid, distinct=true, as=activeHosts))
    | sort(activeHosts, order=desc)
  visualization: bar-chart
  isLive: false
```

**To Add**:
1. Edit dashboard YAML
2. Add widget definition under `widgets:` section
3. Add widget ID to appropriate section under `widgetIds:` array
4. Re-import dashboard

---

## Troubleshooting

### Issue 1: No Data Showing in Dashboard

**Symptoms**: All widgets show "No data available"

**Troubleshooting Steps**:
1. **Verify Base Telemetry**:
   ```cql
   #event_simpleName=ProcessRollup2 
   | FileName=*
   | groupBy([aid], limit=10)
   ```
   - If no results: ProcessRollup2 events not being ingested
   
2. **Check Time Range**: Ensure time selector is set to appropriate range (7d recommended)

3. **Verify TeamViewer Presence**:
   ```cql
   #event_simpleName=ProcessRollup2 
   | FileName=/teamviewer/i
   | groupBy([FileName])
   ```
   - If no results: TeamViewer not running in environment during time range

4. **Check Repository Permissions**: Ensure your user has read access to the repository

**Resolution**: 
- If ProcessRollup2 not available: Contact CrowdStrike support to enable process telemetry
- If no TeamViewer found: Good news - usage may already be low!

---

### Issue 2: Widgets Load Slowly

**Symptoms**: Dashboard takes >30 seconds to load

**Causes**:
- Large environment (10k+ endpoints)
- Extended time range (30+ days)
- Complex join operations

**Solutions**:
1. **Reduce Time Range**: Use 7 days instead of 30 days
2. **Apply Filters**: Use Computer Name or User Name filters to scope results
3. **Optimize Queries**: Add `limit=max` is already present; consider adding host count limits:
   ```cql
   | groupBy([aid], limit=1000)  // Limit to top 1000 hosts
   ```

---

### Issue 3: "Active Sessions" Widget Shows Too Many/Few Results

**Symptoms**: Results don't match expected TeamViewer usage

**Diagnosis**:
- **Too Many Results**: May include processes that executed but didn't create network connections
- **Too Few Results**: May be missing legitimate sessions due to restrictive filters

**Tuning**:

**To Reduce False Positives** (too many):
```cql
// Add minimum connection threshold
| test(uniqueRemoteIPs > 1)  // Require at least 2 unique remote IPs
```

**To Increase Sensitivity** (too few):
```cql
// Remove external-only filter to include internal connections
// Comment out or remove this line:
// | !cidr(RemoteAddressIP4, subnet=[...])
```

---

### Issue 4: RTR or Process Explorer Links Don't Work

**Symptoms**: Clicking investigation links results in errors

**Causes**:
- Incorrect Falcon instance URL in link format
- Missing permissions for RTR or Process Explorer

**Resolution**:
1. **Verify Falcon Instance**: Check if your Falcon instance is at a different URL
   - Current: `falcon.crowdstrike.com`
   - EU: `falcon.eu-1.crowdstrike.com`
   - GOV: `falcon.us-2.crowdstrike.com`

2. **Update Link Format** in YAML:
   ```yaml
   # Find this line in queries:
   | RTR:=format("[RTR Console](https://falcon.crowdstrike.com/activity/real-time-response/console/?aid=%s)", field=[aid])
   
   # Change to your instance:
   | RTR:=format("[RTR Console](https://falcon.eu-1.crowdstrike.com/activity/real-time-response/console/?aid=%s)", field=[aid])
   ```

3. **Check Permissions**: Ensure your user role has:
   - RTR permissions (Active Responder or higher)
   - Process Explorer access

---

### Issue 5: User Outreach List Missing Users

**Symptoms**: Known TeamViewer users not appearing in outreach list

**Diagnosis**:
- Query only shows users with BOTH process execution AND network activity in timeframe
- User may have used TeamViewer outside of selected time range

**Resolution**:
1. **Extend Time Range**: Change from 7 days to 14 or 30 days
2. **Check Installation vs. Usage**: User may appear in "Cleanup Candidates" if no recent network activity
3. **Run Manual Query**:
   ```cql
   #event_simpleName=ProcessRollup2
   | UserName="specific.user@domain.com"
   | FileName=/teamviewer/i
   | table([@timestamp, ComputerName, FileName])
   ```

---

## Advanced Usage Scenarios

### Scenario 1: Compliance Audit
**Question**: "Do we have any TeamViewer running on PCI/HIPAA systems?"

**Approach**:
1. Create asset lookup file with compliance zones
2. Modify query to join with asset data:
   ```cql
   | join({readFile([compliance_zones.csv])}, field=aid, include=[ComplianceZone])
   | ComplianceZone=/(PCI|HIPAA)/
   ```

### Scenario 2: License Cost Tracking
**Question**: "How many TeamViewer licenses do we actually need?"

**Approach**:
1. Use "Installation vs. Active Usage" widget
2. Count systems in "Actively Used" status
3. Add buffer (e.g., 10%) for IT support
4. **Result**: Potential license reduction from total installations to active usage count

### Scenario 3: Security Incident Investigation
**Question**: "Was TeamViewer used during the incident timeframe?"

**Approach**:
1. Set time range to incident window (e.g., 2024-12-15 14:00 to 16:00)
2. Apply Computer Name filter to affected systems
3. Review "Active Sessions - Detailed View"
4. Check "Network Connections" for inbound sessions (potential lateral movement)
5. Use Process Explorer links to examine process tree

### Scenario 4: Migration Success Metrics
**Question**: "How much progress have we made this quarter?"

**Approach**:
1. Export "Daily Usage Summary" for each week of the quarter
2. Create Excel chart:
   - X-axis: Week number
   - Y-axis 1: Active Hosts (declining trend expected)
   - Y-axis 2: Usage Score (declining trend expected)
3. Calculate percentage reduction:
   - Week 1 active hosts: 450
   - Week 12 active hosts: 120
   - **Reduction**: 73% decrease in active usage

---

## Support and Resources

### Getting Help
- **CrowdStrike Support**: For telemetry collection issues
- **LogScale Documentation**: https://library.humio.com
- **Community Forums**: Falcon Community Portal

### Query Optimization Resources
- **Best Practices**: See `/mnt/project/Query_Writing_Best_Practices___Training___LogScale_Documentation.pdf`
- **CQL Reference**: See `/mnt/project/CrowdStrike_Query_Language_Defined___Training___LogScale_Documentation.pdf`

### Dashboard Updates
This dashboard will need periodic maintenance:
- **TeamViewer Updates**: New executables may require filename regex updates
- **Network Changes**: Subnet exclusions may need adjustment
- **Process Refinement**: Thresholds may need tuning based on usage patterns

---

## Appendix: Sample Email Templates

### Template 1: High Priority User (🔴)
**Subject**: Action Required: TeamViewer Migration - Switch to [New RMM Tool]

```
Hi [User Name],

Our records show you're an active TeamViewer user with [X] remote sessions in the past week. As part of our enterprise migration to [New RMM Tool], we need your help transitioning away from TeamViewer.

**What You Need to Do:**
1. Install [New RMM Tool] from the Software Center by [Date]
2. Attend brief training session: [Webinar Link]
3. We'll remove TeamViewer from your system on [Date]

**Why We're Changing:**
- Better security and compliance
- Improved performance and reliability
- Centralized support and management

**Need Help?**
Contact IT Support: [Contact Info]

Thank you,
IT Team
```

### Template 2: Medium Priority User (🟡)
**Subject**: TeamViewer Sunset - Migrate to [New RMM Tool]

```
Hi [User Name],

We're migrating from TeamViewer to [New RMM Tool]. You're registered as an occasional TeamViewer user, so we wanted to make sure you have the new tool before we complete the decommissioning.

**Action Items:**
- Install [New RMM Tool]: [Software Center Link]
- Optional training: [Self-service Guide]
- TeamViewer removal date: [Date]

Questions? Contact IT Support.

Best regards,
IT Team
```

### Template 3: Cleanup Notification (Automated)
**Subject**: TeamViewer Removal Notice - No Recent Activity Detected

```
Hi [User Name],

Our monitoring shows TeamViewer is installed on your system ([Computer Name]) but hasn't been used in the past 30 days.

To reduce security risk and improve system performance, we'll remove TeamViewer on [Date + 7 days].

**If You Still Need Remote Access:**
Install [New RMM Tool]: [Link]

**No Action Required If:**
You don't use remote access tools

This is an automated notification. Reply if you have questions.

IT Team
```

---

## Changelog

### Version 1.0 (Current)
- Initial dashboard release
- 5 main sections with 15+ widgets
- Interactive filtering by computer, user, and usage status
- Export capabilities for all table widgets
- RTR and Process Explorer integration

### Planned Enhancements (Future)
- Automated email notifications for high-usage users
- Integration with CMDB for department-level tracking
- Predictive analytics for migration timeline estimation
- Geographic distribution heat map (if multi-region deployment)

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-03  
**Dashboard File**: `teamviewer_usage_dashboard.yaml`  
**Compatibility**: CrowdStrike Falcon LogScale (Humio) v1.140+
