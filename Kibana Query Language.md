

# **KQL Cheat Sheet for SOC Analysts**

_Search like a threat hunter. Filter like a pro. Think like an attacker._

---

## 1. **The Basics: Your First Few Spells**

```kql
event.code:4625
```

Finds failed login attempts (Event ID 4625). The go-to query to spot login trouble.

```kql
"svc-sql1"
```

Searches for the phrase _svc-sql1_ across **any field**.

---

## 2. **Boolean Logic: Combining Your Clues**

```kql
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
```

Failed logins from disabled accounts. You're already hunting smarter.

```kql
NOT location:"HR-Printer-01"
```

Ignore logs from that noisy HR printer everyone loves to hate.

```kql
user.name:admin AND (host.name:WKS1 OR host.name:WKS2)
```

Track admin activity on either WKS1 or WKS2.

---

## 3. **Time Travel: Working with Timestamps**

```kql
@timestamp >= "2024-12-01T00:00:00Z" AND @timestamp <= "2024-12-10T23:59:59Z"
```

Investigate logs between December 1st and 10th. Focus matters.

```kql
@timestamp >= now-30m
```

Look at the last 30 minutes only. For when something just hit the fan.

---

## 4. **Wildcards and Pattern Magic**

```kql
user.name: admin*
```

Grabs anything starting with “admin” – like admin1, admin_backup, etc.

```kql
command_line: "*Invoke-Mimikatz*"
```

Finds any PowerShell command invoking Mimikatz. Red flag alert.

```kql
host.name:*
```

Filters logs where `host.name` exists. Useful when a field might be empty.

---

## 5. **SOC Playbook: Hands-On Examples That Matter**

### Successful RDP Logins

```kql
event.code:4624 AND winlog.event_data.LogonType:10
```

That’s how you find interactive remote desktop sessions.

### Brute Force Attempt on Admin

```kql
event.code:4625 AND user.name:admin* AND @timestamp >= now-5m
```

Too many failures on admin accounts in the past 5 minutes? Time to act.

### Non-Domain Logons

```kql
event.code:4624 AND NOT user.domain:"CORP"
```

Who’s logging in from outside your corporate domain?

### After-Hours Logins

```kql
(event.code:4624 OR event.code:4625)
AND NOT (@timestamp >= "2024-12-01T08:00:00Z" AND @timestamp <= "2024-12-01T18:00:00Z")
```

Someone’s working late… or someone’s breaking in.

### Investigate a Single Workstation

```kql
host.name:"FINANCE-02" AND event.code:4625
```

See all failed logins on a specific workstation. Zero in.

### Suspicious PowerShell

```kql
process.name:"powershell.exe" AND command_line:*Invoke-WebRequest*
```

Classic lateral movement or data exfil attempt? Follow the breadcrumbs.

---

## 6. **Field Notes: Best Practices & Pro Tips**

- KQL is case-insensitive: `AND`, `Or`, `not` — all work.
    
- Always quote values with spaces: `user.full_name:"John Doe"`
    
- Use parentheses to group logic: `(A OR B) AND C`
    
- Wildcards (`*`) go only at the end: `admin*`, not `*admin`
    
- Check field presence with `field:*`
    
- Build layered queries using both static fields and dynamic time
    

---

## 7. **What is KQL and Why Should You Care?**

KQL (Kibana Query Language) is your direct line to Elasticsearch via Kibana. It’s fast, flexible, and purpose-built for logs. For a SOC analyst, it's the difference between hunting with a flashlight and scanning with infrared.

- Spot brute-force attacks
    
- Detect post-exploitation PowerShell usage
    
- Track suspicious logons and privilege escalations
    
- Analyze timelines with surgical precision
    

KQL doesn’t replace SIEM rules — it _enhances_ your speed during triage, investigations, and threat hunts.

---

## 8. **Quick Reference**

|Feature|Syntax|Use|
|---|---|---|
|Match value|`field:value`|Exact field match|
|Free text|`"term"`|Matches in any field|
|Wildcard|`admin*`|Matches anything starting with `admin`|
|Exists|`field:*`|Field has a value|
|Time filter|`@timestamp >= now-10m`|Time-bound search|
|Logical|`AND / OR / NOT`|Combine filters|
|Grouping|`(a OR b) AND c`|Prioritize conditions|

