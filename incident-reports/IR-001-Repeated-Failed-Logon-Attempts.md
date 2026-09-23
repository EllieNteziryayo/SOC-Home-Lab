# IR-001 — Repeated Failed Logon Attempts

## Incident Details

| Field | Details |
|---|---|
| Incident ID | IR-001 |
| Incident Type | Repeated Failed Authentication / Password Guessing |
| Severity | Medium |
| Status | Closed — Controlled Lab Simulation |
| Affected Host | SOC-WIN11 |
| Affected Account | SOC-Test |
| Detection Source | Splunk Enterprise / Windows Security Event Logs |
| Primary Event ID | 4625 |
| Date | September 19, 2026 |

## 1. Incident Summary

On September 19, 2026, repeated failed authentication attempts were detected against the local `SOC-Test` account on the Windows 11 endpoint `SOC-WIN11`.

Five Windows Security Event ID 4625 events were generated within approximately four seconds. The activity was detected by a scheduled Splunk alert configured to identify five or more failed logon attempts associated with the same account and host.

Investigation of the Windows Security events showed that the attempts were interactive logons using incorrect passwords. A subsequent search for successful Event ID 4624 logons associated with `SOC-Test` did not identify a successful authentication during the period reviewed.

The activity was intentionally generated as part of a controlled SOC home-lab exercise and did not represent an actual compromise.

## 2. Environment

| Component | Description |
|---|---|
| Endpoint | SOC-WIN11 |
| Operating System | Windows 11 Enterprise Evaluation |
| Test Account | SOC-Test |
| SIEM | Splunk Enterprise |
| Endpoint Telemetry | Windows Security Event Logs and Sysmon |
| Hypervisor | Oracle VirtualBox |

Windows Security and Sysmon events were collected from `SOC-WIN11` and ingested into Splunk for detection and investigation.

## 3. Detection

The activity was detected using Windows Security **Event ID 4625**, which records failed logon attempts.

The Splunk detection was configured to identify an account and computer with **five or more failed logons** within the detection window.

| Detection Result | Value |
|---|---|
| Failed Account | SOC-Test |
| Host | SOC-WIN11 |
| Failed Logins | 5 |
| First Attempt | September 19, 2026 at approximately 14:05:20 |
| Last Attempt | September 19, 2026 at approximately 14:05:24 |

A scheduled Splunk alert named **Repeated Failed Logins - Windows** evaluated the detection every five minutes and generated a **Medium-severity alert** after the threshold was met.

### Detection SPL

```spl
index=* source="WinEventLog:Security" EventCode=4625
| rex "(?ms)Account For Which Logon Failed.+?Account Name:\s+(?<Failed_Account>\V+)"
| stats count as Failed_Logins earliest(_time) as First_Attempt latest(_time) as Last_Attempt by Failed_Account ComputerName
| where Failed_Logins >= 5
| convert ctime(First_Attempt) ctime(Last_Attempt)
| sort - Failed_Logins
```

## 4. Investigation & Findings

The alert was investigated by reviewing the underlying Windows Security events in Splunk.

A representative Event ID 4625 showed:

| Field | Observed Value |
|---|---|
| Target Account | SOC-Test |
| Computer | SOC-WIN11 |
| Logon Type | 2 — Interactive |
| Failure Reason | Unknown user name or bad password |
| Status | 0xC000006D |
| Sub Status | 0xC000006A |
| Source Address | 127.0.0.1 |
| Workstation | SOC-WIN11 |
| Authentication Package | Negotiate |

The five failed authentication attempts occurred within approximately four seconds.

Logon Type 2 indicated that the activity was an interactive logon attempt. The source information also indicated that the attempts originated locally from `SOC-WIN11`.

A search for successful Event ID 4624 authentication events associated with `SOC-Test` did not return a successful logon during the period reviewed.

### Investigation Conclusion

The observed activity consisted of repeated incorrect-password attempts against the `SOC-Test` account. The available evidence did not indicate that the attempts resulted in a successful authentication.

Because this was a controlled lab exercise, the failed authentication activity was intentionally generated for detection and investigation purposes.

## 5. MITRE ATT&CK Mapping

| Category | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | Brute Force (T1110) |
| Sub-technique | Password Guessing (T1110.001) |

### Mapping Rationale

The observed activity maps to **T1110.001 — Password Guessing** because multiple password attempts were made against the `SOC-Test` account within a short period.

The repeated Event ID 4625 failures represent behavior consistent with password-guessing activity. In this lab, the activity was intentionally simulated to test detection and investigation capabilities.

## 6. Recommendations

- Monitor Windows Event ID 4625 for repeated authentication failures.
- Configure appropriate account-lockout policies.
- Use multi-factor authentication where applicable.
- Investigate the source system or IP address responsible for repeated failures.
- Review successful authentication events occurring shortly after repeated failures.
- Establish alert thresholds appropriate for the organization's normal authentication behavior.
- Escalate incidents when repeated failures are followed by successful authentication or other suspicious activity.

## 7. Incident Conclusion

The Splunk detection successfully identified five failed authentication attempts against `SOC-Test` on `SOC-WIN11` and generated a scheduled Medium-severity alert.

Analysis of the underlying Windows Security logs confirmed repeated incorrect-password attempts using an interactive logon. No successful `SOC-Test` authentication was identified during the period reviewed.

This exercise demonstrated the SOC workflow:

**Log Collection → Detection → Alerting → Investigation → MITRE ATT&CK Mapping → Incident Documentation**

The incident is considered **closed as a controlled lab simulation**.
