# Sigma Detection Engineering Lab - SigHunt (challenge)

## Overview

This project documents my hands-on work with Sigma rules in the TryHackMe **SigHunt** room. I reviewed Windows attack logs, selected useful fields, wrote detection conditions, and tested the rules with the room's Sigma validator.

**Lab source:** [TryHackMe — SigHunt](https://tryhackme.com/room/sighunt)

This is an educational project. It is not a production-ready detection pack.

## Quick Reference

| Rule | Log evidence | Detection idea | Rule |
|---|---|---|---|
| Malicious mshta | Sysmon Event 1 | mshta.exe started by Chrome | [View YAML](rules/malicious-mshta.yml) |
| Certutil Download | Sysmon Event 1 | certutil.exe with `-urlcache` | [View YAML](rules/certutil-download.yml) |
| Netcat Execution | Sysmon Event 1 | nc.exe with `cmd.exe` | [View YAML](rules/netcat-execution.yml) |
| PowerUp Enumeration | Sysmon Event 1 | PowerShell with `downloadstring` | [View YAML](rules/powerup-enumeration.yml) |
| Service Binary Modification | Sysmon Event 1 | sc.exe with `cmd.exe` | [View YAML](rules/service-binary-modification.yml) |
| RunOnce Persistence | Sysmon Event 1 | reg.exe with `cmdd.exe` | [View YAML](rules/runonce-persistence.yml) |
| 7z Archive Collection | Sysmon Event 1 | 7z.exe with `exfil` | [View YAML](rules/archive-collection.yml) |
| cURL Data Exfiltration | Sysmon Event 1 | curl.exe with `-d` | [View YAML](rules/curl-exfiltration.yml) |
| Ransomware File Encryption | Sysmon Event 11 | TargetFilename contains `Finance` | [View YAML](rules/ransomware-encryption.yml) |

## Tools and Data

- Sigma detection syntax (YAML)
- Windows Sysmon process creation and file creation events
- Attack logs provided by the SigHunt challenge
- SigHunt Sigma Rule Validator

## How I Worked

1. Read each attack log and identify suspicious activity.
2. Check which event fields are available in the validator.
3. Choose fields such as `EventID`, `Image`, `ParentImage`, `CommandLine`, or `TargetFilename`.
4. Write a `selection` with Sigma operators such as `endswith` and `contains`.
5. Validate the rule and adjust it when needed.

### Example: Malicious mshta

The attack log showed `mshta.exe` running with `chrome.exe` as its parent process. I used process creation Event ID 1 and checked the two process names instead of relying on the full paths.

```yaml
detection:
  selection:
    EventID: 1
    Image|endswith: 'mshta.exe'
    ParentImage|endswith: 'chrome.exe'
  condition: selection
```

## Validation Results

In my saved SigHunt screenshots, each of the nine challenge detections reached **100% in the lab validator**. The displayed per-rule result was **1/1 true positive, 0 false positives, and 0 false negatives**. I also completed the room.

These scores describe the limited test events in the room. They do **not** prove that the same rules will produce zero false positives on real endpoints or generalize to other attacks.

**Publication note:** Most YAML files preserve the detection logic shown in my screenshots and add minimal Sigma metadata. The Netcat screenshot cuts off the hash used in the validated rule; the public Netcat YAML omits that hash and is a simplified adaptation, **not an exact reproduction of the validated rule**.

## Limitations and Improvements

- Some detections use broad strings, such as `downloadstring` or the `-d` argument in curl.
- Some detections are specific to the lab, such as `exfil` in an archive name and `Finance` in a filename.
- The RunOnce rule in my screenshots used `cmdd.exe` and does not check the RunOnce registry path. The screenshot value is preserved in the YAML.
- My next step is to add more useful conditions, compare with normal activity, and test against larger datasets.
- A real deployment would need review of the log field mapping and Sigma conversion for its SIEM backend.

## What I Learned

At the beginning, Sigma syntax was difficult for me. I used ChatGPT to understand my first rule. After that, I understood the main structure and wrote the next rules myself.

This room was a useful introduction to Sigma, but most rules were simple. They mainly used one `selection` with a few fields, without advanced filters or correlation. I want to practice more complex rules in future labs.

## Reference

- [Sigma documentation](https://sigmahq.io/docs/)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
