# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub Security Advisories on this repository: Security tab, then "Report a vulnerability". Do not open public issues for security reports. A `security.txt` file at https://drive.mysignet.ca/.well-known/security.txt carries the same routing.

We respond within 7 days. We coordinate disclosure within 90 days of a confirmed report. If a fix requires longer, we agree on a timeline with the reporter before the 90 days elapse.


## Scope

In scope: the code in this repository, the operated service at drive.mysignet.ca including its server side, released `signet` binaries, the web client, the transparency log, and the verification tooling.

Out of scope: denial of service against the operated service, social engineering, spam, and findings that require a previously compromised user device.


## Advisory baseline

Dependency audits run against a documented ignore list at `.cargo/audit.toml`; each entry carries its rationale and a reproducible verification. A green audit means green against that baseline, not the absence of known advisories.


## Safe harbor

PRSN EX Inc. does not pursue legal action for good-faith security research within the scope above. Use test accounts. Do not access, modify, or retain other users' data. Stop and report if you encounter user data unexpectedly.


## Recognition

Valid reports are credited in release notes when the reporter wishes. There is no paid bounty program at this time.
