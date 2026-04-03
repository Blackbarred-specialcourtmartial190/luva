# Security policy

## Supported versions

Security fixes are applied to the **default branch** (`main` / `master`) of [cumakurt/luva](https://github.com/cumakurt/luva). Use the latest tagged release or `main` for production-style deployments.

## Reporting a vulnerability

**Luva is a passive, offline PCAP analyzer** — it does not open listening ports or perform active scanning by design. If you believe you have found a security defect (e.g. unsafe deserialization, path handling, or dependency issue), please **email the maintainer** rather than filing a public issue:

- **cumakurt@gmail.com**

Include a short description, steps to reproduce, and affected version/commit if possible. Allow a reasonable time for triage before public disclosure.

## Operational note

Only analyze captures you are authorized to handle. Outputs may contain sensitive host and protocol data; use `--anonymize-ips` and `--mask-payload` before sharing artifacts outside trust boundaries.
