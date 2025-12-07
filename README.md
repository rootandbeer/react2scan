# React2Shell Detection Scanner — Overview
## Purpose

This script is a lightweight proof‑of‑concept scanner designed to help vulnerability management teams identify systems potentially affected by React2Shell‑related error handling issues (referenced as CVE‑2025‑55182 / CVE‑2025‑66478).
Its focus is detection only — it does not exploit, modify, or interact beyond a basic malformed request probe.

## How It Works

The scanner sends a deliberately malformed multipart form submission with a valid browser boundary.
If the target responds with a 500 failure containing a specific error signature, the script flags it as potentially vulnerable.

Different responses produce different classifications:

“VULNERABLE” — expected error pattern observed

“UNKNOWN 500” — server errored, but without matching signature

“Not Vulnerable” — target either rejects request gracefully or produces other HTTP outcomes

This avoids interaction beyond error‑condition observation — no code execution, state modification, or exploitation is attempted.

## Input Modes Supported

The scanner supports multiple scanning workflows:

1. Single Host Scanning
./react2shell_scan.sh 10.0.1.20 -p 3000

2. CIDR /24 Subnet Expansion
./react2shell_scan.sh 172.18.1.0/24 -p 8443


The script auto‑iterates from .1 through .254.

3. IP Range Expansion
./react2shell_scan.sh 192.168.1.10-50 -p 3000

4. File‑based Bulk Scanning

(One IP per line)

## Usage

./react2shell_scan.sh -f targets.txt -p 3000

```shell
$ bash ./react2scan.sh
[*] React2Shell Detection Probe (CVE‑2025‑55182 / CVE‑2025‑66478)

[*] Port: 8443

Usage:
  ./react2shell_scan.sh host
  ./react2shell_scan.sh 192.168.1.0/24
  ./react2shell_scan.sh ips.txt
  Optional: -p <port>
```
