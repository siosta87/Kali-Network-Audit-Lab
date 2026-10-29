# Provisioning Simulation in Kali-Network-Audit-Lab

## Current repository status

This repository currently contains [user_provisioning_engine.py](user_provisioning_engine.py), a local onboarding simulation. Despite the repository name, it does not currently include Kali network-mapping commands, vulnerability scan results, or a network-audit report.

## What the script does

- Creates a simulated_linux_server directory in the current working directory
- Watches its hr_incoming subdirectory for CSV files
- Reads FirstName, LastName, and optional Department fields
- Generates usernames, mock account records, and local user directories
- Writes a provisioning audit log

It does not create real operating-system accounts, set real account permissions, or enforce password expiration.

## Run the simulation

Requires Python 3 with standard-library modules only. Use fictional records.

```console
python user_provisioning_engine.py
```

Place a CSV in simulated_linux_server/hr_incoming with this format:

```csv
FirstName,LastName,Department
Alex,Example,IT
```

Inspect the generated home folder, mock etc/passwd file, and var/log/provisioning_audit.log under simulated_linux_server. Press Ctrl+C to stop.

## Limitations to address

- Temporary passwords are currently printed and logged in plaintext. Treat them only as disposable simulation values.
- Password expiration and filesystem permissions are described in comments/log messages but are not enforced.
- Blank names and username collisions need stronger validation.
- Successfully processed CSV files are deleted by the script. Keep a separate copy of test input.
- No sample CSV file or automated tests are included.

## Missing network-audit deliverables

To present this as a Kali network-audit project, add the actual lab topology, authorized target scope, commands, scan evidence, findings, and remediation notes. Until then, the included code should be described as a provisioning simulation.
