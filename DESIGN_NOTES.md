# Design notes: Sentinel Access Lab

## 1. Why a simulation?

Real physical-access systems contain credentials, readers, controllers, doors, event logs, and an operator console. A fictional simulation allows safe practice with the monitoring and investigation workflow without accessing workplace hardware, employee records, or live credentials.

## 2. What is modeled?

- **Badges:** a simulated ID, fictional holder, role, and status (`active`, `suspended`, or `revoked`).
- **Doors:** a location, permitted roles, and mode (`normal` or `lockdown`).
- **Events:** a timestamp, badge, door, decision, explanation, scenario, and after-hours flag.
- **Cases:** a detection rule, severity, linked event evidence, status, and notes.
- **Audit:** administrative actions and their details.

SQLite persists these records between application restarts.

## 3. How does an access decision work?

For each fictional badge presentation, the server evaluates the rules in order:

1. Is the simulated door in lockdown?
2. Is the badge unknown?
3. Is the badge inactive, suspended, or revoked?
4. Is the badge's role permitted at the door?
5. Is this an after-hours test requiring the security role?
6. Otherwise, grant the simulated access request.

Each attempt creates an event record with an explicit result and reason. These rules are not a model of any specific employer's access policies.

## 4. Why separate events from cases?

A single denied attempt can be routine. A cluster of denials or a revoked-badge presentation can warrant investigation. The application therefore keeps raw events separate from higher-level cases and links evidence to each case. A case can be investigated, annotated, and resolved without deleting the underlying events.

## 5. Why simulated controls?

Badge status and door mode changes allow an analyst to see how administrative decisions affect later access requests. These changes are logged in the audit trail. No command reaches a real door or RFID device.

## 6. Why the local security boundaries?

The simulator binds to `127.0.0.1`, uses a locally generated administrator password, hashes the password, requires CSRF tokens for state-changing requests, throttles failed logins, and sets restrictive browser security headers. These measures are useful educational examples but do not make the app production-ready.

## 7. What would a future real-world integration require?

Only with organizational authorization: a documented, read-only vendor API or test controller; explicit access permissions; data minimization; privacy review; transport security; multi-user access controls; and a clear separation between observation and physical-door control. No real integration exists in this version.
