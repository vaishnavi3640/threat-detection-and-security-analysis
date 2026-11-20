# WebShield Database (MySQL 8)

Database for the WebShield website security and privacy assessment tool.

## How to run
1. Open MySQL Workbench and connect to your local server.
2. Run `schema.sql` (creates the `webshield` database and 13 tables).
3. Run `seed.sql` (adds sample data from the frontend).
4. Optional: run `fix_guides.sql`, `views.sql` and `queries.sql`.

## Tables
| Table | Purpose |
|---|---|
| users | Registered users (passwords stored only as hashes) |
| workspaces | A user's workspace, for example Acme Studio |
| workspace_members | Links users to workspaces with a role |
| assets | Domains and IPs tracked in a workspace |
| scans | Each website scan, with score, status and an authorized flag |
| finding_templates | Reusable problem descriptions and fix guides |
| findings | Problems found in a scan (open or fixed) |
| incidents | Security incidents shown on the dashboard |
| trackers | Third-party trackers and the block-until-consent setting |
| tickets | Service desk tickets |
| risks | Risk register entries |
| notifications | Messages for the bell icon |
| user_settings | Notification and security preferences |

## Relationships
- users 1 - N workspaces
- users N - N workspaces (workspace_members)
- workspaces 1 - N assets, scans, incidents, trackers, tickets, risks
- scans 1 - N findings
- finding_templates 1 - N findings
- users 1 - N notifications
- users 1 - 1 user_settings

## Design rules
- Primary key on every table, foreign keys with ON DELETE rules.
- CHECK constraints: severity (Critical, High, Medium, Low), status values.
- scans.authorized records that the user confirmed permission to scan.
- Passwords are never stored in plain text.