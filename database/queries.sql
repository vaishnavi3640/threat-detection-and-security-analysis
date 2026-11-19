USE webshield;

-- History page
SELECT url, score, status, started_at FROM scans
WHERE workspace_id = 1 ORDER BY started_at DESC;

-- Weaknesses page: open findings of a scan
SELECT t.title, t.severity, t.category, t.owasp_code, t.description
FROM findings f JOIN finding_templates t ON t.id = f.template_id
WHERE f.scan_id = 1 AND f.status = 'open';

-- Sidebar badge: number of open findings
SELECT COUNT(*) AS open_findings FROM findings
WHERE scan_id = 1 AND status = 'open';

-- Legend: open findings per severity
SELECT t.severity, COUNT(*) AS total FROM findings f
JOIN finding_templates t ON t.id = f.template_id
WHERE f.scan_id = 1 AND f.status = 'open' GROUP BY t.severity;

-- Mark a finding as fixed
UPDATE findings SET status = 'fixed', fixed_at = NOW() WHERE id = 1;

-- Dashboard: open incidents
SELECT `type`, severity, occurred_at FROM incidents
WHERE workspace_id = 1 AND status = 'open';