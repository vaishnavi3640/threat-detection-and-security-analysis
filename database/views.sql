USE webshield;

CREATE OR REPLACE VIEW v_open_findings AS
SELECT f.id AS finding_id, f.scan_id, t.title, t.severity, t.category, t.owasp_code
FROM findings f
JOIN finding_templates t ON t.id = f.template_id
WHERE f.status = 'open';

CREATE OR REPLACE VIEW v_scan_summary AS
SELECT s.id, s.url, s.score, s.status,
       COUNT(f.id) AS total_findings,
       SUM(f.status = 'open') AS open_findings
FROM scans s
LEFT JOIN findings f ON f.scan_id = s.id
GROUP BY s.id, s.url, s.score, s.status;