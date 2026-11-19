INSERT INTO users (full_name, email, password_hash)
VALUES ('Demo User', 'demo@webshield.com', 'bcrypt-hash-placeholder');

INSERT INTO workspaces (name, owner_id) VALUES ('Acme Studio', 1);
INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (1, 1, 'owner');

INSERT INTO assets (workspace_id, domain, ip_address, score) VALUES
(1, 'www.acme-studio.com', '212.212.28.161', 560),
(1, 'www.northstar.co',    '212.212.28.17',  500),
(1, 'www.lumen-cafe.in',   '212.212.28.10',  320);

INSERT INTO scans (workspace_id, asset_id, url, score, status, authorized, completed_at)
VALUES (1, 1, 'https://acme-studio.com', 72, 'completed', TRUE, NOW());

INSERT INTO finding_templates (title, category, owasp_code, severity, description) VALUES
('Secure session cookies','Security','A07:2021','High','Session cookies are missing Secure and SameSite protections.'),
('Content Security Policy is not configured','Security','A05:2021','High','The site does not define a Content-Security-Policy header.'),
('Third-party trackers detected','Privacy',NULL,'Medium','Analytics scripts load before consent is confirmed.'),
('Server information disclosed','Security','A05:2021','Low','Response headers reveal server framework details.'),
('Privacy policy needs clearer retention details','Privacy',NULL,'Low','Retention periods are not clearly explained.');

INSERT INTO findings (scan_id, template_id) VALUES (1,1),(1,2),(1,3),(1,4),(1,5);

INSERT INTO incidents (workspace_id, type, severity, status) VALUES
(1, 'Unauthorized Access', 'Critical', 'open'),
(1, 'Segmentation Disabled', 'Medium', 'open');

INSERT INTO trackers (workspace_id, name, block_until_consent) VALUES
(1, 'Google Analytics', FALSE), (1, 'Meta Pixel', FALSE), (1, 'Hotjar', FALSE);

INSERT INTO tickets (workspace_id, title, priority, status, assignee) VALUES
(1, 'Fix session cookie flags', 'High', 'open', 'Demo User');

INSERT INTO risks (workspace_id, title, likelihood, impact, owner, status) VALUES
(1, 'Unauthorized Access', 'High', 'High', 'Demo User', 'open');