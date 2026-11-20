USE webshield;
SET SQL_SAFE_UPDATES = 0;

UPDATE finding_templates SET
  why_it_matters = 'Without these flags, session cookies can be stolen over insecure connections or sent in cross-site requests.',
  fix_steps = '1. Open your server or framework session settings. 2. Turn on the Secure flag. 3. Set SameSite to Strict or Lax. 4. Add HttpOnly. 5. Reassess to confirm.',
  code_snippet = 'Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict'
WHERE title = 'Secure session cookies';

UPDATE finding_templates SET
  why_it_matters = 'A Content-Security-Policy limits which scripts can run on your page, which helps stop cross-site scripting attacks.',
  fix_steps = '1. List the sources your site really needs. 2. Add a Content-Security-Policy header. 3. Test in report-only mode first. 4. Tighten the rules. 5. Reassess.',
  code_snippet = 'Content-Security-Policy: default-src ''self''; script-src ''self'''
WHERE title = 'Content Security Policy is not configured';

UPDATE finding_templates SET
  why_it_matters = 'Trackers that load before consent can break privacy rules and reduce visitor trust.',
  fix_steps = '1. List all analytics and ad scripts. 2. Load them only after the visitor accepts cookies. 3. Add a consent banner. 4. Reassess.',
  code_snippet = 'if (userConsent === true) { loadAnalyticsScript(); }'
WHERE title = 'Third-party trackers detected';

UPDATE finding_templates SET
  why_it_matters = 'Server and framework details help attackers pick known exploits for your exact software.',
  fix_steps = '1. Open your server configuration. 2. Hide the Server and X-Powered-By headers. 3. Restart the server. 4. Reassess.',
  code_snippet = 'server_tokens off;'
WHERE title = 'Server information disclosed';

UPDATE finding_templates SET
  why_it_matters = 'Visitors and regulators expect to know how long you keep personal data.',
  fix_steps = '1. Decide how long each type of data is kept. 2. Add a Data Retention section to your privacy policy. 3. Publish the update. 4. Reassess.',
  code_snippet = 'We keep account data for 12 months after your last activity, then delete it.'
WHERE title = 'Privacy policy needs clearer retention details';

SET SQL_SAFE_UPDATES = 1;