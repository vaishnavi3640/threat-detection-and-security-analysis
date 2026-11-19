-- WebShield database schema (PostgreSQL)

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(150) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE workspaces (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  owner_id INT REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE workspace_members (
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) DEFAULT 'member',
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE assets (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  domain VARCHAR(255) NOT NULL,
  ip_address VARCHAR(45),
  score INT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE scans (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  asset_id INT REFERENCES assets(id) ON DELETE SET NULL,
  url VARCHAR(255) NOT NULL,
  score INT,
  status VARCHAR(20) DEFAULT 'running'
    CHECK (status IN ('running','completed','failed')),
  authorized BOOLEAN NOT NULL DEFAULT FALSE,
  started_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP
);

CREATE TABLE finding_templates (
  id SERIAL PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  category VARCHAR(20) NOT NULL CHECK (category IN ('Security','Privacy')),
  owasp_code VARCHAR(20),
  severity VARCHAR(10) NOT NULL
    CHECK (severity IN ('Critical','High','Medium','Low')),
  description TEXT,
  why_it_matters TEXT,
  fix_steps TEXT,
  code_snippet TEXT
);

CREATE TABLE findings (
  id SERIAL PRIMARY KEY,
  scan_id INT REFERENCES scans(id) ON DELETE CASCADE,
  template_id INT REFERENCES finding_templates(id),
  status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open','fixed')),
  fixed_at TIMESTAMP
);

CREATE TABLE incidents (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  type VARCHAR(100) NOT NULL,
  severity VARCHAR(10),
  status VARCHAR(20) DEFAULT 'open',
  occurred_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE trackers (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  block_until_consent BOOLEAN DEFAULT FALSE
);

CREATE TABLE tickets (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  priority VARCHAR(10),
  status VARCHAR(20) DEFAULT 'open',
  assignee VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE risks (
  id SERIAL PRIMARY KEY,
  workspace_id INT REFERENCES workspaces(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  likelihood VARCHAR(10),
  impact VARCHAR(10),
  owner VARCHAR(100),
  status VARCHAR(20) DEFAULT 'open'
);

CREATE TABLE notifications (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  link VARCHAR(100),
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_settings (
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_alerts BOOLEAN DEFAULT TRUE,
  weekly_report BOOLEAN DEFAULT TRUE,
  two_factor BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_scans_workspace ON scans(workspace_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_assets_workspace ON assets(workspace_id);
CREATE INDEX idx_incidents_workspace ON incidents(workspace_id);