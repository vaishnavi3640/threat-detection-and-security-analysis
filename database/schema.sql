-- WebShield database schema (MySQL 8)

DROP DATABASE IF EXISTS webshield;
CREATE DATABASE webshield;
USE webshield;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(150) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workspaces (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  owner_id INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE workspace_members (
  workspace_id INT,
  user_id INT,
  role VARCHAR(20) DEFAULT 'member',
  PRIMARY KEY (workspace_id, user_id),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE assets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  domain VARCHAR(255) NOT NULL,
  ip_address VARCHAR(45),
  score INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE scans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  asset_id INT NULL,
  url VARCHAR(255) NOT NULL,
  score INT,
  status VARCHAR(20) DEFAULT 'running',
  authorized BOOLEAN NOT NULL DEFAULT FALSE,
  started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP NULL,
  CHECK (status IN ('running','completed','failed')),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE finding_templates (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  category VARCHAR(20) NOT NULL,
  owasp_code VARCHAR(20),
  severity VARCHAR(10) NOT NULL,
  description TEXT,
  why_it_matters TEXT,
  fix_steps TEXT,
  code_snippet TEXT,
  CHECK (category IN ('Security','Privacy')),
  CHECK (severity IN ('Critical','High','Medium','Low'))
);

CREATE TABLE findings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT,
  template_id INT,
  status VARCHAR(20) DEFAULT 'open',
  fixed_at TIMESTAMP NULL,
  CHECK (status IN ('open','fixed')),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
  FOREIGN KEY (template_id) REFERENCES finding_templates(id)
);

CREATE TABLE incidents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  `type` VARCHAR(100) NOT NULL,
  severity VARCHAR(10),
  status VARCHAR(20) DEFAULT 'open',
  occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE trackers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  name VARCHAR(100) NOT NULL,
  block_until_consent BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE tickets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  title VARCHAR(200) NOT NULL,
  priority VARCHAR(10),
  status VARCHAR(20) DEFAULT 'open',
  assignee VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE risks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT,
  title VARCHAR(200) NOT NULL,
  likelihood VARCHAR(10),
  impact VARCHAR(10),
  `owner` VARCHAR(100),
  status VARCHAR(20) DEFAULT 'open',
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE notifications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  message TEXT NOT NULL,
  link VARCHAR(100),
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_settings (
  user_id INT PRIMARY KEY,
  email_alerts BOOLEAN DEFAULT TRUE,
  weekly_report BOOLEAN DEFAULT TRUE,
  two_factor BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_scans_workspace ON scans(workspace_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_assets_workspace ON assets(workspace_id);
CREATE INDEX idx_incidents_workspace ON incidents(workspace_id);