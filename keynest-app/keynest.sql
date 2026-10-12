-- ============================================================
-- KeyNest Database Setup
-- Run this once in phpMyAdmin or MySQL CLI:
--   mysql -u root -p < keynest.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS keynest CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE keynest;

-- ── USERS ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  email       VARCHAR(255) NOT NULL UNIQUE,
  password    VARCHAR(255) NOT NULL,   -- bcrypt hash
  salt        VARCHAR(64)  NOT NULL,   -- PBKDF2 salt (hex), sent to client on login
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── ENTRIES ────────────────────────────────────────────────
-- All sensitive fields are AES-256-GCM encrypted client-side.
-- The server stores ciphertext only — it cannot read passwords.
CREATE TABLE IF NOT EXISTS entries (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  user_id     CHAR(36)     NOT NULL,
  type        VARCHAR(20)  NOT NULL DEFAULT 'password',  -- 'password' | 'note'
  ciphertext  LONGTEXT     NOT NULL,   -- base64(iv + authTag + encrypted JSON)
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- ── TRASH ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trash (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  user_id     CHAR(36)     NOT NULL,
  type        VARCHAR(20)  NOT NULL DEFAULT 'password',
  ciphertext  LONGTEXT     NOT NULL,
  deleted_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- ── TAGS ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tags (
  id          INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id     CHAR(36)     NOT NULL,
  name        VARCHAR(100) NOT NULL,
  UNIQUE KEY unique_user_tag (user_id, name),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
