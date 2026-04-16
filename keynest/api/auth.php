<?php
// ============================================================
// KeyNest — Auth API
// POST /api/auth.php?action=register   { email, password }
// POST /api/auth.php?action=login      { email, password }
// POST /api/auth.php?action=logout
// GET  /api/auth.php?action=check
// ============================================================

require_once __DIR__ . '/db.php';

$action = $_GET['action'] ?? '';

switch ($action) {

    // ── REGISTER ─────────────────────────────────────────────
    case 'register': {
        $body     = getBody();
        $email    = trim(strtolower($body['email'] ?? ''));
        $password = $body['password'] ?? '';

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            jsonError('Invalid email address.');
        }
        if (strlen($password) < 8) {
            jsonError('Password must be at least 8 characters.');
        }

        $db = getDB();

        // Check email not already taken
        $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            jsonError('An account with this email already exists.');
        }

        // Hash password with bcrypt (server-side auth)
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        // Generate PBKDF2 salt — sent to client so it can derive the
        // encryption key deterministically from the user's password.
        // 32 random bytes = 64 hex chars
        $salt = bin2hex(random_bytes(32));
        $id   = generateUUID();

        $stmt = $db->prepare('INSERT INTO users (id, email, password, salt) VALUES (?, ?, ?, ?)');
        $stmt->execute([$id, $email, $hash, $salt]);

        // Start session
        session_start();
        $_SESSION['user_id']    = $id;
        $_SESSION['user_email'] = $email;

        jsonResponse([
            'id'    => $id,
            'email' => $email,
            'salt'  => $salt,   // needed by client to derive encryption key
        ], 201);
        break;
    }

    // ── LOGIN ─────────────────────────────────────────────────
    case 'login': {
        $body     = getBody();
        $email    = trim(strtolower($body['email'] ?? ''));
        $password = $body['password'] ?? '';

        if (!$email || !$password) {
            jsonError('Email and password are required.');
        }

        $db   = getDB();
        $stmt = $db->prepare('SELECT id, email, password, salt FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password'])) {
            jsonError('Invalid email or password.', 401);
        }

        session_start();
        $_SESSION['user_id']    = $user['id'];
        $_SESSION['user_email'] = $user['email'];

        jsonResponse([
            'id'    => $user['id'],
            'email' => $user['email'],
            'salt'  => $user['salt'],
        ]);
        break;
    }

    // ── LOGOUT ────────────────────────────────────────────────
    case 'logout': {
        session_start();
        session_destroy();
        jsonResponse(['ok' => true]);
        break;
    }

    // ── SESSION CHECK ─────────────────────────────────────────
    case 'check': {
        session_start();
        if (empty($_SESSION['user_id'])) {
            jsonResponse(['authenticated' => false]);
        }

        $db   = getDB();
        $stmt = $db->prepare('SELECT id, email, salt FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user) {
            session_destroy();
            jsonResponse(['authenticated' => false]);
        }

        jsonResponse([
            'authenticated' => true,
            'id'    => $user['id'],
            'email' => $user['email'],
            'salt'  => $user['salt'],
        ]);
        break;
    }

    default:
        jsonError('Unknown action.', 404);
}
