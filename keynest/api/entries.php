<?php
// ============================================================
// KeyNest — Entries API
// All entry data arrives/leaves as encrypted ciphertext.
// The server never decrypts anything.
//
// GET    /api/entries.php?resource=entries        → list all entries
// POST   /api/entries.php?resource=entries        → create entry  { id, type, ciphertext }
// PUT    /api/entries.php?resource=entries&id=X   → update entry  { ciphertext }
// DELETE /api/entries.php?resource=entries&id=X   → move to trash
//
// GET    /api/entries.php?resource=trash          → list trash
// POST   /api/entries.php?resource=trash&id=X     → restore from trash
// DELETE /api/entries.php?resource=trash&id=X     → permanently delete
// DELETE /api/entries.php?resource=trash          → empty trash
//
// GET    /api/entries.php?resource=tags           → list tags
// POST   /api/entries.php?resource=tags           → create tag  { name }
// DELETE /api/entries.php?resource=tags&id=X      → delete tag
// ============================================================

require_once __DIR__ . '/db.php';

$user     = requireAuth();
$method   = $_SERVER['REQUEST_METHOD'];
$resource = $_GET['resource'] ?? '';
$id       = $_GET['id'] ?? '';
$db       = getDB();

// ── ENTRIES ──────────────────────────────────────────────────
if ($resource === 'entries') {

    if ($method === 'GET') {
        $stmt = $db->prepare('SELECT id, type, ciphertext, created_at, updated_at FROM entries WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$user['id']]);
        jsonResponse($stmt->fetchAll());
    }

    if ($method === 'POST') {
        $body = getBody();
        $entryId    = $body['id']         ?? generateUUID();
        $type       = $body['type']       ?? 'password';
        $ciphertext = $body['ciphertext'] ?? '';

        if (!$ciphertext) jsonError('Ciphertext is required.');
        if (!in_array($type, ['password', 'note'])) jsonError('Invalid type.');

        $stmt = $db->prepare('INSERT INTO entries (id, user_id, type, ciphertext) VALUES (?, ?, ?, ?)');
        $stmt->execute([$entryId, $user['id'], $type, $ciphertext]);

        $stmt = $db->prepare('SELECT id, type, ciphertext, created_at, updated_at FROM entries WHERE id = ?');
        $stmt->execute([$entryId]);
        jsonResponse($stmt->fetch(), 201);
    }

    if ($method === 'PUT') {
        if (!$id) jsonError('Entry ID required.');
        $body = getBody();
        $ciphertext = $body['ciphertext'] ?? '';
        if (!$ciphertext) jsonError('Ciphertext is required.');

        $stmt = $db->prepare('UPDATE entries SET ciphertext = ? WHERE id = ? AND user_id = ?');
        $stmt->execute([$ciphertext, $id, $user['id']]);
        if ($stmt->rowCount() === 0) jsonError('Entry not found.', 404);
        jsonResponse(['ok' => true]);
    }

    if ($method === 'DELETE') {
        if (!$id) jsonError('Entry ID required.');

        // Move to trash instead of deleting
        $stmt = $db->prepare('SELECT id, type, ciphertext FROM entries WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $user['id']]);
        $entry = $stmt->fetch();
        if (!$entry) jsonError('Entry not found.', 404);

        $db->beginTransaction();
        $stmt = $db->prepare('INSERT INTO trash (id, user_id, type, ciphertext) VALUES (?, ?, ?, ?)');
        $stmt->execute([$entry['id'], $user['id'], $entry['type'], $entry['ciphertext']]);
        $stmt = $db->prepare('DELETE FROM entries WHERE id = ?');
        $stmt->execute([$id]);
        $db->commit();

        jsonResponse(['ok' => true]);
    }
}

// ── TRASH ──────────────────────────────────────────────────
if ($resource === 'trash') {

    if ($method === 'GET') {
        // Auto-purge entries older than 30 days
        $stmt = $db->prepare('DELETE FROM trash WHERE user_id = ? AND deleted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)');
        $stmt->execute([$user['id']]);

        $stmt = $db->prepare('SELECT id, type, ciphertext, deleted_at FROM trash WHERE user_id = ? ORDER BY deleted_at DESC');
        $stmt->execute([$user['id']]);
        jsonResponse($stmt->fetchAll());
    }

    // Restore single item
    if ($method === 'POST') {
        if (!$id) jsonError('Trash item ID required.');

        $stmt = $db->prepare('SELECT id, type, ciphertext FROM trash WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $user['id']]);
        $item = $stmt->fetch();
        if (!$item) jsonError('Item not found.', 404);

        $db->beginTransaction();
        $stmt = $db->prepare('INSERT INTO entries (id, user_id, type, ciphertext) VALUES (?, ?, ?, ?)');
        $stmt->execute([$item['id'], $user['id'], $item['type'], $item['ciphertext']]);
        $stmt = $db->prepare('DELETE FROM trash WHERE id = ?');
        $stmt->execute([$id]);
        $db->commit();

        jsonResponse(['ok' => true]);
    }

    if ($method === 'DELETE') {
        if ($id) {
            // Delete single item permanently
            $stmt = $db->prepare('DELETE FROM trash WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, $user['id']]);
            if ($stmt->rowCount() === 0) jsonError('Item not found.', 404);
        } else {
            // Empty all trash
            $stmt = $db->prepare('DELETE FROM trash WHERE user_id = ?');
            $stmt->execute([$user['id']]);
        }
        jsonResponse(['ok' => true]);
    }
}

// ── TAGS ───────────────────────────────────────────────────
if ($resource === 'tags') {

    if ($method === 'GET') {
        $stmt = $db->prepare('SELECT id, name FROM tags WHERE user_id = ? ORDER BY name ASC');
        $stmt->execute([$user['id']]);
        jsonResponse($stmt->fetchAll());
    }

    if ($method === 'POST') {
        $body = getBody();
        $name = trim($body['name'] ?? '');
        if (!$name) jsonError('Tag name required.');
        if (strlen($name) > 100) jsonError('Tag name too long.');

        // Upsert — ignore duplicate
        $stmt = $db->prepare('INSERT IGNORE INTO tags (user_id, name) VALUES (?, ?)');
        $stmt->execute([$user['id'], $name]);
        $tagId = $db->lastInsertId() ?: null;

        // Fetch the tag (whether just inserted or already existed)
        $stmt = $db->prepare('SELECT id, name FROM tags WHERE user_id = ? AND name = ?');
        $stmt->execute([$user['id'], $name]);
        jsonResponse($stmt->fetch(), 201);
    }

    if ($method === 'DELETE') {
        if (!$id) jsonError('Tag ID required.');
        $stmt = $db->prepare('DELETE FROM tags WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $user['id']]);
        jsonResponse(['ok' => true]);
    }
}

jsonError('Unknown resource.', 404);
