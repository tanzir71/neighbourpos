<?php
/*
README (Deployment — 10 lines)
1) Upload this file as `neighbourpos.php` to your PHP hosting (same folder becomes app root).
2) Ensure the folder is writable by PHP so it can create `neighbourpos.db` next to this file.
3) Visit `/neighbourpos.php` once to auto-initialize the SQLite schema and settings.
4) Default admin login: admin@example.com / ChangeMe123! (change in Settings immediately).
5) Optional: click “Load sample data” (admin only) to populate demo products/customers/orders.
6) Add cPanel Cron (daily): `php /home/USER/public_html/neighbourpos.php action=cron_campaigns token=YOUR_TOKEN`
7) Add cPanel Cron (nightly): `php /home/USER/public_html/neighbourpos.php action=cron_purge_logs token=YOUR_TOKEN`
8) If cron can’t call via CLI, use wget/curl URL with token: `/neighbourpos.php?action=cron_campaigns&token=...`
9) For HTTPS + cookies, enable SSL in hosting and keep `SESSION_SECURE_AUTO` true.
10) Backups: copy `neighbourpos.db` regularly (download via FTP or hosting backup tools).
*/

declare(strict_types=1);

/* =========================
   Customize here (CONFIG)
   ========================= */

$CONFIG = [
  'APP_NAME' => 'NeighbourPOS',
  'ACCENT' => '#2563eb',
  'CURRENCY' => 'USD',
  'CURRENCY_SYMBOL' => '$',

  'TAX_RATE' => 0.08,
  'DEFAULT_TIP_RATE' => 0.00,
  'ENABLE_DELIVERY_DEFAULT' => true,
  'LOW_STOCK_THRESHOLD' => 5,

  'STOCK_DECREMENT_ON' => 'complete',

  'RETENTION_DAYS_AUDIT' => 120,

  'RETENTION_FACTOR' => 0.85,

  'DEFAULT_ADMIN_EMAIL' => 'admin@example.com',
  'DEFAULT_ADMIN_PASSWORD' => 'ChangeMe123!',

  'CRON_TOKEN' => 'CHANGE_THIS_CRON_TOKEN',

  'REQUIRE_MARKETING_OPT_IN' => true,

  'SESSION_SECURE_AUTO' => true,
  'SESSION_IDLE_TIMEOUT_SECONDS' => 3600,

  'LOG_FILE' => __DIR__.DIRECTORY_SEPARATOR.'neighbourpos.log',

  'RATE_LIMITS' => [
    'LOGIN' => ['limit' => 8, 'window_seconds' => 600],
    'API_WRITE' => ['limit' => 120, 'window_seconds' => 300],
  ],

  'COUPON' => [
    'ENABLED' => true,
    'PREFIX' => 'NP',
    'LENGTH' => 8,
    'SINGLE_USE_PER_CUSTOMER' => true,
  ],

  'SIMULATOR' => [
    'DEFAULT_REDEMPTION_RATE' => 0.06,
    'DEFAULT_COUPON_LIFT' => 0.12,
  ],

  'EMAIL' => [
    'ENABLED' => false,
    'FROM' => 'store@example.com',
    // Plug a provider here (SendGrid/Mailgun/etc) in send_email_placeholder().
  ],

  'SMS' => [
    'ENABLED' => false,
    'FROM' => 'NeighbourPOS',
    // Plug a provider here (Twilio/etc) in send_sms_placeholder().
    // Optional customer SMS verification can be enabled in verify_sms_code_placeholder().
  ],

  'AUTO_CAMPAIGNS' => [
    [
      'name' => 'Winback 30+ days (high value)',
      'filters' => [
        'inactive_days' => 30,
        'total_spent_min_cents' => 2000,
        'order_count_min' => 2,
      ],
      'channel' => 'export',
      'message_template' => "We miss you! Come back this week for a thank-you offer.",
      'schedule_hour' => 10,
    ],
  ],
];

apply_env_overrides($CONFIG, __DIR__.DIRECTORY_SEPARATOR.'.env');

/* =========================
   Bootstrap & utilities
   ========================= */

ini_set('display_errors', '0');
error_reporting(E_ALL);

if (PHP_SAPI !== 'cli') {
  $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
  $cookieSecure = $secure;
  if (!empty($CONFIG['SESSION_SECURE_AUTO']) && $CONFIG['SESSION_SECURE_AUTO'] === false) $cookieSecure = false;

  if (PHP_VERSION_ID >= 70300) {
    session_set_cookie_params([
      'lifetime' => 0,
      'path' => '/',
      'httponly' => true,
      'samesite' => 'Lax',
      'secure' => $cookieSecure,
    ]);
  }
}
session_name('neighbourpos_sess');
session_start();

$CSP_NONCE = bin2hex(random_bytes(16));

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
  header('Strict-Transport-Security: max-age=15552000; includeSubDomains');
}
// Customize CSP in build_csp_header() if you add external scripts/styles or a CDN.
header('Content-Security-Policy: '.build_csp_header($CSP_NONCE));

enforce_session_timeout($CONFIG);

function htmlEscape(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function h(string $s): string { return htmlEscape($s); }
function now_iso(): string { return gmdate('Y-m-d H:i:s'); }
function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }

set_error_handler(function(int $severity, string $message, string $file, int $line): bool {
  if (!(error_reporting() & $severity)) return true;
  throw new ErrorException($message, 0, $severity, $file, $line);
});

set_exception_handler(function(Throwable $e): void {
  $isJson = false;
  $action = $_GET['action'] ?? '';
  if (is_string($action) && str_starts_with($action, 'api_')) $isJson = true;
  $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
  if (is_string($accept) && stripos($accept, 'application/json') !== false) $isJson = true;

  log_error_safe($e);
  if ($isJson) {
    json_out(['ok' => false, 'error' => 'Server error'], 500);
  }

  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  echo "Server error";
  exit;
});

function json_out(array $payload, int $code = 200): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($payload, JSON_UNESCAPED_SLASHES);
  exit;
}

function redirect_to(string $url): void {
  header('Location: '.$url);
  exit;
}

function csrf_token(): string {
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
  return $_SESSION['csrf'];
}

function require_csrf(): void {
  $token = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
  if (!$token || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
    json_out(['ok' => false, 'error' => 'CSRF token invalid'], 403);
  }
}

function read_json_body(): array {
  $raw = file_get_contents('php://input');
  if (!$raw) return [];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}

function normalize_phone(string $phone): string {
  $p = preg_replace('/[^\d\+]/', '', trim($phone));
  if ($p === '') return '';
  if ($p[0] !== '+') {
    $digits = preg_replace('/\D/', '', $p);
    if (strlen($digits) === 10) $p = '+1'.$digits;
    else $p = '+'.$digits;
  }
  $p = '+'.preg_replace('/\D/', '', $p);
  return $p;
}

function apply_env_overrides(array &$CONFIG, string $envPath): void {
  if (!is_file($envPath)) return;
  $raw = @file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  if (!is_array($raw)) return;
  foreach ($raw as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#')) continue;
    $pos = strpos($line, '=');
    if ($pos === false) continue;
    $k = trim(substr($line, 0, $pos));
    $v = trim(substr($line, $pos + 1));
    if ($k === '') continue;
    if (str_starts_with($v, '"') && str_ends_with($v, '"')) $v = substr($v, 1, -1);
    if (str_starts_with($v, "'") && str_ends_with($v, "'")) $v = substr($v, 1, -1);

    if ($k === 'CRON_TOKEN') $CONFIG['CRON_TOKEN'] = $v;
    if ($k === 'DEFAULT_ADMIN_EMAIL') $CONFIG['DEFAULT_ADMIN_EMAIL'] = $v;
    if ($k === 'DEFAULT_ADMIN_PASSWORD') $CONFIG['DEFAULT_ADMIN_PASSWORD'] = $v;
    if ($k === 'LOG_FILE') $CONFIG['LOG_FILE'] = $v;
    if ($k === 'SESSION_IDLE_TIMEOUT_SECONDS') $CONFIG['SESSION_IDLE_TIMEOUT_SECONDS'] = max(300, (int)$v);
    if ($k === 'ACCENT') $CONFIG['ACCENT'] = $v;
  }
}

function build_csp_header(string $nonce): string {
  return implode('; ', [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "font-src 'self' https://fonts.gstatic.com",
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
    "script-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
    "upgrade-insecure-requests",
  ]);
}

function log_error_safe(Throwable $e): void {
  global $CONFIG;
  $path = (string)($CONFIG['LOG_FILE'] ?? (__DIR__.DIRECTORY_SEPARATOR.'neighbourpos.log'));
  $line = '['.gmdate('c').'] '.$e::class.': '.$e->getMessage().' @ '.$e->getFile().':'.$e->getLine()."\n";
  $line .= $e->getTraceAsString()."\n\n";
  @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
}

function enforce_session_timeout(array $CONFIG): void {
  $idle = (int)($CONFIG['SESSION_IDLE_TIMEOUT_SECONDS'] ?? 3600);
  if ($idle < 300) $idle = 300;

  $now = time();
  $last = (int)($_SESSION['last_active_ts'] ?? 0);
  $_SESSION['last_active_ts'] = $now;

  if (!empty($_SESSION['uid']) && $last > 0 && ($now - $last) > $idle) {
    session_unset();
    session_destroy();
    $action = $_GET['action'] ?? '';
    if (is_string($action) && str_starts_with($action, 'api_')) {
      json_out(['ok' => false, 'error' => 'Session expired'], 401);
    }
    redirect_to('?action=staff_login');
  }
}

function validate_hex_color(string $s): ?string {
  $s = trim($s);
  if (preg_match('/^#[0-9a-fA-F]{6}$/', $s)) return strtoupper($s);
  return null;
}

function store_accent_safe(array $store, array $CONFIG): string {
  $candidate = (string)($store['accent'] ?? '');
  $ok = validate_hex_color($candidate);
  if ($ok) return $ok;
  $fallback = validate_hex_color((string)($CONFIG['ACCENT'] ?? '#2563eb'));
  return $fallback ?: '#2563EB';
}

function money_fmt(array $CONFIG, int $cents): string {
  $sym = $CONFIG['CURRENCY_SYMBOL'] ?? '$';
  $amt = number_format($cents / 100, 2, '.', ',');
  return $sym.$amt;
}

function rand_code(int $len): string {
  $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $out = '';
  for ($i = 0; $i < $len; $i++) $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
  return $out;
}

function require_login(): void {
  if (empty($_SESSION['uid'])) redirect_to('?action=staff_login');
}

function is_admin(): bool {
  return !empty($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function rate_limit_or_fail(PDO $pdo, string $bucketKey, int $limit, int $windowSeconds, bool $json): void {
  $now = time();
  $windowSeconds = max(10, $windowSeconds);
  $limit = max(1, $limit);

  $pdo->beginTransaction();
  $st = $pdo->prepare("SELECT k, count, reset_at FROM rate_limits WHERE k = ?");
  $st->execute([$bucketKey]);
  $row = $st->fetch();
  if (!$row || (int)$row['reset_at'] <= $now) {
    $resetAt = $now + $windowSeconds;
    $up = $pdo->prepare("INSERT OR REPLACE INTO rate_limits(k, count, reset_at) VALUES(?,?,?)");
    $up->execute([$bucketKey, 1, $resetAt]);
    $pdo->commit();
    return;
  }

  $count = (int)$row['count'] + 1;
  $resetAt = (int)$row['reset_at'];
  $up = $pdo->prepare("UPDATE rate_limits SET count = ? WHERE k = ?");
  $up->execute([$count, $bucketKey]);
  $pdo->commit();

  if ($count > $limit) {
    $retry = max(1, $resetAt - $now);
    header('Retry-After: '.$retry);
    if ($json) json_out(['ok' => false, 'error' => 'Rate limit exceeded', 'retry_after' => $retry], 429);
    http_response_code(429);
    echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Too Many Requests</title></head><body>";
    echo "<p>Too many requests. Try again in ".htmlEscape((string)$retry)." seconds.</p>";
    echo "</body></html>";
    exit;
  }
}

/* =========================
   DB (SQLite via PDO)
   ========================= */

function db(array $CONFIG): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;

  $dbPath = __DIR__.DIRECTORY_SEPARATOR.'neighbourpos.db';
  $pdo = new PDO('sqlite:'.$dbPath, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);

  $pdo->exec("PRAGMA journal_mode=WAL;");
  $pdo->exec("PRAGMA synchronous=NORMAL;");
  $pdo->exec("PRAGMA foreign_keys=OFF;");
  $pdo->exec("PRAGMA busy_timeout=5000;");

  init_db($pdo);
  ensure_default_admin($pdo, $CONFIG);

  return $pdo;
}

function init_db(PDO $pdo): void {
  $pdo->beginTransaction();

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff',
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS stores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      enable_delivery INTEGER NOT NULL DEFAULT 1,
      tax_rate REAL NOT NULL DEFAULT 0.0,
      accent TEXT NOT NULL DEFAULT '#2563eb',
      currency TEXT NOT NULL DEFAULT 'USD',
      currency_symbol TEXT NOT NULL DEFAULT '$',
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sku TEXT,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL,
      stock_qty INTEGER NOT NULL DEFAULT 0,
      category TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL UNIQUE,
      name TEXT,
      address TEXT,
      email TEXT,
      marketing_opt_in INTEGER NOT NULL DEFAULT 0,
      marketing_opt_in_ts TEXT,
      last_order_at TEXT,
      total_spent_cents INTEGER NOT NULL DEFAULT 0,
      order_count INTEGER NOT NULL DEFAULT 0,
      tags_text TEXT NOT NULL DEFAULT '',
      metadata_json TEXT NOT NULL DEFAULT '{}',
      lat REAL,
      lng REAL,
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_code TEXT NOT NULL UNIQUE,
      customer_id INTEGER,
      phone_text TEXT,
      order_type TEXT NOT NULL,
      items_json TEXT NOT NULL,
      subtotal_cents INTEGER NOT NULL,
      tax_cents INTEGER NOT NULL,
      tip_cents INTEGER NOT NULL,
      total_cents INTEGER NOT NULL,
      status TEXT NOT NULL,
      payment_method TEXT NOT NULL DEFAULT 'cash',
      payment_received INTEGER NOT NULL DEFAULT 0,
      expected_eta_minutes INTEGER NOT NULL DEFAULT 15,
      stock_applied INTEGER NOT NULL DEFAULT 0,
      metrics_applied INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER,
      product_name TEXT NOT NULL,
      category TEXT,
      qty INTEGER NOT NULL,
      price_cents INTEGER NOT NULL,
      notes TEXT,
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS segments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      filters_json TEXT NOT NULL,
      last_run_at TEXT
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      segment_id INTEGER,
      channel TEXT NOT NULL,
      message_template TEXT NOT NULL,
      scheduled_at TEXT,
      sent_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS campaign_recipients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER NOT NULL,
      customer_id INTEGER NOT NULL,
      phone TEXT NOT NULL,
      email TEXT,
      coupon_code TEXT,
      sent_at TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      payload_json TEXT NOT NULL DEFAULT '{}'
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      ts TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS imports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      rows_total INTEGER NOT NULL DEFAULT 0,
      rows_imported INTEGER NOT NULL DEFAULT 0,
      errors_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );
  ");

  $pdo->exec("
    CREATE TABLE IF NOT EXISTS rate_limits (
      k TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      reset_at INTEGER NOT NULL
    );
  ");

  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_products_active ON products(active);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_customers_last_order ON customers(last_order_at);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_customers_spent ON customers(total_spent_cents);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_order_items_product ON order_items(product_id);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_order_items_category ON order_items(category);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign ON campaign_recipients(campaign_id);");

  $pdo->commit();
}

function ensure_default_admin(PDO $pdo, array $CONFIG): void {
  $cnt = (int)$pdo->query("SELECT COUNT(*) AS c FROM users")->fetch()['c'];
  if ($cnt > 0) return;

  $email = strtolower(trim((string)$CONFIG['DEFAULT_ADMIN_EMAIL']));
  $pass = (string)$CONFIG['DEFAULT_ADMIN_PASSWORD'];
  $hash = password_hash($pass, PASSWORD_DEFAULT);

  $st = $pdo->prepare("INSERT INTO users(email, password_hash, role, created_at) VALUES(?,?,?,?)");
  $st->execute([$email, $hash, 'admin', now_iso()]);

  $storeCnt = (int)$pdo->query("SELECT COUNT(*) AS c FROM stores")->fetch()['c'];
  if ($storeCnt === 0) {
    $st2 = $pdo->prepare("INSERT INTO stores(name, enable_delivery, tax_rate, accent, currency, currency_symbol, created_at) VALUES(?,?,?,?,?,?,?)");
    $st2->execute(['Neighbour Store', 1, 0.08, '#2563eb', 'USD', '$', now_iso()]);
  }
}

function audit(PDO $pdo, ?int $userId, string $action, array $payload): void {
  $st = $pdo->prepare("INSERT INTO audit_log(user_id, action, payload_json, ts) VALUES(?,?,?,?)");
  $st->execute([$userId, $action, json_encode($payload, JSON_UNESCAPED_SLASHES), now_iso()]);
}

/* =========================
   Campaign/SMS/Email placeholders
   ========================= */

function send_sms_placeholder(array $CONFIG, string $toPhone, string $message): array {
  // Plug Twilio (or other) here. Return ['ok'=>true] or ['ok'=>false,'error'=>'...'].
  // IMPORTANT: Store must comply with local SMS laws and costs; keep opt-in proof.
  return ['ok' => false, 'error' => 'SMS provider not configured'];
}

function send_email_placeholder(array $CONFIG, string $toEmail, string $subject, string $body): array {
  // Plug SendGrid/Mailgun/etc here. Return ['ok'=>true] or ['ok'=>false,'error'=>'...'].
  return ['ok' => false, 'error' => 'Email provider not configured'];
}

function verify_sms_code_placeholder(array $CONFIG, string $phone, string $code): bool {
  // Optional: implement SMS verification flow for customers (store code in session/db with expiry).
  return true;
}

/* =========================
   Segmentation
   ========================= */

function parse_filters($raw): array {
  if (is_string($raw)) {
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
  }
  return is_array($raw) ? $raw : [];
}

function tags_to_text(array $tags): string {
  $clean = [];
  foreach ($tags as $t) {
    $t = trim((string)$t);
    if ($t === '') continue;
    $t = strtolower(preg_replace('/[^a-z0-9_\-]/', '', $t));
    if ($t === '') continue;
    $clean[] = $t;
  }
  $clean = array_values(array_unique($clean));
  if (!$clean) return '';
  return ',' . implode(',', $clean) . ',';
}

function estimate_distance_km(float $lat1, float $lng1, float $lat2, float $lng2): float {
  $R = 6371.0;
  $dLat = deg2rad($lat2 - $lat1);
  $dLng = deg2rad($lng2 - $lng1);
  $a = sin($dLat/2)*sin($dLat/2) + cos(deg2rad($lat1))*cos(deg2rad($lat2))*sin($dLng/2)*sin($dLng/2);
  $c = 2 * atan2(sqrt($a), sqrt(1-$a));
  return $R * $c;
}

function segment_query(PDO $pdo, array $filters, int $limit, int $offset = 0): array {
  $where = [];
  $params = [];

  if (!empty($filters['marketing_opt_in_only'])) {
    $where[] = "c.marketing_opt_in = 1";
  }

  if (isset($filters['total_spent_min_cents']) && $filters['total_spent_min_cents'] !== '') {
    $where[] = "c.total_spent_cents >= ?";
    $params[] = (int)$filters['total_spent_min_cents'];
  }
  if (isset($filters['total_spent_max_cents']) && $filters['total_spent_max_cents'] !== '') {
    $where[] = "c.total_spent_cents <= ?";
    $params[] = (int)$filters['total_spent_max_cents'];
  }

  if (isset($filters['order_count_min']) && $filters['order_count_min'] !== '') {
    $where[] = "c.order_count >= ?";
    $params[] = (int)$filters['order_count_min'];
  }
  if (isset($filters['order_count_max']) && $filters['order_count_max'] !== '') {
    $where[] = "c.order_count <= ?";
    $params[] = (int)$filters['order_count_max'];
  }

  if (!empty($filters['inactive_days'])) {
    $where[] = "(c.last_order_at IS NULL OR c.last_order_at < datetime('now', ?))";
    $params[] = '-'.((int)$filters['inactive_days']).' days';
  }
  if (!empty($filters['recency_days'])) {
    $where[] = "c.last_order_at >= datetime('now', ?)";
    $params[] = '-'.((int)$filters['recency_days']).' days';
  }

  $joins = '';
  $groupBy = '';
  if (!empty($filters['purchased_product_id']) || !empty($filters['purchased_category'])) {
    $joins .= " INNER JOIN order_items oi ON oi.product_id IS NOT NULL AND oi.order_id IN (SELECT id FROM orders o WHERE o.customer_id = c.id AND o.status = 'completed') ";
    if (!empty($filters['purchased_product_id'])) {
      $where[] = "oi.product_id = ?";
      $params[] = (int)$filters['purchased_product_id'];
    }
    if (!empty($filters['purchased_category'])) {
      $where[] = "oi.category = ?";
      $params[] = (string)$filters['purchased_category'];
    }
    $groupBy = " GROUP BY c.id ";
  }

  if (!empty($filters['tag_any']) && is_array($filters['tag_any'])) {
    $tagW = [];
    foreach ($filters['tag_any'] as $t) {
      $t = strtolower(preg_replace('/[^a-z0-9_\-]/', '', (string)$t));
      if ($t === '') continue;
      $tagW[] = "c.tags_text LIKE ?";
      $params[] = '%,' . $t . ',%';
    }
    if ($tagW) $where[] = '(' . implode(' OR ', $tagW) . ')';
  }

  $sql = "SELECT c.* FROM customers c {$joins}";
  if ($where) $sql .= " WHERE " . implode(' AND ', $where);
  if ($groupBy) $sql .= $groupBy;
  $sql .= " ORDER BY COALESCE(c.last_order_at, c.created_at) DESC LIMIT ? OFFSET ?";

  $params2 = $params;
  $params2[] = $limit;
  $params2[] = $offset;

  $st = $pdo->prepare($sql);
  $st->execute($params2);
  $rows = $st->fetchAll();

  if (!empty($filters['location_radius_km']) && isset($filters['location_lat']) && isset($filters['location_lng'])) {
    $lat = (float)$filters['location_lat'];
    $lng = (float)$filters['location_lng'];
    $radius = (float)$filters['location_radius_km'];

    $filtered = [];
    foreach ($rows as $r) {
      if ($r['lat'] === null || $r['lng'] === null) continue;
      $d = estimate_distance_km($lat, $lng, (float)$r['lat'], (float)$r['lng']);
      if ($d <= $radius) $filtered[] = $r;
    }
    $rows = $filtered;
  }

  return $rows;
}

function segment_count(PDO $pdo, array $filters): int {
  $rows = segment_query($pdo, $filters, 5000, 0);
  return count($rows);
}

function calc_customer_ltv(array $CONFIG, array $cust): float {
  $orderCount = (int)($cust['order_count'] ?? 0);
  if ($orderCount <= 0) return 0.0;
  $totalSpent = (int)($cust['total_spent_cents'] ?? 0);
  $aov = ($orderCount > 0) ? ($totalSpent / $orderCount) : 0;
  $factor = (float)($CONFIG['RETENTION_FACTOR'] ?? 0.85);
  return ($aov * $orderCount * $factor) / 100.0;
}

/* =========================
   Orders: stock + metrics application
   ========================= */

function apply_order_effects(PDO $pdo, array $CONFIG, int $orderId): void {
  $st = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
  $st->execute([$orderId]);
  $order = $st->fetch();
  if (!$order) return;

  $shouldApplyStock = ($CONFIG['STOCK_DECREMENT_ON'] ?? 'complete') === 'complete';
  $status = (string)$order['status'];

  if ($status !== 'completed') return;

  $pdo->beginTransaction();

  if ($shouldApplyStock && (int)$order['stock_applied'] === 0) {
    $stItems = $pdo->prepare("SELECT product_id, qty FROM order_items WHERE order_id = ? AND product_id IS NOT NULL");
    $stItems->execute([$orderId]);
    foreach ($stItems->fetchAll() as $it) {
      $pid = (int)$it['product_id'];
      $qty = (int)$it['qty'];
      $upd = $pdo->prepare("UPDATE products SET stock_qty = stock_qty - ? WHERE id = ?");
      $upd->execute([$qty, $pid]);
    }
    $pdo->prepare("UPDATE orders SET stock_applied = 1 WHERE id = ?")->execute([$orderId]);
  }

  if ((int)$order['metrics_applied'] === 0 && !empty($order['customer_id'])) {
    $cid = (int)$order['customer_id'];
    $total = (int)$order['total_cents'];
    $pdo->prepare("
      UPDATE customers
      SET last_order_at = ?, total_spent_cents = total_spent_cents + ?, order_count = order_count + 1
      WHERE id = ?
    ")->execute([now_iso(), $total, $cid]);
    $pdo->prepare("UPDATE orders SET metrics_applied = 1 WHERE id = ?")->execute([$orderId]);
  }

  $pdo->commit();
}

/* =========================
   Routing
   ========================= */

$pdo = db($CONFIG);
$action = $_GET['action'] ?? '';

if (PHP_SAPI === 'cli') {
  $cliAction = $argv[1] ?? '';
  if ($cliAction) $action = $cliAction;
  if (!$action && isset($argv[2]) && str_starts_with($argv[2], 'action=')) $action = substr($argv[2], 7);
  parse_str(implode('&', array_slice($argv, 1)), $cliParams);
  if (!empty($cliParams['action'])) $action = (string)$cliParams['action'];
  $_GET = array_merge($_GET, $cliParams);
  $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function current_store(PDO $pdo, array $CONFIG): array {
  $r = $pdo->query("SELECT * FROM stores ORDER BY id ASC LIMIT 1")->fetch();
  if ($r) return $r;
  return [
    'id' => 1,
    'name' => 'Neighbour Store',
    'enable_delivery' => (int)($CONFIG['ENABLE_DELIVERY_DEFAULT'] ? 1 : 0),
    'tax_rate' => (float)($CONFIG['TAX_RATE'] ?? 0.0),
    'accent' => (string)($CONFIG['ACCENT'] ?? '#2563eb'),
    'currency' => (string)($CONFIG['CURRENCY'] ?? 'USD'),
    'currency_symbol' => (string)($CONFIG['CURRENCY_SYMBOL'] ?? '$'),
  ];
}

/* =========================
   Auth actions
   ========================= */

if ($action === 'logout') {
  if ($method !== 'POST') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Method Not Allowed";
    exit;
  }
  require_csrf();
  session_unset();
  session_destroy();
  redirect_to('?action=staff_login');
}

if ($action === 'staff_login') {
  if ($method === 'POST') {
    require_csrf();
    $rl = (array)($CONFIG['RATE_LIMITS']['LOGIN'] ?? ['limit' => 8, 'window_seconds' => 600]);
    rate_limit_or_fail($pdo, 'login:ip:'.client_ip(), (int)($rl['limit'] ?? 8), (int)($rl['window_seconds'] ?? 600), false);
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $pass = (string)($_POST['password'] ?? '');

    $st = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $st->execute([$email]);
    $u = $st->fetch();

    if ($u && password_verify($pass, (string)$u['password_hash'])) {
      session_regenerate_id(true);
      $_SESSION['uid'] = (int)$u['id'];
      $_SESSION['email'] = (string)$u['email'];
      $_SESSION['role'] = (string)$u['role'];
      $_SESSION['last_active_ts'] = time();
      audit($pdo, (int)$u['id'], 'auth.login', ['ip' => client_ip()]);
      redirect_to('?');
    }

    $err = 'Invalid credentials';
  }

  $store = current_store($pdo, $CONFIG);
  $accent = store_accent_safe($store, $CONFIG);
  $csrf = csrf_token();
  echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  echo "<title>".h($CONFIG['APP_NAME'])." — Staff Login</title>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>
    :root{--accent:{$accent};--bg:#0b0c0f;--card:#11131a;--txt:#f5f7ff;--muted:#9aa3b2;--line:#23283a;}
    *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#07080b,#0b0c0f);color:var(--txt);}
    a{color:var(--txt)}
    .wrap{max-width:420px;margin:0 auto;padding:24px}
    .brand{display:flex;align-items:center;gap:10px;margin-top:20px;margin-bottom:18px}
    .dot{width:10px;height:10px;border-radius:999px;background:var(--accent);box-shadow:0 0 0 6px rgba(37,99,235,.14)}
    .card{background:rgba(17,19,26,.78);border:1px solid var(--line);border-radius:16px;padding:16px}
    .h1{font-size:18px;font-weight:800;margin:0}
    .p{color:var(--muted);font-size:13px;line-height:1.4;margin:6px 0 0}
    label{display:block;font-size:12px;color:var(--muted);margin-top:12px}
    input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid var(--line);background:#0f1118;color:var(--txt);outline:none}
    input:focus{border-color:rgba(37,99,235,.6);box-shadow:0 0 0 4px rgba(37,99,235,.14)}
    .btn{margin-top:14px;width:100%;padding:12px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:var(--accent);color:#fff;font-weight:700}
    .btn:active{transform:translateY(1px)}
    .err{margin-top:12px;background:rgba(239,68,68,.14);border:1px solid rgba(239,68,68,.28);color:#fecaca;padding:10px;border-radius:12px;font-size:13px}
    .foot{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.5}
  </style></head><body>";
  echo "<div class='wrap'>";
  echo "<div class='brand'><div class='dot'></div><div><div class='h1'>".h($CONFIG['APP_NAME'])."</div><div class='p'>Mobile-first POS + CRM for neighborhood stores.</div></div></div>";
  echo "<div class='card'>";
  echo "<form method='post' action='?action=staff_login'>";
  echo "<input type='hidden' name='csrf' value='".h($csrf)."'>";
  echo "<label>Email</label><input name='email' type='email' autocomplete='username' required>";
  echo "<label>Password</label><input name='password' type='password' autocomplete='current-password' required>";
  echo "<button class='btn' type='submit'>Sign in</button>";
  if (!empty($err)) echo "<div class='err'>".h($err)."</div>";
  echo "</form>";
  echo "<div class='foot'>Compliance note: you are responsible for SMS/email marketing laws and costs. NeighbourPOS does not process payments. <a href='SETUP.md'>Docs</a> • <a href='SECURITY.md'>Security</a></div>";
  echo "</div>";
  echo "</div></body></html>";
  exit;
}

if ($action === 'staff_register') {
  $userCount = (int)$pdo->query("SELECT COUNT(*) AS c FROM users")->fetch()['c'];
  if ($userCount > 0 && !is_admin()) {
    require_login();
    if (!is_admin()) redirect_to('?');
  }

  if ($method === 'POST') {
    require_csrf();
    $rl = (array)($CONFIG['RATE_LIMITS']['LOGIN'] ?? ['limit' => 8, 'window_seconds' => 600]);
    rate_limit_or_fail($pdo, 'register:ip:'.client_ip(), (int)($rl['limit'] ?? 8), (int)($rl['window_seconds'] ?? 600), false);
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $pass = (string)($_POST['password'] ?? '');
    $role = (string)($_POST['role'] ?? 'staff');
    if ($role !== 'admin') $role = 'staff';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($pass) < 8) {
      $err = 'Provide a valid email and a password (8+ chars).';
    } else {
      $hash = password_hash($pass, PASSWORD_DEFAULT);
      try {
        $st = $pdo->prepare("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)");
        $st->execute([$email, $hash, $role, now_iso()]);
        audit($pdo, $_SESSION['uid'] ?? null, 'users.create', ['email' => $email, 'role' => $role, 'ip' => client_ip()]);
        redirect_to('?action=staff_login');
      } catch (Throwable $e) {
        $err = 'Email already exists.';
      }
    }
  }

  $store = current_store($pdo, $CONFIG);
  $accent = store_accent_safe($store, $CONFIG);
  $csrf = csrf_token();
  echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  echo "<title>".h($CONFIG['APP_NAME'])." — Staff Register</title>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>
    :root{--accent:{$accent};--bg:#0b0c0f;--card:#11131a;--txt:#f5f7ff;--muted:#9aa3b2;--line:#23283a;}
    *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#07080b,#0b0c0f);color:var(--txt);}
    .wrap{max-width:420px;margin:0 auto;padding:24px}
    .card{background:rgba(17,19,26,.78);border:1px solid var(--line);border-radius:16px;padding:16px}
    .h1{font-size:18px;font-weight:800;margin:0}
    label{display:block;font-size:12px;color:var(--muted);margin-top:12px}
    input,select{width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);background:#0f1118;color:var(--txt);outline:none}
    .btn{margin-top:14px;width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:var(--accent);color:#fff;font-weight:700}
    .err{margin-top:12px;background:rgba(239,68,68,.14);border:1px solid rgba(239,68,68,.28);color:#fecaca;padding:10px;border-radius:12px;font-size:13px}
    .muted{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.4}
  </style></head><body>";
  echo "<div class='wrap'><div class='card'>";
  echo "<div class='h1'>Create staff account</div>";
  echo "<form method='post' action='?action=staff_register'>";
  echo "<input type='hidden' name='csrf' value='".h($csrf)."'>";
  echo "<label>Email</label><input name='email' type='email' required>";
  echo "<label>Password</label><input name='password' type='password' required>";
  if (is_admin() || $userCount === 0) {
    echo "<label>Role</label><select name='role'><option value='staff'>staff</option><option value='admin'>admin</option></select>";
  }
  echo "<button class='btn' type='submit'>Create</button>";
  if (!empty($err)) echo "<div class='err'>".h($err)."</div>";
  echo "</form>";
  echo "<div class='muted'>Anti-gaming note: to flag device/IP creating many accounts with different phones, add counters in audit_log keyed by ip or a device fingerprint. <a href='SETUP.md'>Docs</a> • <a href='SECURITY.md'>Security</a></div>";
  echo "</div></div></body></html>";
  exit;
}

/* =========================
   Cron endpoints (token protected)
   ========================= */

function require_cron_token(array $CONFIG): void {
  $token = $_GET['token'] ?? '';
  if (!$token || !hash_equals((string)$CONFIG['CRON_TOKEN'], (string)$token)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Forbidden";
    exit;
  }
}

if ($action === 'cron_purge_logs') {
  require_cron_token($CONFIG);
  $pdo = db($CONFIG);
  $days = (int)($CONFIG['RETENTION_DAYS_AUDIT'] ?? 120);
  $st = $pdo->prepare("DELETE FROM audit_log WHERE ts < datetime('now', ?)");
  $st->execute(['-'.$days.' days']);
  header('Content-Type: text/plain; charset=utf-8');
  echo "Purged audit_log older than {$days} days.\n";
  exit;
}

if ($action === 'cron_campaigns') {
  require_cron_token($CONFIG);
  $pdo = db($CONFIG);

  $ran = [];

  $stDue = $pdo->prepare("SELECT * FROM campaigns WHERE scheduled_at IS NOT NULL AND scheduled_at <= ? AND sent_count = 0 ORDER BY scheduled_at ASC LIMIT 50");
  $stDue->execute([now_iso()]);
  foreach ($stDue->fetchAll() as $c) {
    $_GET['id'] = (string)$c['id'];
    $ran[] = "scheduled_campaign_id=".$c['id'];
  }

  foreach (($CONFIG['AUTO_CAMPAIGNS'] ?? []) as $rule) {
    $name = (string)($rule['name'] ?? 'Auto campaign');
    $filters = (array)($rule['filters'] ?? []);
    $channel = (string)($rule['channel'] ?? 'export');
    $msg = (string)($rule['message_template'] ?? 'Hello!');
    $hour = (int)($rule['schedule_hour'] ?? 10);

    $todayKey = gmdate('Y-m-d');
    $exists = $pdo->prepare("SELECT COUNT(*) AS c FROM campaigns WHERE name = ? AND created_at >= datetime('now','-1 day')");
    $exists->execute([$name]);
    if ((int)$exists->fetch()['c'] > 0) continue;

    $segName = $name.' (auto)';
    $segSt = $pdo->prepare("INSERT INTO segments(name, filters_json, last_run_at) VALUES(?,?,NULL)");
    $segSt->execute([$segName, json_encode($filters, JSON_UNESCAPED_SLASHES)]);
    $segmentId = (int)$pdo->lastInsertId();

    $sched = gmdate('Y-m-d').' '.str_pad((string)$hour, 2, '0', STR_PAD_LEFT).':00:00';

    $cst = $pdo->prepare("INSERT INTO campaigns(name, segment_id, channel, message_template, scheduled_at, sent_count, created_at) VALUES(?,?,?,?,?,0,?)");
    $cst->execute([$name, $segmentId, $channel, $msg, $sched, now_iso()]);
    $ran[] = "auto_created=".$name;
  }

  audit($pdo, null, 'cron.campaigns', ['ran' => $ran, 'ip' => client_ip()]);

  header('Content-Type: text/plain; charset=utf-8');
  echo "Cron campaigns OK.\n";
  foreach ($ran as $r) echo $r."\n";
  exit;
}

/* =========================
   API actions (JSON)
   ========================= */

if (str_starts_with($action, 'api_')) {
  require_login();
  $uid = (int)($_SESSION['uid'] ?? 0);
  $store = current_store($pdo, $CONFIG);

  $body = [];
  if ($method === 'POST') {
    require_csrf();
    $body = read_json_body();
  }

  if ($action === 'api_me') {
    json_out(['ok' => true, 'data' => [
      'user' => ['id' => $uid, 'email' => $_SESSION['email'] ?? '', 'role' => $_SESSION['role'] ?? 'staff'],
      'store' => $store,
      'config' => [
        'low_stock_threshold' => (int)$CONFIG['LOW_STOCK_THRESHOLD'],
        'require_marketing_opt_in' => (bool)$CONFIG['REQUIRE_MARKETING_OPT_IN'],
      ],
      'csrf' => csrf_token(),
    ]]);
  }

  if ($action === 'api_settings_update') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);

    $name = trim((string)($body['name'] ?? $store['name']));
    $enableDelivery = !empty($body['enable_delivery']) ? 1 : 0;
    $tax = (float)($body['tax_rate'] ?? $store['tax_rate']);
    $accent = trim((string)($body['accent'] ?? $store['accent']));
    $accentOk = validate_hex_color($accent);
    if (!$accentOk) $accentOk = store_accent_safe($store, $CONFIG);
    $sym = trim((string)($body['currency_symbol'] ?? $store['currency_symbol']));
    if ($sym === '') $sym = (string)$store['currency_symbol'];
    $sym = substr($sym, 0, 4);

    $st = $pdo->prepare("UPDATE stores SET name=?, enable_delivery=?, tax_rate=?, accent=?, currency=?, currency_symbol=? WHERE id=?");
    $st->execute([$name, $enableDelivery, $tax, $accentOk, (string)$store['currency'], $sym, (int)$store['id']]);
    audit($pdo, $uid, 'store.update', ['name' => $name, 'enable_delivery' => $enableDelivery, 'tax_rate' => $tax, 'accent' => $accentOk]);
    json_out(['ok' => true]);
  }

  if ($action === 'api_products_list') {
    $q = trim((string)($_GET['q'] ?? ''));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per = min(50, max(10, (int)($_GET['per'] ?? 25)));
    $off = ($page - 1) * $per;

    $where = "WHERE active = 1";
    $params = [];
    if ($q !== '') {
      $where .= " AND name LIKE ?";
      $params[] = '%'.$q.'%';
    }

    $st = $pdo->prepare("SELECT * FROM products {$where} ORDER BY name ASC LIMIT ? OFFSET ?");
    $params[] = $per;
    $params[] = $off;
    $st->execute($params);
    $rows = $st->fetchAll();

    $cntSt = $pdo->prepare("SELECT COUNT(*) AS c FROM products {$where}");
    $cntSt->execute(array_slice($params, 0, max(0, count($params)-2)));
    $total = (int)$cntSt->fetch()['c'];

    json_out(['ok' => true, 'data' => ['items' => $rows, 'page' => $page, 'per' => $per, 'total' => $total]]);
  }

  if ($action === 'api_product_update') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);

    $id = (int)($body['id'] ?? 0);
    $stock = (int)($body['stock_qty'] ?? 0);
    $active = !empty($body['active']) ? 1 : 0;

    $st = $pdo->prepare("UPDATE products SET stock_qty = ?, active = ? WHERE id = ?");
    $st->execute([$stock, $active, $id]);
    audit($pdo, $uid, 'products.update', ['id' => $id, 'stock_qty' => $stock, 'active' => $active]);

    json_out(['ok' => true]);
  }

  if ($action === 'api_low_stock') {
    $threshold = (int)($CONFIG['LOW_STOCK_THRESHOLD'] ?? 5);
    $st = $pdo->prepare("SELECT id, name, stock_qty, category FROM products WHERE active = 1 AND stock_qty <= ? ORDER BY stock_qty ASC, name ASC LIMIT 50");
    $st->execute([$threshold]);
    json_out(['ok' => true, 'data' => ['threshold' => $threshold, 'items' => $st->fetchAll()]]);
  }

  if ($action === 'api_customers_search') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_read:ip:'.client_ip(), (int)($rl['limit'] ?? 120) * 2, (int)($rl['window_seconds'] ?? 300), true);
    $q = trim((string)($_GET['q'] ?? ''));
    $phone = normalize_phone($q);
    if ($q === '' && $phone === '') json_out(['ok' => true, 'data' => []]);

    $params = [];
    $where = '';
    if ($q === '' && $phone !== '') {
      $where = "WHERE phone = ?";
      $params[] = $phone;
    } else {
      $where = "WHERE (phone LIKE ? OR name LIKE ? OR email LIKE ?";
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
      if ($phone !== '') {
        $where .= " OR phone = ?";
        $params[] = $phone;
      }
      $where .= ")";
    }

    $st = $pdo->prepare("SELECT id, phone, name, marketing_opt_in, last_order_at, total_spent_cents, order_count, tags_text, created_at FROM customers {$where} ORDER BY COALESCE(last_order_at, created_at) DESC LIMIT 50");
    $st->execute($params);
    $rows = $st->fetchAll();
    json_out(['ok' => true, 'data' => $rows]);
  }

  if ($action === 'api_customer_get') {
    $id = (int)($_GET['id'] ?? 0);
    $phone = normalize_phone((string)($_GET['phone'] ?? ''));
    if ($id === 0 && $phone === '') json_out(['ok' => false, 'error' => 'Missing id or phone'], 400);

    if ($id > 0) {
      $st = $pdo->prepare("SELECT * FROM customers WHERE id = ?");
      $st->execute([$id]);
    } else {
      $st = $pdo->prepare("SELECT * FROM customers WHERE phone = ?");
      $st->execute([$phone]);
    }
    $cust = $st->fetch();
    if (!$cust) json_out(['ok' => false, 'error' => 'Not found'], 404);

    $o = $pdo->prepare("SELECT id, order_code, order_type, status, total_cents, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT 20");
    $o->execute([(int)$cust['id']]);

    $cust['ltv_estimate'] = calc_customer_ltv($CONFIG, $cust);
    json_out(['ok' => true, 'data' => ['customer' => $cust, 'orders' => $o->fetchAll()]]);
  }

  if ($action === 'api_customer_upsert') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $phone = normalize_phone((string)($body['phone'] ?? ''));
    if ($phone === '') json_out(['ok' => false, 'error' => 'Phone required'], 400);

    $name = trim((string)($body['name'] ?? ''));
    $address = trim((string)($body['address'] ?? ''));
    $email = trim((string)($body['email'] ?? ''));
    $optIn = !empty($body['marketing_opt_in']) ? 1 : 0;
    $tags = $body['tags'] ?? [];
    $tagsText = is_array($tags) ? tags_to_text($tags) : '';

    $lat = isset($body['lat']) && $body['lat'] !== '' ? (float)$body['lat'] : null;
    $lng = isset($body['lng']) && $body['lng'] !== '' ? (float)$body['lng'] : null;

    $st = $pdo->prepare("SELECT id, marketing_opt_in FROM customers WHERE phone = ?");
    $st->execute([$phone]);
    $existing = $st->fetch();

    if ($existing) {
      $prevOpt = (int)$existing['marketing_opt_in'];
      $optTs = null;
      if ($optIn === 1 && $prevOpt === 0) $optTs = now_iso();

      $up = $pdo->prepare("
        UPDATE customers
        SET name = COALESCE(NULLIF(?,''), name),
            address = COALESCE(NULLIF(?,''), address),
            email = COALESCE(NULLIF(?,''), email),
            marketing_opt_in = ?,
            marketing_opt_in_ts = COALESCE(?, marketing_opt_in_ts),
            tags_text = COALESCE(NULLIF(?,''), tags_text),
            lat = COALESCE(?, lat),
            lng = COALESCE(?, lng)
        WHERE id = ?
      ");
      $up->execute([$name, $address, $email, $optIn, $optTs, $tagsText, $lat, $lng, (int)$existing['id']]);
      audit($pdo, $uid, 'customers.update', ['phone' => $phone, 'marketing_opt_in' => $optIn]);
      json_out(['ok' => true, 'data' => ['id' => (int)$existing['id']]]);
    } else {
      $ins = $pdo->prepare("INSERT INTO customers(phone,name,address,email,marketing_opt_in,marketing_opt_in_ts,tags_text,metadata_json,lat,lng,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
      $ins->execute([$phone, $name ?: null, $address ?: null, $email ?: null, $optIn, $optIn ? now_iso() : null, $tagsText, '{}', $lat, $lng, now_iso()]);
      $idNew = (int)$pdo->lastInsertId();
      audit($pdo, $uid, 'customers.create', ['phone' => $phone, 'id' => $idNew, 'ip' => client_ip()]);
      json_out(['ok' => true, 'data' => ['id' => $idNew]]);
    }
  }

  if ($action === 'api_orders_create') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $cart = $body['items'] ?? [];
    if (!is_array($cart) || count($cart) === 0) json_out(['ok' => false, 'error' => 'Cart empty'], 400);

    $orderType = (string)($body['order_type'] ?? 'pickup');
    $allowed = ['dine_in','pickup','delivery'];
    if (!in_array($orderType, $allowed, true)) $orderType = 'pickup';
    if ($orderType === 'delivery' && (int)$store['enable_delivery'] !== 1) $orderType = 'pickup';

    $walkin = !empty($body['walkin']) ? 1 : 0;

    $phone = normalize_phone((string)($body['phone'] ?? ''));
    $custId = null;
    $phoneText = null;

    if ($walkin === 0) {
      if ($phone === '') json_out(['ok' => false, 'error' => 'Customer phone required (or mark walk-in)'], 400);
      $phoneText = $phone;

      $stc = $pdo->prepare("SELECT id FROM customers WHERE phone = ?");
      $stc->execute([$phone]);
      $found = $stc->fetch();
      if ($found) {
        $custId = (int)$found['id'];
      } else {
        $name = trim((string)($body['customer_name'] ?? ''));
        $address = trim((string)($body['customer_address'] ?? ''));
        $optIn = !empty($body['marketing_opt_in']) ? 1 : 0;

        $ins = $pdo->prepare("INSERT INTO customers(phone,name,address,email,marketing_opt_in,marketing_opt_in_ts,tags_text,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
        $ins->execute([$phone, $name ?: null, $address ?: null, null, $optIn, $optIn ? now_iso() : null, '', '{}', now_iso()]);
        $custId = (int)$pdo->lastInsertId();
        audit($pdo, $uid, 'customers.create.via_pos', ['phone' => $phone, 'id' => $custId]);
      }
    } else {
      $phoneText = (string)($body['walkin_label'] ?? 'WALK-IN');
    }

    $subtotal = 0;
    $itemsOut = [];
    $itemsForDb = [];

    foreach ($cart as $line) {
      $pid = (int)($line['product_id'] ?? 0);
      $qty = max(1, (int)($line['qty'] ?? 1));
      $notes = trim((string)($line['notes'] ?? ''));

      $stp = $pdo->prepare("SELECT id,name,price_cents,category,stock_qty,active FROM products WHERE id = ?");
      $stp->execute([$pid]);
      $p = $stp->fetch();
      if (!$p || (int)$p['active'] !== 1) continue;

      $price = (int)$p['price_cents'];
      $lineTotal = $price * $qty;
      $subtotal += $lineTotal;

      $itemsOut[] = [
        'product_id' => (int)$p['id'],
        'name' => (string)$p['name'],
        'qty' => $qty,
        'price_cents' => $price,
        'notes' => $notes,
        'line_total_cents' => $lineTotal,
        'category' => (string)($p['category'] ?? ''),
      ];

      $itemsForDb[] = [$pid, (string)$p['name'], (string)($p['category'] ?? ''), $qty, $price, $notes];
    }

    if (count($itemsOut) === 0) json_out(['ok' => false, 'error' => 'No valid items'], 400);

    $taxRate = (float)$store['tax_rate'];
    $tax = (int)round($subtotal * $taxRate);
    $tip = (int)max(0, (int)($body['tip_cents'] ?? 0));
    $total = $subtotal + $tax + $tip;

    $eta = (int)max(5, (int)($body['expected_eta_minutes'] ?? 15));
    $paymentMethod = (string)($body['payment_method'] ?? 'cash');
    if (!in_array($paymentMethod, ['cash','card','online'], true)) $paymentMethod = 'cash';
    $paid = !empty($body['payment_received']) ? 1 : 0;

    $orderCode = rand_code(8);
    $ts = now_iso();

    $pdo->beginTransaction();

    $ins = $pdo->prepare("
      INSERT INTO orders(order_code,customer_id,phone_text,order_type,items_json,subtotal_cents,tax_cents,tip_cents,total_cents,status,payment_method,payment_received,expected_eta_minutes,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ");
    $ins->execute([
      $orderCode,
      $custId,
      $phoneText,
      $orderType,
      json_encode($itemsOut, JSON_UNESCAPED_SLASHES),
      $subtotal,
      $tax,
      $tip,
      $total,
      'new',
      $paymentMethod,
      $paid,
      $eta,
      $ts,
      $ts,
    ]);
    $orderId = (int)$pdo->lastInsertId();

    $insIt = $pdo->prepare("INSERT INTO order_items(order_id,product_id,product_name,category,qty,price_cents,notes,created_at) VALUES(?,?,?,?,?,?,?,?)");
    foreach ($itemsForDb as $it) {
      $insIt->execute([$orderId, $it[0], $it[1], $it[2], $it[3], $it[4], $it[5], $ts]);
    }

    if (($CONFIG['STOCK_DECREMENT_ON'] ?? 'complete') === 'create') {
      $stItems = $pdo->prepare("SELECT product_id, qty FROM order_items WHERE order_id = ? AND product_id IS NOT NULL");
      $stItems->execute([$orderId]);
      foreach ($stItems->fetchAll() as $it) {
        $pdo->prepare("UPDATE products SET stock_qty = stock_qty - ? WHERE id = ?")->execute([(int)$it['qty'], (int)$it['product_id']]);
      }
      $pdo->prepare("UPDATE orders SET stock_applied = 1 WHERE id = ?")->execute([$orderId]);
    }

    audit($pdo, $uid, 'orders.create', ['order_id' => $orderId, 'order_code' => $orderCode, 'total_cents' => $total, 'ip' => client_ip()]);

    $pdo->commit();

    json_out(['ok' => true, 'data' => ['order_id' => $orderId, 'order_code' => $orderCode]]);
  }

  if ($action === 'api_orders_list') {
    $status = (string)($_GET['status'] ?? 'active');
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per = min(50, max(10, (int)($_GET['per'] ?? 20)));
    $off = ($page - 1) * $per;

    $where = "WHERE 1=1";
    $params = [];
    if ($status === 'active') {
      $where .= " AND status IN ('new','preparing','ready_for_pickup','out_for_delivery')";
    } elseif ($status !== 'all') {
      $where .= " AND status = ?";
      $params[] = $status;
    }

    $st = $pdo->prepare("SELECT id, order_code, order_type, phone_text, total_cents, status, payment_method, payment_received, expected_eta_minutes, created_at, updated_at FROM orders {$where} ORDER BY created_at DESC LIMIT ? OFFSET ?");
    $params[] = $per;
    $params[] = $off;
    $st->execute($params);
    json_out(['ok' => true, 'data' => $st->fetchAll()]);
  }

  if ($action === 'api_order_get') {
    $id = (int)($_GET['id'] ?? 0);
    $st = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
    $st->execute([$id]);
    $o = $st->fetch();
    if (!$o) json_out(['ok' => false, 'error' => 'Not found'], 404);
    $o['items'] = json_decode((string)$o['items_json'], true) ?: [];
    json_out(['ok' => true, 'data' => $o]);
  }

  if ($action === 'api_order_status_update') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $id = (int)($body['id'] ?? 0);
    $status = (string)($body['status'] ?? '');
    $allowed = ['new','preparing','ready_for_pickup','out_for_delivery','completed','cancelled'];
    if (!in_array($status, $allowed, true)) json_out(['ok' => false, 'error' => 'Invalid status'], 400);

    $st = $pdo->prepare("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?");
    $st->execute([$status, now_iso(), $id]);
    audit($pdo, $uid, 'orders.status', ['id' => $id, 'status' => $status]);

    if ($status === 'completed') {
      apply_order_effects($pdo, $CONFIG, $id);
    }

    json_out(['ok' => true]);
  }

  if ($action === 'api_segments_list') {
    $rows = $pdo->query("SELECT id, name, filters_json, last_run_at FROM segments ORDER BY id DESC LIMIT 50")->fetchAll();
    json_out(['ok' => true, 'data' => $rows]);
  }

  if ($action === 'api_segment_create') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $name = trim((string)($body['name'] ?? ''));
    $filters = (array)($body['filters'] ?? []);
    if ($name === '') json_out(['ok' => false, 'error' => 'Name required'], 400);

    $st = $pdo->prepare("INSERT INTO segments(name, filters_json, last_run_at) VALUES(?,?,NULL)");
    $st->execute([$name, json_encode($filters, JSON_UNESCAPED_SLASHES)]);
    audit($pdo, $uid, 'segments.create', ['name' => $name]);

    json_out(['ok' => true, 'data' => ['id' => (int)$pdo->lastInsertId()]]);
  }

  if ($action === 'api_segment_preview') {
    $filters = (array)($body['filters'] ?? []);
    $filters['marketing_opt_in_only'] = !empty($filters['marketing_opt_in_only']);
    $rows = segment_query($pdo, $filters, 50, 0);
    $count = segment_count($pdo, $filters);

    $pdo->prepare("UPDATE segments SET last_run_at = ? WHERE id = ?")->execute([now_iso(), (int)($body['segment_id'] ?? 0)]);
    audit($pdo, $uid, 'segments.preview', ['count' => $count]);

    json_out(['ok' => true, 'data' => ['count' => $count, 'sample' => $rows]]);
  }

  if ($action === 'api_campaigns_list') {
    $rows = $pdo->query("
      SELECT c.id, c.name, c.segment_id, s.name AS segment_name, c.channel, c.scheduled_at, c.sent_count, c.created_at
      FROM campaigns c
      LEFT JOIN segments s ON s.id = c.segment_id
      ORDER BY c.id DESC
      LIMIT 50
    ")->fetchAll();
    json_out(['ok' => true, 'data' => $rows]);
  }

  if ($action === 'api_campaign_create') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $name = trim((string)($body['name'] ?? ''));
    $segmentId = (int)($body['segment_id'] ?? 0);
    $channel = (string)($body['channel'] ?? 'export');
    $msg = trim((string)($body['message_template'] ?? ''));

    if ($name === '' || $segmentId <= 0 || $msg === '') json_out(['ok' => false, 'error' => 'Missing fields'], 400);
    if (!in_array($channel, ['sms','email','export'], true)) $channel = 'export';

    $scheduledAt = null;
    if (!empty($body['scheduled_at'])) $scheduledAt = (string)$body['scheduled_at'];

    $st = $pdo->prepare("INSERT INTO campaigns(name, segment_id, channel, message_template, scheduled_at, sent_count, created_at) VALUES(?,?,?,?,?,0,?)");
    $st->execute([$name, $segmentId, $channel, $msg, $scheduledAt, now_iso()]);
    $id = (int)$pdo->lastInsertId();
    audit($pdo, $uid, 'campaigns.create', ['id' => $id, 'name' => $name, 'channel' => $channel]);

    json_out(['ok' => true, 'data' => ['id' => $id]]);
  }

  if ($action === 'api_campaign_send') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $id = (int)($body['id'] ?? 0);
    $overrideOptIn = !empty($body['override_opt_in']) ? 1 : 0;
    $withCoupons = !empty($body['with_coupons']) ? 1 : 0;

    $st = $pdo->prepare("SELECT * FROM campaigns WHERE id = ?");
    $st->execute([$id]);
    $camp = $st->fetch();
    if (!$camp) json_out(['ok' => false, 'error' => 'Not found'], 404);

    $seg = $pdo->prepare("SELECT * FROM segments WHERE id = ?");
    $seg->execute([(int)$camp['segment_id']]);
    $segRow = $seg->fetch();
    if (!$segRow) json_out(['ok' => false, 'error' => 'Segment missing'], 400);

    $filters = parse_filters((string)$segRow['filters_json']);
    $filters['marketing_opt_in_only'] = ($CONFIG['REQUIRE_MARKETING_OPT_IN'] ?? true) ? ($overrideOptIn ? false : true) : false;

    $recipients = segment_query($pdo, $filters, 5000, 0);

    $pdo->beginTransaction();
    $pdo->prepare("DELETE FROM campaign_recipients WHERE campaign_id = ?")->execute([$id]);

    $ins = $pdo->prepare("INSERT INTO campaign_recipients(campaign_id, customer_id, phone, email, coupon_code, sent_at, status, payload_json) VALUES(?,?,?,?,?,?,?,?)");

    $sentCount = 0;
    foreach ($recipients as $c) {
      $coupon = null;
      if ($withCoupons && !empty($CONFIG['COUPON']['ENABLED'])) {
        $coupon = (string)$CONFIG['COUPON']['PREFIX'].'-'.rand_code((int)$CONFIG['COUPON']['LENGTH']);
      }
      $payload = [
        'message' => (string)$camp['message_template'],
        'coupon_code' => $coupon,
        'opt_in_required' => (bool)($CONFIG['REQUIRE_MARKETING_OPT_IN'] ?? true),
        'opt_in_overridden' => (bool)$overrideOptIn,
      ];
      $ins->execute([
        $id,
        (int)$c['id'],
        (string)$c['phone'],
        (string)($c['email'] ?? ''),
        $coupon,
        null,
        'queued',
        json_encode($payload, JSON_UNESCAPED_SLASHES),
      ]);
      $sentCount++;
    }

    $pdo->prepare("UPDATE campaigns SET sent_count = ? WHERE id = ?")->execute([$sentCount, $id]);
    audit($pdo, $uid, 'campaigns.queue', ['id' => $id, 'count' => $sentCount, 'override_opt_in' => $overrideOptIn, 'with_coupons' => $withCoupons]);

    $pdo->commit();

    json_out(['ok' => true, 'data' => ['queued' => $sentCount]]);
  }

  if ($action === 'api_campaign_simulate') {
    $segmentId = (int)($body['segment_id'] ?? 0);
    $red = (float)($body['redemption_rate'] ?? ($CONFIG['SIMULATOR']['DEFAULT_REDEMPTION_RATE'] ?? 0.06));
    $lift = (float)($body['coupon_lift'] ?? ($CONFIG['SIMULATOR']['DEFAULT_COUPON_LIFT'] ?? 0.12));
    $overrideOptIn = !empty($body['override_opt_in']) ? 1 : 0;

    $seg = $pdo->prepare("SELECT * FROM segments WHERE id = ?");
    $seg->execute([$segmentId]);
    $segRow = $seg->fetch();
    if (!$segRow) json_out(['ok' => false, 'error' => 'Segment not found'], 404);

    $filters = parse_filters((string)$segRow['filters_json']);
    $filters['marketing_opt_in_only'] = ($CONFIG['REQUIRE_MARKETING_OPT_IN'] ?? true) ? ($overrideOptIn ? false : true) : false;

    $rows = segment_query($pdo, $filters, 5000, 0);
    $count = count($rows);

    $avgSpend = 0.0;
    if ($count > 0) {
      $sum = 0;
      $oc = 0;
      foreach ($rows as $c) {
        $sum += (int)$c['total_spent_cents'];
        $oc += max(1, (int)$c['order_count']);
      }
      $avgSpend = ($oc > 0) ? ($sum / $oc) : 0.0;
    }

    $expectedRecipients = $count;
    $expectedRedemptions = (int)round($expectedRecipients * $red);
    $expectedRevenueCents = (int)round($expectedRedemptions * $avgSpend * (1.0 + $lift));

    json_out(['ok' => true, 'data' => [
      'recipients' => $expectedRecipients,
      'expected_redemptions' => $expectedRedemptions,
      'expected_revenue_cents' => $expectedRevenueCents,
      'avg_order_value_cents_est' => (int)round($avgSpend),
      'assumptions' => ['redemption_rate' => $red, 'coupon_lift' => $lift],
    ]]);
  }

  if ($action === 'api_load_sample_data') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'sample:ip:'.client_ip(), 3, 3600, true);

    $pdo->beginTransaction();

    $storeCnt = (int)$pdo->query("SELECT COUNT(*) AS c FROM stores")->fetch()['c'];
    if ($storeCnt === 0) {
      $st2 = $pdo->prepare("INSERT INTO stores(name, enable_delivery, tax_rate, accent, currency, currency_symbol, created_at) VALUES(?,?,?,?,?,?,?)");
      $st2->execute(['Neighbour Store', 1, 0.08, (string)$CONFIG['ACCENT'], (string)$CONFIG['CURRENCY'], (string)$CONFIG['CURRENCY_SYMBOL'], now_iso()]);
    }

    $prodCnt = (int)$pdo->query("SELECT COUNT(*) AS c FROM products")->fetch()['c'];
    if ($prodCnt === 0) {
      $products = [
        ['BAG-001','Bagel Classic', 399, 40, 'Bakery'],
        ['COF-001','Coffee (Small)', 299, 120, 'Drinks'],
        ['COF-002','Coffee (Large)', 399, 90, 'Drinks'],
        ['TEA-001','Iced Tea', 349, 60, 'Drinks'],
        ['SND-001','Turkey Sandwich', 899, 25, 'Deli'],
        ['SND-002','Veggie Wrap', 799, 18, 'Deli'],
        ['SNK-001','Chips', 199, 12, 'Snacks'],
        ['SNK-002','Granola Bar', 149, 9, 'Snacks'],
        ['DES-001','Cookie', 179, 6, 'Dessert'],
        ['DES-002','Brownie', 249, 4, 'Dessert'],
      ];
      $ins = $pdo->prepare("INSERT INTO products(sku,name,price_cents,stock_qty,category,active,created_at) VALUES(?,?,?,?,?,?,?)");
      foreach ($products as $p) $ins->execute([$p[0], $p[1], $p[2], $p[3], $p[4], 1, now_iso()]);
    }

    $custCnt = (int)$pdo->query("SELECT COUNT(*) AS c FROM customers")->fetch()['c'];
    if ($custCnt === 0) {
      $customers = [
        ['+14155550101','Maya','12 Oak St','maya@example.com',1,['vip','nearby'], null, null],
        ['+14155550102','Jordan','99 Pine Ave','',0,['new'], null, null],
        ['+14155550103','Sam','5 Cedar Rd','sam@example.com',1,['deli_fan'], null, null],
      ];
      $ins = $pdo->prepare("INSERT INTO customers(phone,name,address,email,marketing_opt_in,marketing_opt_in_ts,tags_text,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
      foreach ($customers as $c) {
        $tagsText = tags_to_text($c[5]);
        $ins->execute([$c[0], $c[1], $c[2], $c[3] ?: null, $c[4], $c[4] ? now_iso() : null, $tagsText, '{}', now_iso()]);
      }

      $custs = $pdo->query("SELECT id, phone FROM customers ORDER BY id ASC")->fetchAll();
      $prods = $pdo->query("SELECT id, name, price_cents, category FROM products ORDER BY id ASC")->fetchAll();

      $makeOrder = function(int $customerId, string $phone, array $items, string $status, string $createdAt) use ($pdo) {
        $subtotal = 0;
        foreach ($items as &$it) {
          $it['line_total_cents'] = $it['price_cents'] * $it['qty'];
          $subtotal += $it['line_total_cents'];
        }
        $tax = (int)round($subtotal * 0.08);
        $tip = 0;
        $total = $subtotal + $tax + $tip;
        $code = rand_code(8);

        $ins = $pdo->prepare("INSERT INTO orders(order_code,customer_id,phone_text,order_type,items_json,subtotal_cents,tax_cents,tip_cents,total_cents,status,payment_method,payment_received,expected_eta_minutes,created_at,updated_at,stock_applied,metrics_applied) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        $ins->execute([$code,$customerId,$phone,'pickup',json_encode($items,JSON_UNESCAPED_SLASHES),$subtotal,$tax,$tip,$total,$status,'card',1,15,$createdAt,$createdAt,1,1]);
        $oid = (int)$pdo->lastInsertId();
        $insIt = $pdo->prepare("INSERT INTO order_items(order_id,product_id,product_name,category,qty,price_cents,notes,created_at) VALUES(?,?,?,?,?,?,?,?)");
        foreach ($items as $it) {
          $insIt->execute([$oid, $it['product_id'], $it['name'], $it['category'], $it['qty'], $it['price_cents'], $it['notes'] ?? '', $createdAt]);
        }
        $pdo->prepare("UPDATE customers SET last_order_at=?, total_spent_cents=total_spent_cents+?, order_count=order_count+1 WHERE id=?")
          ->execute([$createdAt, $total, $customerId]);
      };

      $pmap = [];
      foreach ($prods as $p) $pmap[(int)$p['id']] = $p;

      $t1 = gmdate('Y-m-d H:i:s', time() - 40*86400);
      $t2 = gmdate('Y-m-d H:i:s', time() - 12*86400);
      $t3 = gmdate('Y-m-d H:i:s', time() - 2*86400);

      $makeOrder((int)$custs[0]['id'], (string)$custs[0]['phone'], [
        ['product_id'=>$prods[1]['id'],'name'=>$prods[1]['name'],'qty'=>2,'price_cents'=>$prods[1]['price_cents'],'category'=>$prods[1]['category'],'notes'=>''],
        ['product_id'=>$prods[4]['id'],'name'=>$prods[4]['name'],'qty'=>1,'price_cents'=>$prods[4]['price_cents'],'category'=>$prods[4]['category'],'notes'=>'extra mustard'],
      ], 'completed', $t3);

      $makeOrder((int)$custs[0]['id'], (string)$custs[0]['phone'], [
        ['product_id'=>$prods[0]['id'],'name'=>$prods[0]['name'],'qty'=>3,'price_cents'=>$prods[0]['price_cents'],'category'=>$prods[0]['category'],'notes'=>''],
      ], 'completed', $t2);

      $makeOrder((int)$custs[1]['id'], (string)$custs[1]['phone'], [
        ['product_id'=>$prods[2]['id'],'name'=>$prods[2]['name'],'qty'=>1,'price_cents'=>$prods[2]['price_cents'],'category'=>$prods[2]['category'],'notes'=>''],
        ['product_id'=>$prods[8]['id'],'name'=>$prods[8]['name'],'qty'=>1,'price_cents'=>$prods[8]['price_cents'],'category'=>$prods[8]['category'],'notes'=>''],
      ], 'completed', $t2);

      $makeOrder((int)$custs[2]['id'], (string)$custs[2]['phone'], [
        ['product_id'=>$prods[5]['id'],'name'=>$prods[5]['name'],'qty'=>2,'price_cents'=>$prods[5]['price_cents'],'category'=>$prods[5]['category'],'notes'=>'no onion'],
      ], 'completed', $t1);
    }

    audit($pdo, $uid, 'sample.load', ['ip' => client_ip()]);
    $pdo->commit();

    json_out(['ok' => true]);
  }

  json_out(['ok' => false, 'error' => 'Unknown API action'], 404);
}

/* =========================
   Public customer portal
   ========================= */

if ($action === 'portal') {
  $store = current_store($pdo, $CONFIG);
  $accent = store_accent_safe($store, $CONFIG);

  $phone = normalize_phone((string)($_GET['phone'] ?? ''));
  $orders = [];
  $cust = null;

  if ($phone !== '') {
    $st = $pdo->prepare("SELECT id, phone, name, marketing_opt_in, marketing_opt_in_ts, created_at FROM customers WHERE phone = ?");
    $st->execute([$phone]);
    $cust = $st->fetch();

    $o = $pdo->prepare("SELECT order_code, order_type, status, total_cents, created_at, expected_eta_minutes FROM orders WHERE phone_text = ? ORDER BY created_at DESC LIMIT 10");
    $o->execute([$phone]);
    $orders = $o->fetchAll();
  }

  echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  echo "<title>".h($CONFIG['APP_NAME'])." — Order Status</title>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>
    :root{--accent:{$accent};--bg:#0b0c0f;--card:#11131a;--txt:#f5f7ff;--muted:#9aa3b2;--line:#23283a;}
    *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#07080b;color:var(--txt);}
    .wrap{max-width:520px;margin:0 auto;padding:18px}
    .card{background:rgba(17,19,26,.78);border:1px solid var(--line);border-radius:16px;padding:14px;margin-top:12px}
    .h1{font-size:16px;font-weight:800;margin:0}
    .muted{color:var(--muted);font-size:12px;line-height:1.4}
    input{width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);background:#0f1118;color:var(--txt);outline:none;margin-top:10px}
    .btn{margin-top:10px;width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:var(--accent);color:#fff;font-weight:700}
    .row{display:flex;justify-content:space-between;gap:10px;align-items:center}
    .badge{font-size:11px;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.1);color:#cbd5e1}
    .b-new{background:rgba(37,99,235,.12);border-color:rgba(37,99,235,.22)}
    .b-prep{background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.22)}
    .b-ready{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.22)}
    .b-out{background:rgba(147,51,234,.12);border-color:rgba(147,51,234,.22)}
    .b-done{background:rgba(100,116,139,.18);border-color:rgba(100,116,139,.26)}
  </style></head><body><div class='wrap'>";
  echo "<div class='card'><div class='h1'>Order status lookup</div><div class='muted'>Enter your phone number to see recent orders and current status.</div>";
  echo "<form method='get'><input type='hidden' name='action' value='portal'>";
  echo "<input name='phone' placeholder='Phone (e.g., +14155550101)' value='".h($_GET['phone'] ?? '')."'>";
  echo "<button class='btn' type='submit'>Lookup</button></form></div>";

  if ($phone !== '') {
    if (!$cust) {
      echo "<div class='card'><div class='h1'>Not found</div><div class='muted'>No customer record for ".h($phone).". Ask staff to add you at checkout.</div></div>";
    } else {
      echo "<div class='card'><div class='h1'>".h($cust['name'] ?: $cust['phone'])."</div>";
      echo "<div class='muted'>Marketing opt-in: ".(((int)$cust['marketing_opt_in'] === 1) ? "Yes" : "No")."</div></div>";

      echo "<div class='card'><div class='h1'>Recent orders</div>";
      if (!$orders) echo "<div class='muted' style='margin-top:8px'>No orders yet.</div>";
      foreach ($orders as $o) {
        $st = (string)$o['status'];
        $cls = 'b-new';
        if ($st === 'preparing') $cls = 'b-prep';
        if ($st === 'ready_for_pickup') $cls = 'b-ready';
        if ($st === 'out_for_delivery') $cls = 'b-out';
        if ($st === 'completed' || $st === 'cancelled') $cls = 'b-done';
        echo "<div style='margin-top:10px;padding-top:10px;border-top:1px solid var(--line)'>";
        echo "<div class='row'><div><div style='font-weight:700'>".h($o['order_code'])."</div><div class='muted'>".h($o['order_type'])." • ".h($o['created_at'])."</div></div>";
        echo "<div class='badge {$cls}'>".h($st)."</div></div>";
        echo "<div class='muted' style='margin-top:6px'>Total: ".h(money_fmt($CONFIG, (int)$o['total_cents']))." • ETA: ".(int)$o['expected_eta_minutes']." min</div>";
        echo "</div>";
      }
      echo "</div>";
    }
  }

  echo "<div class='card'><div class='muted'>Disclaimer: Status updates depend on staff actions. For marketing messages, opt-in is required by default; stores must comply with local laws and keep consent proof. <a href='SECURITY.md'>Security</a></div></div>";
  echo "</div></body></html>";
  exit;
}

/* =========================
   Receipt (printable)
   ========================= */

if ($action === 'receipt') {
  require_login();
  $id = (int)($_GET['id'] ?? 0);
  $st = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
  $st->execute([$id]);
  $o = $st->fetch();
  if (!$o) { http_response_code(404); echo "Not found"; exit; }

  $store = current_store($pdo, $CONFIG);
  $items = json_decode((string)$o['items_json'], true) ?: [];

  echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  echo "<title>Receipt ".h($o['order_code'])."</title>";
  echo "<style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;padding:16px;color:#111}
    .wrap{max-width:520px;margin:0 auto}
    .h1{font-size:18px;font-weight:800;margin:0}
    .muted{color:#555;font-size:12px}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    td{padding:8px 0;border-bottom:1px solid #eee;font-size:13px}
    .right{text-align:right}
    .tot{font-weight:800}
    @media print{button{display:none}}
  </style></head><body><div class='wrap'>";
  echo "<button onclick='window.print()' style='padding:10px 12px;border:1px solid #ddd;border-radius:10px;background:#fff;font-weight:700'>Print</button>";
  echo "<div style='margin-top:10px'><div class='h1'>".h($store['name'])."</div><div class='muted'>Order ".h($o['order_code'])." • ".h($o['created_at'])."</div>";
  echo "<div class='muted'>Type: ".h($o['order_type'])." • Status: ".h($o['status'])."</div>";
  echo "<div class='muted'>Customer: ".h((string)($o['phone_text'] ?? ''))."</div></div>";

  echo "<table>";
  foreach ($items as $it) {
    $name = (string)($it['name'] ?? 'Item');
    $qty = (int)($it['qty'] ?? 1);
    $price = (int)($it['price_cents'] ?? 0);
    $notes = (string)($it['notes'] ?? '');
    echo "<tr><td>".h($qty."× ".$name).($notes ? "<div class='muted'>".h($notes)."</div>" : "")."</td><td class='right'>".h(money_fmt($CONFIG, $price*$qty))."</td></tr>";
  }
  echo "<tr><td class='right muted'>Subtotal</td><td class='right'>".h(money_fmt($CONFIG, (int)$o['subtotal_cents']))."</td></tr>";
  echo "<tr><td class='right muted'>Tax</td><td class='right'>".h(money_fmt($CONFIG, (int)$o['tax_cents']))."</td></tr>";
  echo "<tr><td class='right muted'>Tip</td><td class='right'>".h(money_fmt($CONFIG, (int)$o['tip_cents']))."</td></tr>";
  echo "<tr><td class='right tot'>Total</td><td class='right tot'>".h(money_fmt($CONFIG, (int)$o['total_cents']))."</td></tr>";
  echo "<tr><td class='right muted'>Payment</td><td class='right'>".h($o['payment_method'])." • ".(((int)$o['payment_received']===1) ? "received" : "pending")."</td></tr>";
  echo "</table>";

  echo "<div class='muted' style='margin-top:14px'>Platform does not process payments. Thank you!</div>";
  echo "</div></body></html>";
  exit;
}

/* =========================
   App shell (mobile-first UI)
   ========================= */

require_login();
$store = current_store($pdo, $CONFIG);
$accent = store_accent_safe($store, $CONFIG);
$csrf = csrf_token();

?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="csrf-token" content="<?=h($csrf)?>">
  <title><?=h($CONFIG['APP_NAME'])?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root{
      --accent: <?=$accent?>;
      --bg:#07080b;
      --panel:#0f1118;
      --card:rgba(17,19,26,.78);
      --line:#23283a;
      --txt:#f5f7ff;
      --muted:#9aa3b2;
      --good:#22c55e;
      --warn:#f59e0b;
      --bad:#ef4444;
      --violet:#9333ea;
    }
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#06070a,#07080b);color:var(--txt);}
    a{color:inherit}
    button,input,select,textarea{font-family:inherit}
    .app{max-width:1100px;margin:0 auto;padding:14px;padding-bottom:84px}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
    .brand{display:flex;align-items:center;gap:10px}
    .dot{width:10px;height:10px;border-radius:999px;background:var(--accent);box-shadow:0 0 0 6px rgba(37,99,235,.14)}
    .title{font-weight:900;font-size:16px;letter-spacing:-.02em}
    .sub{color:var(--muted);font-size:12px;margin-top:2px}
    .pill{border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);padding:6px 10px;border-radius:999px;font-size:12px;color:#dbe3f3}
    .grid{display:grid;grid-template-columns:1fr;gap:12px}
    @media(min-width:980px){ .grid{grid-template-columns: 1.2fr .8fr} }

    .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px}
    .h1{font-size:14px;font-weight:900;margin:0}
    .muted{color:var(--muted);font-size:12px;line-height:1.4}
    .row{display:flex;gap:10px;align-items:center}
    .row > *{flex:1}
    .field label{display:block;color:var(--muted);font-size:11px;margin:10px 0 6px}
    .field input,.field select,.field textarea{width:100%;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:#0f1118;color:var(--txt);outline:none}
    .field textarea{min-height:70px;resize:vertical}
    .field input:focus,.field select:focus,.field textarea:focus{border-color:rgba(37,99,235,.6);box-shadow:0 0 0 4px rgba(37,99,235,.14)}

    .btn{padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.06);color:var(--txt);font-weight:800}
    .btn.primary{background:var(--accent);border-color:rgba(255,255,255,.08)}
    .btn.danger{background:rgba(239,68,68,.18);border-color:rgba(239,68,68,.24)}
    .btn.ghost{background:transparent;border-color:rgba(255,255,255,.1)}
    .btn:active{transform:translateY(1px)}
    .btn.small{padding:8px 10px;border-radius:10px;font-size:12px}
    .btn:disabled{opacity:.5}

    .nav{position:fixed;left:0;right:0;bottom:0;background:rgba(9,10,14,.9);backdrop-filter: blur(10px);border-top:1px solid rgba(255,255,255,.06)}
    .navin{max-width:1100px;margin:0 auto;display:grid;grid-template-columns:repeat(5,1fr);gap:6px;padding:10px 12px}
    .tab{display:flex;flex-direction:column;align-items:center;gap:4px;padding:8px 6px;border-radius:14px;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.03);font-size:11px;color:#cbd5e1}
    .tab.active{border-color:rgba(37,99,235,.28);background:rgba(37,99,235,.12);color:#eaf0ff}

    .list{display:flex;flex-direction:column;gap:10px;margin-top:10px}
    .item{padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03)}
    .item .name{font-weight:900;font-size:13px}
    .item .meta{color:var(--muted);font-size:12px;margin-top:4px}
    .badge{font-size:11px;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.1);color:#cbd5e1;white-space:nowrap}
    .b-new{background:rgba(37,99,235,.12);border-color:rgba(37,99,235,.22)}
    .b-prep{background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.22)}
    .b-ready{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.22)}
    .b-out{background:rgba(147,51,234,.12);border-color:rgba(147,51,234,.22)}
    .b-done{background:rgba(100,116,139,.18);border-color:rgba(100,116,139,.26)}
    .kpi{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px}
    .k{padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03)}
    .k .v{font-weight:900;font-size:16px}
    .k .l{color:var(--muted);font-size:11px;margin-top:4px}
    .warnbox{margin-top:10px;padding:10px;border-radius:14px;border:1px solid rgba(245,158,11,.22);background:rgba(245,158,11,.10);color:#fde68a;font-size:12px;line-height:1.35}
    .okbox{margin-top:10px;padding:10px;border-radius:14px;border:1px solid rgba(34,197,94,.22);background:rgba(34,197,94,.10);color:#bbf7d0;font-size:12px;line-height:1.35}
    .errbox{margin-top:10px;padding:10px;border-radius:14px;border:1px solid rgba(239,68,68,.22);background:rgba(239,68,68,.10);color:#fecaca;font-size:12px;line-height:1.35}
  </style>
</head>
<body>
<div class="app">
  <div class="topbar">
    <div class="brand">
      <div class="dot"></div>
      <div>
        <div class="title"><?=h($CONFIG['APP_NAME'])?> <span class="pill"><?=h((string)$store['name'])?></span></div>
        <div class="sub">POS convenience → CRM moat (segments + campaigns). Customer portal: <span class="pill">?action=portal</span></div>
      </div>
    </div>
    <div class="row" style="justify-content:flex-end;flex:0;gap:8px">
      <a class="btn small ghost" href="?action=portal" target="_blank">Customer portal</a>
      <form method="post" action="?action=logout" style="margin:0">
        <input type="hidden" name="csrf" value="<?=h($csrf)?>">
        <button class="btn small ghost" type="submit">Logout</button>
      </form>
    </div>
  </div>

  <div id="view"></div>
</div>

<div class="nav">
  <div class="navin">
    <button class="tab" data-tab="pos">POS</button>
    <button class="tab" data-tab="orders">Orders</button>
    <button class="tab" data-tab="inventory">Inventory</button>
    <button class="tab" data-tab="crm">CRM</button>
    <button class="tab" data-tab="campaigns">Campaigns</button>
  </div>
</div>

<script>
  const CSRF = document.querySelector('meta[name="csrf-token"]').getAttribute('content')
  const $view = document.getElementById('view')
  const state = {
    me: null,
    store: null,
    tab: 'pos',
    products: [],
    cart: [],
    lowStock: [],
    orders: [],
    customerSearch: [],
    selectedCustomer: null,
    customerOrders: [],
    segments: [],
    campaigns: [],
    sim: null
  }

  function qs(sel, el=document){ return el.querySelector(sel) }
  function qsa(sel, el=document){ return [...el.querySelectorAll(sel)] }
  function esc(s){ return (s??'').toString().replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])) }

  async function api(action, {method='GET', body=null, params=null} = {}) {
    let url = `?action=${action}`
    if (params) {
      const u = new URL(url, window.location.href)
      for (const [k,v] of Object.entries(params)) u.searchParams.set(k, v)
      url = u.pathname + u.search
    }
    const opt = { method, headers: { 'Accept':'application/json' } }
    if (method === 'POST') {
      opt.headers['Content-Type'] = 'application/json'
      opt.headers['X-CSRF-Token'] = CSRF
      opt.body = JSON.stringify(body ?? {})
    }
    const res = await fetch(url, opt)
    const data = await res.json().catch(()=>({ok:false,error:'Bad JSON'}))
    if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`)
    return data.data
  }

  function money(cents){
    const sym = state.store?.currency_symbol ?? '$'
    return sym + (cents/100).toFixed(2)
  }

  function badge(status){
    const cls = {
      'new':'b-new','preparing':'b-prep','ready_for_pickup':'b-ready','out_for_delivery':'b-out',
      'completed':'b-done','cancelled':'b-done'
    }[status] || 'b-new'
    return `<span class="badge ${cls}">${esc(status)}</span>`
  }

  function setTab(tab){
    state.tab = tab
    qsa('.tab').forEach(b=>b.classList.toggle('active', b.dataset.tab===tab))
    render()
    window.location.hash = tab
  }

  function cartAdd(p){
    const found = state.cart.find(x=>x.product_id===p.id)
    if (found) found.qty += 1
    else state.cart.push({ product_id:p.id, name:p.name, price_cents:p.price_cents, qty:1, notes:'' })
    render()
  }
  function cartQty(pid, delta){
    const it = state.cart.find(x=>x.product_id===pid)
    if (!it) return
    it.qty = Math.max(1, it.qty + delta)
    render()
  }
  function cartRemove(pid){
    state.cart = state.cart.filter(x=>x.product_id!==pid)
    render()
  }

  function cartTotals(){
    let subtotal = 0
    for (const it of state.cart) subtotal += it.price_cents * it.qty
    const taxRate = Number(state.store?.tax_rate ?? 0)
    const tax = Math.round(subtotal * taxRate)
    const tip = Math.max(0, parseInt(qs('#pos_tip')?.value || '0', 10) || 0)
    return { subtotal, tax, tip, total: subtotal + tax + tip }
  }

  async function loadMe(){
    const data = await api('api_me')
    state.me = data.user
    state.store = data.store
    document.documentElement.style.setProperty('--accent', state.store.accent)
  }

  async function loadProducts(q=''){
    const data = await api('api_products_list', { params: { q, page: 1, per: 30 }})
    state.products = data.items
  }

  async function loadLowStock(){
    const data = await api('api_low_stock')
    state.lowStock = data.items
  }

  async function loadOrders(status='active'){
    state.orders = await api('api_orders_list', { params: { status, page: 1, per: 25 } })
  }

  async function loadSegments(){
    state.segments = await api('api_segments_list')
  }

  async function loadCampaigns(){
    state.campaigns = await api('api_campaigns_list')
  }

  function renderPOS(){
    const enableDelivery = Number(state.store?.enable_delivery ?? 1) === 1
    const totals = cartTotals()

    return `
      <div class="grid">
        <div class="card">
          <div class="h1">Quick Order</div>
          <div class="muted">Search inventory, build cart, capture phone (or walk-in), place order.</div>

          <div class="field">
            <label>Product search</label>
            <input id="pos_q" placeholder="Search products (e.g., coffee, sandwich)">
          </div>

          <div class="list" id="pos_products">
            ${state.products.map(p=>`
              <div class="item">
                <div class="row" style="align-items:flex-start">
                  <div style="flex:1">
                    <div class="name">${esc(p.name)}</div>
                    <div class="meta">${esc(p.category || 'Uncategorized')} • ${money(p.price_cents)} • Stock: ${esc(p.stock_qty)}</div>
                  </div>
                  <div style="flex:0">
                    <button class="btn small primary" data-add="${p.id}">Add</button>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="card">
          <div class="h1">Cart</div>
          <div class="muted">Order type and customer details. Inventory is reduced on <b><?=h($CONFIG['STOCK_DECREMENT_ON'])?></b>.</div>

          <div class="list">
            ${state.cart.length === 0 ? `<div class="muted">Cart empty. Add items from inventory.</div>` : state.cart.map(it=>`
              <div class="item">
                <div class="row" style="align-items:flex-start">
                  <div style="flex:1">
                    <div class="name">${esc(it.name)}</div>
                    <div class="meta">${money(it.price_cents)} each</div>
                  </div>
                  <div style="flex:0;display:flex;gap:6px;align-items:center">
                    <button class="btn small" data-qtyminus="${it.product_id}">-</button>
                    <div class="pill">${esc(it.qty)}</div>
                    <button class="btn small" data-qtyplus="${it.product_id}">+</button>
                    <button class="btn small danger" data-remove="${it.product_id}">×</button>
                  </div>
                </div>
                <div class="field">
                  <label>Modifiers / notes</label>
                  <input data-notes="${it.product_id}" placeholder="e.g., no onion, extra mustard" value="${esc(it.notes||'')}">
                </div>
              </div>
            `).join('')}
          </div>

          <div class="row" style="margin-top:10px">
            <div class="field">
              <label>Order type</label>
              <select id="pos_type">
                <option value="pickup">pickup</option>
                <option value="dine_in">dine-in</option>
                ${enableDelivery ? `<option value="delivery">delivery</option>` : ``}
              </select>
            </div>
            <div class="field">
              <label>ETA (minutes)</label>
              <input id="pos_eta" type="number" min="5" value="15">
            </div>
          </div>

          <div class="row">
            <div class="field">
              <label>Payment method</label>
              <select id="pos_paymethod">
                <option value="cash">cash</option>
                <option value="card">card</option>
                <option value="online">online</option>
              </select>
            </div>
            <div class="field">
              <label>Tip (cents)</label>
              <input id="pos_tip" type="number" min="0" value="0">
            </div>
          </div>

          <div class="row">
            <div class="field">
              <label><input id="pos_paid" type="checkbox"> Mark payment received</label>
              <div class="muted">NeighbourPOS records payment status only (no processing).</div>
            </div>
            <div class="field">
              <label><input id="pos_walkin" type="checkbox"> Walk-in anonymous</label>
              <div class="muted">If checked, customer lookup is skipped.</div>
            </div>
          </div>

          <div class="field">
            <label>Customer phone</label>
            <input id="pos_phone" placeholder="+14155550101">
          </div>
          <div class="row">
            <div class="field">
              <label>Customer name (optional)</label>
              <input id="pos_name" placeholder="Name">
            </div>
            <div class="field">
              <label>Marketing opt-in</label>
              <select id="pos_optin">
                <option value="0">No (default)</option>
                <option value="1">Yes (consented)</option>
              </select>
            </div>
          </div>
          <div class="field">
            <label>Address (optional; recommended for delivery)</label>
            <input id="pos_addr" placeholder="Address">
          </div>

          <div class="kpi">
            <div class="k"><div class="v">${money(totals.subtotal)}</div><div class="l">Subtotal</div></div>
            <div class="k"><div class="v">${money(totals.tax)}</div><div class="l">Tax</div></div>
            <div class="k"><div class="v">${money(totals.tip)}</div><div class="l">Tip</div></div>
            <div class="k"><div class="v">${money(totals.total)}</div><div class="l">Total</div></div>
          </div>

          <button class="btn primary" style="width:100%;margin-top:12px" id="pos_place" ${state.cart.length===0?'disabled':''}>Place order</button>

          <div class="warnbox">
            Compliance warning: only message customers who explicitly opted in. This app defaults marketing_opt_in=false and audits campaign runs.
          </div>
          <div id="pos_msg"></div>
        </div>
      </div>
    `
  }

  function renderOrders(){
    return `
      <div class="card">
        <div class="row" style="align-items:flex-start">
          <div>
            <div class="h1">Active Orders</div>
            <div class="muted">Fast status updates: new → preparing → ready/out → completed/cancelled.</div>
          </div>
          <div style="flex:0;display:flex;gap:8px">
            <button class="btn small" id="orders_refresh">Refresh</button>
            <select class="btn small" id="orders_filter" style="padding:8px 10px">
              <option value="active">active</option>
              <option value="all">all</option>
              <option value="new">new</option>
              <option value="preparing">preparing</option>
              <option value="ready_for_pickup">ready_for_pickup</option>
              <option value="out_for_delivery">out_for_delivery</option>
              <option value="completed">completed</option>
              <option value="cancelled">cancelled</option>
            </select>
          </div>
        </div>

        <div class="list">
          ${state.orders.length===0 ? `<div class="muted" style="margin-top:8px">No orders.</div>` : state.orders.map(o=>`
            <div class="item">
              <div class="row" style="align-items:flex-start">
                <div style="flex:1">
                  <div class="name">${esc(o.order_code)} ${badge(o.status)}</div>
                  <div class="meta">${esc(o.order_type)} • ${money(o.total_cents)} • ${esc(o.phone_text || '')}</div>
                  <div class="meta">${esc(o.created_at)} • Payment: ${esc(o.payment_method)} • ${o.payment_received ? 'received' : 'pending'}</div>
                </div>
                <div style="flex:0;display:flex;flex-direction:column;gap:6px;align-items:stretch">
                  <a class="btn small ghost" target="_blank" href="?action=receipt&id=${o.id}">Receipt</a>
                  <button class="btn small" data-st="${o.id}" data-next="preparing">Preparing</button>
                  <button class="btn small" data-st="${o.id}" data-next="${o.order_type==='delivery'?'out_for_delivery':'ready_for_pickup'}">${o.order_type==='delivery'?'Out for delivery':'Ready'}</button>
                  <button class="btn small primary" data-st="${o.id}" data-next="completed">Complete</button>
                  <button class="btn small danger" data-st="${o.id}" data-next="cancelled">Cancel</button>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
        <div id="orders_msg"></div>
      </div>
    `
  }

  function renderInventory(){
    return `
      <div class="grid">
        <div class="card">
          <div class="h1">Inventory</div>
          <div class="muted">Search products (server-side) and adjust stock. Low-stock alert threshold: <b>${esc(state.me ? '<?=h((string)$CONFIG['LOW_STOCK_THRESHOLD'])?>' : '')}</b></div>

          <div class="field">
            <label>Search</label>
            <input id="inv_q" placeholder="Search inventory">
          </div>

          <div class="list">
            ${state.products.map(p=>`
              <div class="item">
                <div class="row" style="align-items:flex-start">
                  <div style="flex:1">
                    <div class="name">${esc(p.name)}</div>
                    <div class="meta">${esc(p.category || 'Uncategorized')} • ${money(p.price_cents)} • ID ${p.id}</div>
                  </div>
                  <div style="flex:0;min-width:140px">
                    <div class="field" style="margin-top:-6px">
                      <label>Stock</label>
                      <input data-stock="${p.id}" type="number" value="${esc(p.stock_qty)}">
                    </div>
                    <button class="btn small" data-saveprod="${p.id}">Save</button>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>

          <div id="inv_msg"></div>
        </div>

        <div class="card">
          <div class="h1">Low-stock alerts</div>
          <div class="muted">Export lists to CSV for restocking workflows.</div>

          <button class="btn small" id="low_refresh">Refresh</button>
          <div class="list">
            ${state.lowStock.length===0 ? `<div class="muted" style="margin-top:8px">No low-stock products.</div>` : state.lowStock.map(p=>`
              <div class="item">
                <div class="name">${esc(p.name)}</div>
                <div class="meta">${esc(p.category || '')} • Stock: <b>${esc(p.stock_qty)}</b></div>
              </div>
            `).join('')}
          </div>

          <div class="warnbox">
            Shared-hosting tip: for large catalogs, keep using server-side paging and the indexed product name search.
          </div>
        </div>
      </div>
    `
  }

  function renderCRM(){
    const cust = state.selectedCustomer?.customer
    const orders = state.selectedCustomer?.orders || []
    const ltv = cust?.ltv_estimate ? Number(cust.ltv_estimate).toFixed(2) : '0.00'
    return `
      <div class="grid">
        <div class="card">
          <div class="h1">Customers (CRM)</div>
          <div class="muted">Primary identifier is phone. Keep profiles minimal: phone + optional name/address + opt-in.</div>

          <div class="field">
            <label>Search by phone/name/email</label>
            <input id="crm_q" placeholder="e.g., +1415..., Maya, vip">
          </div>

          <div class="list">
            ${state.customerSearch.length===0 ? `<div class="muted">Search to find customers (limit 50).</div>` : state.customerSearch.map(c=>`
              <div class="item" data-cust="${c.id}">
                <div class="row" style="align-items:flex-start">
                  <div style="flex:1">
                    <div class="name">${esc(c.name || c.phone)}</div>
                    <div class="meta">${esc(c.phone)} • Orders: ${esc(c.order_count)} • Spent: ${money(c.total_spent_cents)}</div>
                    <div class="meta">Opt-in: ${c.marketing_opt_in ? 'Yes' : 'No'} • Tags: ${esc((c.tags_text||'').replaceAll(',',' ').trim())}</div>
                  </div>
                  <div style="flex:0">
                    <button class="btn small" data-open="${c.id}">Open</button>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
          <div id="crm_msg"></div>
        </div>

        <div class="card">
          <div class="h1">Profile</div>
          ${!cust ? `<div class="muted" style="margin-top:8px">Select a customer to view details and edit opt-in/tags.</div>` : `
            <div class="kpi">
              <div class="k"><div class="v">${money(cust.total_spent_cents)}</div><div class="l">Total spent</div></div>
              <div class="k"><div class="v">${esc(cust.order_count)}</div><div class="l">Orders</div></div>
              <div class="k"><div class="v">${esc(cust.last_order_at || '—')}</div><div class="l">Last order</div></div>
              <div class="k"><div class="v">${esc(ltv)}</div><div class="l">LTV estimate</div></div>
            </div>

            <div class="field">
              <label>Phone</label>
              <input id="cust_phone" value="${esc(cust.phone)}" disabled>
            </div>
            <div class="row">
              <div class="field">
                <label>Name</label>
                <input id="cust_name" value="${esc(cust.name||'')}">
              </div>
              <div class="field">
                <label>Email</label>
                <input id="cust_email" value="${esc(cust.email||'')}">
              </div>
            </div>
            <div class="field">
              <label>Address</label>
              <input id="cust_addr" value="${esc(cust.address||'')}">
            </div>
            <div class="row">
              <div class="field">
                <label>Marketing opt-in</label>
                <select id="cust_optin">
                  <option value="0" ${cust.marketing_opt_in?'' : 'selected'}>No (default)</option>
                  <option value="1" ${cust.marketing_opt_in?'selected' : ''}>Yes (consented)</option>
                </select>
              </div>
              <div class="field">
                <label>Tags (comma separated)</label>
                <input id="cust_tags" value="${esc((cust.tags_text||'').split(',').filter(Boolean).join(','))}" placeholder="vip,nearby">
              </div>
            </div>
            <button class="btn small primary" id="cust_save">Save</button>

            <div class="warnbox">
              Consent: store should keep proof (timestamp + source). This app stores opt-in timestamp when toggled from No→Yes.
            </div>

            <div style="margin-top:12px">
              <div class="h1">Recent orders</div>
              <div class="list">
                ${orders.length===0 ? `<div class="muted" style="margin-top:8px">No orders yet.</div>` : orders.map(o=>`
                  <div class="item">
                    <div class="row" style="align-items:flex-start">
                      <div style="flex:1">
                        <div class="name">${esc(o.order_code)} ${badge(o.status)}</div>
                        <div class="meta">${esc(o.order_type)} • ${money(o.total_cents)} • ${esc(o.created_at)}</div>
                      </div>
                      <div style="flex:0">
                        <a class="btn small ghost" target="_blank" href="?action=receipt&id=${o.id}">Receipt</a>
                      </div>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          `}
          <div id="cust_msg"></div>
        </div>
      </div>
    `
  }

  function renderCampaigns(){
    return `
      <div class="grid">
        <div class="card">
          <div class="h1">Segments</div>
          <div class="muted">Build reusable filters for targeting (recency, spend, order count, tags, product/category).</div>

          <div class="row">
            <div class="field">
              <label>Name</label>
              <input id="seg_name" placeholder="e.g., VIP inactive 30d">
            </div>
            <div class="field">
              <label>Inactive since (days)</label>
              <input id="seg_inactive" type="number" min="0" placeholder="30">
            </div>
          </div>

          <div class="row">
            <div class="field">
              <label>Total spent min (cents)</label>
              <input id="seg_spent_min" type="number" min="0" placeholder="2000">
            </div>
            <div class="field">
              <label>Order count min</label>
              <input id="seg_orders_min" type="number" min="0" placeholder="2">
            </div>
          </div>

          <div class="row">
            <div class="field">
              <label>Purchased category (optional)</label>
              <input id="seg_cat" placeholder="Deli">
            </div>
            <div class="field">
              <label>Tag any (comma separated)</label>
              <input id="seg_tags" placeholder="vip,nearby">
            </div>
          </div>

          <button class="btn small primary" id="seg_create">Save segment</button>
          <button class="btn small" id="seg_preview">Preview</button>

          <div id="seg_msg"></div>

          <div class="list">
            ${state.segments.length===0 ? `<div class="muted" style="margin-top:8px">No segments yet.</div>` : state.segments.map(s=>`
              <div class="item">
                <div class="row" style="align-items:flex-start">
                  <div style="flex:1">
                    <div class="name">#${s.id} ${esc(s.name)}</div>
                    <div class="meta">${esc(s.filters_json)}</div>
                  </div>
                  <div style="flex:0;display:flex;gap:6px">
                    <button class="btn small" data-use-seg="${s.id}">Use</button>
                  </div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="card">
          <div class="h1">Campaign builder</div>
          <div class="muted">Choose a segment → write message → export list or (optionally) send via SMS/Email provider.</div>

          <div class="field">
            <label>Segment</label>
            <select id="camp_seg">
              <option value="">Select segment</option>
              ${state.segments.map(s=>`<option value="${s.id}">#${s.id} ${esc(s.name)}</option>`).join('')}
            </select>
          </div>

          <div class="row">
            <div class="field">
              <label>Channel</label>
              <select id="camp_channel">
                <option value="export">export (CSV)</option>
                <option value="sms">sms (placeholder)</option>
                <option value="email">email (placeholder)</option>
              </select>
            </div>
            <div class="field">
              <label>Opt-in override</label>
              <select id="camp_override">
                <option value="0">No (default)</option>
                <option value="1">Yes (audited)</option>
              </select>
            </div>
          </div>

          <div class="field">
            <label>Message template</label>
            <textarea id="camp_msg" placeholder="Example: We miss you! Show this message for a thank-you discount."></textarea>
          </div>

          <div class="row">
            <div class="field">
              <label>Coupons</label>
              <select id="camp_coupon">
                <option value="0">No coupon codes</option>
                <option value="1">Generate coupon codes</option>
              </select>
            </div>
            <div class="field">
              <label>Schedule (optional, ISO)</label>
              <input id="camp_sched" placeholder="YYYY-MM-DD HH:MM:SS">
            </div>
          </div>

          <button class="btn small" id="camp_sim">Simulate</button>
          <button class="btn small primary" id="camp_create">Create</button>
          <button class="btn small primary" id="camp_send">Send/Queue now</button>

          ${state.sim ? `
            <div class="okbox">
              Estimated recipients: <b>${esc(state.sim.recipients)}</b><br>
              Expected redemptions: <b>${esc(state.sim.expected_redemptions)}</b><br>
              Est revenue: <b>${money(state.sim.expected_revenue_cents)}</b><br>
              AOV est: <b>${money(state.sim.avg_order_value_cents_est)}</b>
            </div>
          ` : ``}

          <div class="warnbox">
            SMS costs and compliance are on you. By default, campaigns target only opted-in customers unless “override” is used (audited).
          </div>

          <div id="camp_msgbox"></div>

          <div style="margin-top:12px">
            <div class="h1">Past campaigns</div>
            <div class="list">
              ${state.campaigns.length===0 ? `<div class="muted" style="margin-top:8px">No campaigns yet.</div>` : state.campaigns.map(c=>`
                <div class="item">
                  <div class="row" style="align-items:flex-start">
                    <div style="flex:1">
                      <div class="name">#${c.id} ${esc(c.name)}</div>
                      <div class="meta">Segment: ${esc(c.segment_name || ('#'+c.segment_id))} • Channel: ${esc(c.channel)} • Sent/queued: ${esc(c.sent_count)}</div>
                      <div class="meta">Scheduled: ${esc(c.scheduled_at || '—')} • Created: ${esc(c.created_at)}</div>
                    </div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
    `
  }

  function render(){
    if (state.tab === 'pos') $view.innerHTML = renderPOS()
    if (state.tab === 'orders') $view.innerHTML = renderOrders()
    if (state.tab === 'inventory') $view.innerHTML = renderInventory()
    if (state.tab === 'crm') $view.innerHTML = renderCRM()
    if (state.tab === 'campaigns') $view.innerHTML = renderCampaigns()
    bind()
  }

  function msg(elId, type, text){
    const el = qs('#'+elId)
    if (!el) return
    const cls = type==='ok' ? 'okbox' : (type==='err' ? 'errbox' : 'warnbox')
    el.innerHTML = `<div class="${cls}">${esc(text)}</div>`
  }

  function bind(){
    qsa('.tab').forEach(b=>b.onclick=()=>setTab(b.dataset.tab))

    const posQ = qs('#pos_q')
    if (posQ) posQ.oninput = async () => {
      await loadProducts(posQ.value)
      render()
    }

    qsa('[data-add]').forEach(b=>b.onclick=()=>{
      const id = Number(b.dataset.add)
      const p = state.products.find(x=>Number(x.id)===id)
      if (p) cartAdd(p)
    })

    qsa('[data-qtyminus]').forEach(b=>b.onclick=()=>cartQty(Number(b.dataset.qtyminus), -1))
    qsa('[data-qtyplus]').forEach(b=>b.onclick=()=>cartQty(Number(b.dataset.qtyplus), +1))
    qsa('[data-remove]').forEach(b=>b.onclick=()=>cartRemove(Number(b.dataset.remove)))
    qsa('[data-notes]').forEach(inp=>inp.oninput=()=>{
      const pid = Number(inp.dataset.notes)
      const it = state.cart.find(x=>x.product_id===pid)
      if (it) it.notes = inp.value
    })

    const place = qs('#pos_place')
    if (place) place.onclick = async () => {
      try{
        const walkin = qs('#pos_walkin')?.checked ? 1 : 0
        const payload = {
          items: state.cart.map(it=>({ product_id: it.product_id, qty: it.qty, notes: it.notes })),
          order_type: qs('#pos_type')?.value || 'pickup',
          expected_eta_minutes: parseInt(qs('#pos_eta')?.value||'15',10)||15,
          tip_cents: parseInt(qs('#pos_tip')?.value||'0',10)||0,
          payment_method: qs('#pos_paymethod')?.value || 'cash',
          payment_received: qs('#pos_paid')?.checked ? 1 : 0,
          walkin,
          phone: qs('#pos_phone')?.value || '',
          customer_name: qs('#pos_name')?.value || '',
          customer_address: qs('#pos_addr')?.value || '',
          marketing_opt_in: (qs('#pos_optin')?.value || '0') === '1' ? 1 : 0
        }
        const out = await api('api_orders_create', { method:'POST', body: payload })
        state.cart = []
        msg('pos_msg','ok',`Order placed: ${out.order_code}`)
        await loadOrders('active')
        render()
      }catch(e){
        msg('pos_msg','err', e.message || 'Failed to place order')
      }
    }

    const ordRef = qs('#orders_refresh')
    if (ordRef) ordRef.onclick = async ()=>{ await loadOrders(qs('#orders_filter')?.value || 'active'); render() }
    const ordFil = qs('#orders_filter')
    if (ordFil) ordFil.onchange = async ()=>{ await loadOrders(ordFil.value); render() }

    qsa('[data-st]').forEach(b=>b.onclick=async ()=>{
      try{
        await api('api_order_status_update', { method:'POST', body:{ id:Number(b.dataset.st), status:b.dataset.next } })
        msg('orders_msg','ok','Order updated')
        await loadOrders(qs('#orders_filter')?.value || 'active')
        render()
      }catch(e){
        msg('orders_msg','err', e.message || 'Failed to update')
      }
    })

    const invQ = qs('#inv_q')
    if (invQ) invQ.oninput = async ()=>{ await loadProducts(invQ.value); render() }

    qsa('[data-saveprod]').forEach(b=>b.onclick=async ()=>{
      try{
        const id = Number(b.dataset.saveprod)
        const stock = parseInt(qs(`[data-stock="${id}"]`)?.value || '0',10) || 0
        await api('api_product_update', { method:'POST', body:{ id, stock_qty: stock, active: 1 } })
        msg('inv_msg','ok','Saved')
        await loadLowStock()
        await loadProducts(qs('#inv_q')?.value || '')
        render()
      }catch(e){
        msg('inv_msg','err', e.message || 'Save failed')
      }
    })

    const lowRef = qs('#low_refresh')
    if (lowRef) lowRef.onclick = async ()=>{ await loadLowStock(); render() }

    const crmQ = qs('#crm_q')
    if (crmQ) crmQ.oninput = async ()=>{
      const q = crmQ.value.trim()
      if (q.length < 2) { state.customerSearch = []; render(); return }
      try{
        state.customerSearch = await api('api_customers_search', { params: { q }})
        render()
      }catch(e){
        msg('crm_msg','err', e.message || 'Search failed')
      }
    }

    qsa('[data-open]').forEach(b=>b.onclick=async ()=>{
      try{
        const id = Number(b.dataset.open)
        state.selectedCustomer = await api('api_customer_get', { params: { id }})
        render()
      }catch(e){
        msg('crm_msg','err', e.message || 'Open failed')
      }
    })

    const custSave = qs('#cust_save')
    if (custSave) custSave.onclick = async ()=>{
      try{
        const tags = (qs('#cust_tags')?.value || '').split(',').map(s=>s.trim()).filter(Boolean)
        const payload = {
          phone: qs('#cust_phone')?.value || '',
          name: qs('#cust_name')?.value || '',
          email: qs('#cust_email')?.value || '',
          address: qs('#cust_addr')?.value || '',
          marketing_opt_in: (qs('#cust_optin')?.value || '0') === '1' ? 1 : 0,
          tags
        }
        await api('api_customer_upsert', { method:'POST', body: payload })
        msg('cust_msg','ok','Saved')
        state.selectedCustomer = await api('api_customer_get', { params: { phone: payload.phone }})
        render()
      }catch(e){
        msg('cust_msg','err', e.message || 'Save failed')
      }
    }

    const segCreate = qs('#seg_create')
    if (segCreate) segCreate.onclick = async ()=>{
      try{
        const filters = collectSegFilters()
        const name = qs('#seg_name')?.value?.trim() || ''
        const out = await api('api_segment_create', { method:'POST', body: { name, filters } })
        msg('seg_msg','ok',`Saved segment #${out.id}`)
        await loadSegments()
        render()
      }catch(e){
        msg('seg_msg','err', e.message || 'Segment save failed')
      }
    }

    const segPreview = qs('#seg_preview')
    if (segPreview) segPreview.onclick = async ()=>{
      try{
        const filters = collectSegFilters()
        const out = await api('api_segment_preview', { method:'POST', body: { filters } })
        msg('seg_msg','ok',`Preview: ${out.count} recipients. Sample: ${out.sample.slice(0,3).map(x=>x.phone).join(', ')}`)
      }catch(e){
        msg('seg_msg','err', e.message || 'Preview failed')
      }
    }

    qsa('[data-use-seg]').forEach(b=>b.onclick=()=>{
      qs('#camp_seg').value = b.dataset.useSeg
      msg('camp_msgbox','ok',`Selected segment #${b.dataset.useSeg}`)
    })

    const campSim = qs('#camp_sim')
    if (campSim) campSim.onclick = async ()=>{
      try{
        const segment_id = Number(qs('#camp_seg')?.value || '0')
        const override_opt_in = (qs('#camp_override')?.value || '0') === '1' ? 1 : 0
        state.sim = await api('api_campaign_simulate', { method:'POST', body: { segment_id, override_opt_in }})
        render()
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Sim failed')
      }
    }

    const campCreate = qs('#camp_create')
    if (campCreate) campCreate.onclick = async ()=>{
      try{
        const payload = {
          name: `Campaign ${new Date().toISOString().slice(0,10)}`,
          segment_id: Number(qs('#camp_seg')?.value || '0'),
          channel: qs('#camp_channel')?.value || 'export',
          message_template: qs('#camp_msg')?.value || '',
          scheduled_at: (qs('#camp_sched')?.value || '').trim() || null
        }
        if (!payload.segment_id || !payload.message_template.trim()) throw new Error('Select segment and write message')
        const out = await api('api_campaign_create', { method:'POST', body: payload })
        msg('camp_msgbox','ok',`Created campaign #${out.id}`)
        await loadCampaigns()
        render()
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Create failed')
      }
    }

    const campSend = qs('#camp_send')
    if (campSend) campSend.onclick = async ()=>{
      try{
        const id = Number(prompt('Enter campaign ID to send/queue now:') || '0')
        if (!id) return
        const override_opt_in = (qs('#camp_override')?.value || '0') === '1' ? 1 : 0
        const with_coupons = (qs('#camp_coupon')?.value || '0') === '1' ? 1 : 0
        const out = await api('api_campaign_send', { method:'POST', body: { id, override_opt_in, with_coupons } })
        msg('camp_msgbox','ok',`Queued ${out.queued} recipients. Export lists from DB or extend with /export endpoint.`)
        await loadCampaigns()
        render()
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Send failed')
      }
    }
  }

  function collectSegFilters(){
    const inactive_days = parseInt(qs('#seg_inactive')?.value || '',10)
    const total_spent_min_cents = parseInt(qs('#seg_spent_min')?.value || '',10)
    const order_count_min = parseInt(qs('#seg_orders_min')?.value || '',10)
    const purchased_category = (qs('#seg_cat')?.value || '').trim()
    const tag_any = (qs('#seg_tags')?.value || '').split(',').map(s=>s.trim()).filter(Boolean)
    const f = {}
    if (!isNaN(inactive_days) && inactive_days > 0) f.inactive_days = inactive_days
    if (!isNaN(total_spent_min_cents) && total_spent_min_cents > 0) f.total_spent_min_cents = total_spent_min_cents
    if (!isNaN(order_count_min) && order_count_min > 0) f.order_count_min = order_count_min
    if (purchased_category) f.purchased_category = purchased_category
    if (tag_any.length) f.tag_any = tag_any
    return f
  }

  async function boot(){
    await loadMe()
    await loadProducts('')
    await loadLowStock()
    await loadOrders('active')
    await loadSegments()
    await loadCampaigns()

    const initial = (window.location.hash || '#pos').slice(1)
    setTab(['pos','orders','inventory','crm','campaigns'].includes(initial) ? initial : 'pos')
  }

  boot().catch(e=>{
    $view.innerHTML = `<div class="card"><div class="h1">Error</div><div class="errbox">${esc(e.message || e)}</div>
      <div class="muted">If you just deployed: ensure PHP can write next to this file to create <b>neighbourpos.db</b>.</div>
      <div class="muted" style="margin-top:10px">Admin-only demo: open DevTools Console and run <b>loadSample()</b> after login.</div>
      </div>`
  })

  async function loadSample(){
    try{
      await api('api_load_sample_data', { method:'POST', body:{} })
      alert('Sample data loaded. Refreshing...')
      await loadProducts('')
      await loadLowStock()
      await loadOrders('active')
      await loadSegments()
      await loadCampaigns()
      render()
    }catch(e){ alert(e.message || e) }
  }
  window.loadSample = loadSample
</script>

<div style="max-width:1100px;margin:0 auto;padding:0 14px 18px;color:var(--muted);font-size:12px;line-height:1.45">
  <div class="card" style="margin:14px 0">
    <div class="h1">Security & docs</div>
    <div class="muted" style="margin-top:6px">
      <a href="SETUP.md">Docs</a> • <a href="SECURITY.md">Security</a> • <a href="README.md">README</a>
    </div>
    <div class="muted" style="margin-top:10px">
      Logged in as <?=h((string)($_SESSION['email'] ?? ''))?> (<?=h((string)($_SESSION['role'] ?? 'staff'))?>).
    </div>
    <div class="muted" style="margin-top:10px">
      CRM moat: orders feed customer recency/frequency/spend; segments turn those signals into reusable target lists; campaigns export or queue messages while defaulting to opt-in-only delivery and auditing overrides.
    </div>
  </div>
</div>
</body>
</html>
