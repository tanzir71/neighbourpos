<?php
/*
README (Deployment - 10 lines)
1) Upload this file as `neighbourpos.php` to your PHP hosting (same folder becomes app root).
2) Ensure the folder is writable by PHP so it can create `neighbourpos.db` next to this file.
3) Visit `/neighbourpos.php` once to auto-initialize the SQLite schema and settings.
4) Default admin login: admin@example.com / ChangeMe123! (change in Settings immediately).
5) Optional: click "Load sample data" (admin only) to populate demo products/customers/orders.
6) Add cPanel Cron (daily): `php /home/USER/public_html/neighbourpos.php action=cron_campaigns token=YOUR_TOKEN`
7) Add cPanel Cron (nightly): `php /home/USER/public_html/neighbourpos.php action=cron_purge_logs token=YOUR_TOKEN`
8) If cron can't call via CLI, use wget/curl URL with token: `/neighbourpos.php?action=cron_campaigns&token=...`
9) For HTTPS + cookies, enable SSL in hosting and keep `SESSION_SECURE_AUTO` true.
10) Backups: copy `neighbourpos.db` regularly (download via FTP or hosting backup tools).
*/

declare(strict_types=1);

const APP_VERSION = '0.4.0';
const PRODUCT_IMPORT_MAX_ROWS = 500;

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
function brand_favicon_href(): string {
  return "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='12' fill='%23090b10'/%3E%3Crect x='50' y='10' width='5' height='44' rx='2.5' fill='%231652f0'/%3E%3Ctext x='9' y='42' font-family='Inter,Arial,sans-serif' font-size='25' font-weight='900' letter-spacing='0' fill='white'%3ENP%3C/text%3E%3C/svg%3E";
}
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

function normalize_country_code(string $countryCode): string {
  $cc = preg_replace('/[^\d\+]/', '', trim($countryCode));
  if ($cc === '') return '+1';
  if (str_starts_with($cc, '00')) $cc = '+'.substr($cc, 2);
  if ($cc[0] !== '+') $cc = '+'.$cc;
  if (!preg_match('/^\+[1-9][0-9]{0,3}$/', $cc)) return '+1';
  return $cc;
}

function normalize_e164(string $phone, string $countryCode): ?string {
  $p = preg_replace('/[\s\-\(\)\.]/', '', trim($phone));
  $p = preg_replace('/[^\d\+]/', '', $p ?? '');
  if ($p === '') return null;
  if (str_starts_with($p, '00')) $p = '+'.substr($p, 2);
  if ($p[0] !== '+') {
    $digits = preg_replace('/\D/', '', $p);
    if (str_starts_with($digits, '0')) $digits = substr($digits, 1);
    $p = normalize_country_code($countryCode).$digits;
  } else {
    $p = '+'.preg_replace('/\D/', '', $p);
  }
  return preg_match('/^\+[1-9][0-9]{6,14}$/', $p) ? $p : null;
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

function money_fmt(array $settings, int $cents): string {
  $sym = $settings['currency_symbol'] ?? ($settings['CURRENCY_SYMBOL'] ?? '$');
  $amt = number_format($cents / 100, 2, '.', ',');
  return $sym.$amt;
}

function public_script_url(): string {
  $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
  $scheme = $https ? 'https' : 'http';
  $host = $_SERVER['HTTP_HOST'] ?? '';
  $script = $_SERVER['SCRIPT_NAME'] ?? basename(__FILE__);
  if ($host === '') return $script;
  return $scheme.'://'.$host.$script;
}

function receipt_public_url(string $orderCode): string {
  return public_script_url().'?action=receipt&code='.rawurlencode($orderCode);
}

function public_page_css(string $accent): string {
  return "
    :root{--accent:{$accent};--bg:#f6f8fc;--panel:#fff;--txt:#090b10;--muted:#5c6472;--line:#dfe6f0;--line2:#cfd8e6;--wash:#edf2f8;--bad:#b42318;--good:#177a3b;--shadow-sm:0 1px 2px rgb(9 11 16 / .06);--shadow-md:0 8px 28px rgb(9 11 16 / .08);--radius-card:10px;--radius-control:6px}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(180deg,#f8fafc 0%,#eef3fb 100%);color:var(--txt);font-size:14px}
    a{color:var(--accent);text-decoration:none}
    a:hover{text-decoration:underline}
    .publicShell{min-height:100vh;display:grid;place-items:center;padding:24px}
    .publicWrap{width:min(100%,430px)}
    .publicWrap.wide{width:min(100%,560px)}
    .publicBrand{display:flex;align-items:center;gap:10px;margin:0 0 16px}
    .brandMark{width:40px;height:40px;flex:0 0 auto;border-radius:8px;display:grid;place-items:center;background:#090b10;color:#fff;font-size:14px;font-weight:900;letter-spacing:0;position:relative;overflow:hidden;box-shadow:var(--shadow-sm)}
    .brandMark::after{content:'';position:absolute;right:7px;top:7px;width:4px;height:26px;border-radius:999px;background:var(--accent)}
    .brandMark span{position:relative;z-index:1;transform:translateX(-1px)}
    .brandText strong{display:block;font-size:15px;font-weight:700;letter-spacing:0}
    .brandText span{display:block;margin-top:2px;color:var(--muted);font-size:12px}
    .publicCard{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-card);box-shadow:var(--shadow-sm);padding:18px}
    .publicCard + .publicCard{margin-top:12px}
    .h1{font-size:18px;line-height:1.2;font-weight:700;margin:0;letter-spacing:0}
    .p,.muted{color:var(--muted);font-size:12.5px;line-height:1.45;margin:6px 0 0}
    label{display:block;font-size:11.5px;color:var(--muted);font-weight:600;margin:12px 0 6px}
    input,select{width:100%;height:38px;border-radius:var(--radius-control);border:1px solid var(--line);background:var(--wash);color:var(--txt);padding:0 11px;font:500 13px/1.2 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;outline:none}
    input[type='checkbox']{width:16px;height:16px;margin:0 7px 0 0;vertical-align:-3px}
    input:focus,select:focus{border-color:color-mix(in srgb,var(--accent) 64%,#fff);background:#fff;box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 14%,transparent)}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:38px;border-radius:var(--radius-control);border:0;background:var(--wash);color:var(--txt);padding:0 13px;font:500 13px/1 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;text-decoration:none;cursor:pointer}
    .btn:hover{text-decoration:none;background:#e5ebf3}
    .btn.primary{width:100%;margin-top:14px;background:var(--accent);color:#fff}
    .btn.primary:hover{filter:brightness(.96)}
    .err{margin-top:12px;border-radius:8px;background:#fff0ee;color:var(--bad);padding:10px 11px;font-size:12.5px;line-height:1.35}
    .ok{margin-top:12px;border-radius:8px;background:#eaf7ef;color:var(--good);padding:10px 11px;font-size:12.5px;line-height:1.35}
    .row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
    .row.wrap{flex-wrap:wrap}
    .badge{display:inline-flex;align-items:center;min-height:24px;border-radius:999px;padding:0 8px;font-size:11px;font-weight:600;background:#eef2f7;color:#445064;white-space:nowrap}
    .b-new{background:#eaf1ff;color:#1642a6}.b-prep{background:#fff5dc;color:#744800}.b-ready{background:#eaf7ef;color:#145c2e}.b-out{background:#f2eafd;color:#5f2e9c}.b-done{background:#eef2f7;color:#445064}
    .orderRow{padding:11px 0;border-top:1px solid var(--line)}
    .orderRow:first-of-type{border-top:0}
    .foot{margin-top:14px;color:var(--muted);font-size:12px;line-height:1.5}
    @media(max-width:620px){.publicShell{display:block;padding:16px}.publicWrap,.publicWrap.wide{width:100%}.row{align-items:stretch;flex-direction:column}.badge{align-self:flex-start}}
  ";
}

function public_brand_html(array $CONFIG, string $subtitle): string {
  return "<div class='publicBrand'><div class='brandMark' aria-hidden='true'><span>NP</span></div><div class='brandText'><strong>".h((string)$CONFIG['APP_NAME'])."</strong><span>".h($subtitle)."</span></div></div>";
}

function receipt_page_css(string $accent): string {
  return "
    :root{--accent:{$accent};--txt:#090b10;--muted:#5c6472;--line:#dfe6f0;--wash:#edf2f8;--panel:#fff;--shadow-sm:0 1px 2px rgb(9 11 16 / .06)}
    *{box-sizing:border-box}
    body{margin:0;background:#f6f8fc;color:var(--txt);font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:14px}
    .receiptShell{min-height:100vh;padding:18px;display:grid;place-items:start center}
    .receiptWrap{width:min(100%,420px)}
    .receiptToolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap}
    .toolbarActions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .btn{display:inline-flex;align-items:center;justify-content:center;min-height:36px;border-radius:6px;border:0;background:var(--wash);color:var(--txt);padding:0 12px;font:500 13px/1 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;text-decoration:none;cursor:pointer}
    .btn.primary{background:var(--accent);color:#fff}
    .receiptPaper{background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow-sm);padding:18px}
    .brandLine{display:flex;align-items:center;gap:10px;margin-bottom:12px}
    .brandMark{width:36px;height:36px;flex:0 0 auto;border-radius:8px;display:grid;place-items:center;background:#090b10;color:#fff;font-size:13px;font-weight:900;letter-spacing:0;position:relative;overflow:hidden}
    .brandMark::after{content:'';position:absolute;right:6px;top:6px;width:4px;height:24px;border-radius:999px;background:var(--accent)}
    .brandMark span{position:relative;z-index:1;transform:translateX(-1px)}
    .h1{font-size:18px;font-weight:700;margin:0;letter-spacing:0}
    .muted{color:var(--muted);font-size:12px;line-height:1.4}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    td{padding:8px 0;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
    .right{text-align:right}
    .receiptTotals{margin-top:12px;border-radius:8px;background:#f8fafc;border:1px solid var(--line);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
    .totalRow{display:flex;justify-content:space-between;gap:12px;padding:8px 10px;border-top:1px solid var(--line)}
    .totalRow:first-child{border-top:0}
    .totalRow.total{font-weight:700;font-size:13px;color:var(--txt)}
    .shareStatus{width:100%;color:var(--muted);font-size:12px;line-height:1.4}
    @page{size:80mm auto;margin:4mm}
    @media print{
      html,body{width:80mm;margin:0;background:#fff}
      .receiptShell{display:block;min-height:0;padding:0}
      .receiptWrap{width:72mm;max-width:none;margin:0 auto}
      .receiptToolbar,.shareStatus{display:none!important}
      .receiptPaper{border:0;border-radius:0;box-shadow:none;padding:0;width:72mm}
      .brandMark{display:none}
      .h1{font-size:14px}
      .muted{font-size:10px;color:#222}
      td{font-size:10.5px;padding:5px 0;border-bottom:1px solid #ddd}
      .receiptTotals{border:0;border-radius:0;background:#fff;font-size:10.5px;margin-top:8px}
      .totalRow{padding:4px 0;border-top:1px solid #ddd}
    }
  ";
}

function csv_safe_cell($value): string {
  $text = (string)($value ?? '');
  if ($text !== '' && preg_match('/^[=\+\-@\t\r]/', $text) === 1) {
    return "'".$text;
  }
  return $text;
}

function csv_safe_phone_cell($value): string {
  $text = (string)($value ?? '');
  // Provider import profiles require strict E.164 phone values without a leading apostrophe.
  if (preg_match('/^\+[1-9][0-9]{6,14}$/', $text) === 1) return $text;
  return csv_safe_cell($text);
}

function product_import_price_to_cents($value): ?int {
  $text = trim((string)($value ?? ''));
  if ($text === '') return null;
  $clean = preg_replace('/[^\d\.\-]/', '', $text);
  if ($clean === null || preg_match('/^-?\d+(?:\.\d{1,4})?$/', $clean) !== 1) return null;
  $amount = (float)$clean;
  if (!is_finite($amount) || $amount < 0) return null;
  return (int)round($amount * 100);
}

function product_import_parse_csv(string $csv): array {
  $csv = preg_replace('/^\xEF\xBB\xBF/', '', $csv) ?? $csv;
  $fh = fopen('php://temp', 'r+');
  if ($fh === false) {
    return ['rows_total' => 0, 'valid_count' => 0, 'rows' => [], 'errors' => [['row' => 0, 'errors' => ['Could not read CSV']]], 'too_many' => false];
  }
  fwrite($fh, $csv);
  rewind($fh);

  $header = fgetcsv($fh);
  if ($header === false) {
    fclose($fh);
    return ['rows_total' => 0, 'valid_count' => 0, 'rows' => [], 'errors' => [['row' => 1, 'errors' => ['CSV header required']]], 'too_many' => false];
  }

  $map = [];
  foreach ($header as $idx => $name) {
    $map[strtolower(trim((string)$name))] = $idx;
  }
  $required = ['sku', 'name', 'price', 'stock', 'category'];
  $missing = array_values(array_filter($required, fn($col) => !array_key_exists($col, $map)));
  if ($missing) {
    fclose($fh);
    return [
      'rows_total' => 0,
      'valid_count' => 0,
      'rows' => [],
      'errors' => [['row' => 1, 'errors' => ['Missing columns: '.implode(', ', $missing)]]],
      'too_many' => false,
    ];
  }

  $rows = [];
  $errors = [];
  $rowsTotal = 0;
  $rowNumber = 1;
  while (($line = fgetcsv($fh)) !== false) {
    $rowNumber++;
    $nonBlank = false;
    foreach ($line as $cell) {
      if (trim((string)$cell) !== '') {
        $nonBlank = true;
        break;
      }
    }
    if (!$nonBlank) continue;

    $rowsTotal++;
    if ($rowsTotal > PRODUCT_IMPORT_MAX_ROWS) {
      fclose($fh);
      return [
        'rows_total' => $rowsTotal,
        'valid_count' => count($rows),
        'rows' => $rows,
        'errors' => $errors,
        'too_many' => true,
        'error' => 'Product import is capped at 500 rows',
      ];
    }

    $cell = function (string $key) use ($line, $map): string {
      $idx = $map[$key] ?? -1;
      return $idx >= 0 && array_key_exists($idx, $line) ? trim((string)$line[$idx]) : '';
    };

    $rowErrors = [];
    $sku = substr($cell('sku'), 0, 64);
    $name = trim($cell('name'));
    if ($name === '') $rowErrors[] = 'name required';
    $price = product_import_price_to_cents($cell('price'));
    if ($price === null) $rowErrors[] = 'price must be a non-negative amount';
    $stockText = $cell('stock');
    $stock = null;
    if (preg_match('/^\d+$/', $stockText) === 1) $stock = (int)$stockText;
    else $rowErrors[] = 'stock must be a non-negative whole number';
    $category = substr($cell('category'), 0, 80);

    if ($rowErrors) {
      $errors[] = ['row' => $rowNumber, 'errors' => $rowErrors];
      continue;
    }

    $rows[] = [
      'row' => $rowNumber,
      'sku' => $sku,
      'name' => substr($name, 0, 160),
      'price_cents' => $price,
      'stock_qty' => $stock,
      'category' => $category,
    ];
  }
  fclose($fh);

  return [
    'rows_total' => $rowsTotal,
    'valid_count' => count($rows),
    'rows' => $rows,
    'errors' => $errors,
    'too_many' => false,
  ];
}

function product_import_apply(PDO $pdo, array $rows, string $ts): int {
  $imported = 0;
  $findSku = $pdo->prepare("SELECT id FROM products WHERE sku = ? LIMIT 1");
  $update = $pdo->prepare("UPDATE products SET name=?, price_cents=?, stock_qty=?, category=?, active=1 WHERE id=?");
  $insert = $pdo->prepare("INSERT INTO products(sku,name,price_cents,stock_qty,category,active,created_at) VALUES(?,?,?,?,?,?,?)");

  foreach ($rows as $row) {
    $sku = trim((string)($row['sku'] ?? ''));
    $name = (string)($row['name'] ?? '');
    $price = (int)($row['price_cents'] ?? 0);
    $stock = (int)($row['stock_qty'] ?? 0);
    $category = trim((string)($row['category'] ?? ''));

    $existing = null;
    if ($sku !== '') {
      $findSku->execute([$sku]);
      $existing = $findSku->fetch();
    }
    if ($existing) {
      $update->execute([$name, $price, $stock, $category ?: null, (int)$existing['id']]);
    } else {
      $insert->execute([$sku ?: null, $name, $price, $stock, $category ?: null, 1, $ts]);
    }
    $imported++;
  }

  return $imported;
}

function campaign_payload(array $r): array {
  $payload = json_decode((string)($r['payload_json'] ?? '{}'), true);
  return is_array($payload) ? $payload : [];
}

function campaign_recipient_email(array $r): string {
  $email = trim((string)($r['recipient_email'] ?? ''));
  if ($email === '') $email = trim((string)($r['customer_email'] ?? ''));
  return $email;
}

function campaign_recipient_coupon(array $r): string {
  $payload = campaign_payload($r);
  $coupon = trim((string)($r['coupon_code'] ?? ''));
  if ($coupon === '') $coupon = trim((string)($payload['coupon_code'] ?? ''));
  return $coupon;
}

function campaign_row_name(array $r): string {
  return trim((string)($r['customer_name'] ?? ($r['name'] ?? '')));
}

function campaign_render_message(array $camp, array $r, string $storeName = ''): string {
  $payload = campaign_payload($r);
  $message = (string)($payload['message'] ?? ($camp['message_template'] ?? ''));
  $name = campaign_row_name($r);
  [$first] = split_customer_name($name);
  $coupon = campaign_recipient_coupon($r);
  $balance = (string)($payload['balance'] ?? ($r['balance'] ?? ''));

  return strtr($message, [
    '{{coupon}}' => $coupon,
    '{coupon_code}' => $coupon,
    '{name}' => $name,
    '{first_name}' => $first,
    '{store_name}' => $storeName,
    '{balance}' => $balance,
  ]);
}

function split_customer_name(string $name): array {
  $name = trim(preg_replace('/\s+/', ' ', $name));
  if ($name === '') return ['', ''];
  $parts = explode(' ', $name, 2);
  return [$parts[0] ?? '', $parts[1] ?? ''];
}

function customer_tags_from_text(string $tagsText): array {
  $tags = [];
  foreach (explode(',', trim($tagsText, ", \t\n\r\0\x0B")) as $tag) {
    $tag = trim($tag);
    if ($tag === '') continue;
    $tags[strtolower($tag)] = $tag;
  }
  return array_values($tags);
}

function campaign_export_profile(string $format, array $camp, array $rows, string $countryCode, string $storeName = ''): array {
  $headers = [
    'mailchimp' => ['Email Address', 'First Name', 'Last Name', 'Phone', 'Tags'],
    'brevo' => ['EMAIL', 'SMS', 'FIRSTNAME', 'LASTNAME', 'COUPON_CODE'],
    'sms' => ['phone', 'name', 'coupon_code', 'message'],
    'whatsapp' => ['phone', 'name', 'message', 'wa_link'],
  ][$format] ?? [];

  $out = [];
  $seen = [];
  foreach ($rows as $r) {
    $name = campaign_row_name($r);
    [$first, $last] = split_customer_name($name);
    $email = campaign_recipient_email($r);
    $emailKey = strtolower($email);
    $e164 = normalize_e164((string)($r['phone'] ?? ''), $countryCode);
    $coupon = campaign_recipient_coupon($r);
    $message = campaign_render_message($camp, $r, $storeName);

    if ($format === 'mailchimp') {
      if ($email === '' || isset($seen[$emailKey])) continue;
      $seen[$emailKey] = true;
      $tags = customer_tags_from_text((string)($r['tags_text'] ?? ''));
      if (($camp['include_campaign_tag'] ?? true) !== false && trim((string)($camp['name'] ?? '')) !== '') {
        array_unshift($tags, 'campaign:'.(string)$camp['name']);
      }
      $out[] = [
        csv_safe_cell($email),
        csv_safe_cell($first),
        csv_safe_cell($last),
        csv_safe_phone_cell($e164 ?? ''),
        csv_safe_cell(implode(',', array_values(array_unique($tags)))),
      ];
      continue;
    }

    if ($format === 'brevo') {
      if ($email === '' && $e164 === null) continue;
      $key = $email !== '' ? 'email:'.$emailKey : 'phone:'.$e164;
      if (isset($seen[$key])) continue;
      $seen[$key] = true;
      $out[] = [
        csv_safe_cell($email),
        csv_safe_phone_cell($e164 ?? ''),
        csv_safe_cell($first),
        csv_safe_cell($last),
        csv_safe_cell($coupon),
      ];
      continue;
    }

    if ($e164 === null || isset($seen[$e164])) continue;
    $seen[$e164] = true;

    if ($format === 'sms') {
      $out[] = [
        csv_safe_phone_cell($e164),
        csv_safe_cell($name),
        csv_safe_cell($coupon),
        csv_safe_cell($message),
      ];
      continue;
    }

    if ($format === 'whatsapp') {
      $digits = preg_replace('/\D/', '', $e164);
      $out[] = [
        csv_safe_phone_cell($e164),
        csv_safe_cell($name),
        csv_safe_cell($message),
        csv_safe_cell('https://wa.me/'.$digits.'?text='.rawurlencode($message)),
      ];
    }
  }

  return [$headers, $out];
}

function campaign_export_allowed_format(string $format): bool {
  return in_array($format, ['full', 'mailchimp', 'brevo', 'sms', 'whatsapp'], true);
}

function campaign_export_filename(array $camp, string $format, bool $legacyFull = false): string {
  if ($legacyFull && $format === 'full') return 'campaign-'.(int)$camp['id'].'-recipients.csv';
  $slug = strtolower(trim((string)($camp['name'] ?? 'campaign')));
  $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
  $slug = trim((string)$slug, '-');
  if ($slug === '') $slug = 'campaign-'.(int)($camp['id'] ?? 0);
  return $slug.'-'.$format.'-'.gmdate('Ymd').'.csv';
}

function campaign_export_preview_summary(string $format, array $camp, array $rows, string $countryCode, string $storeName = ''): array {
  [, $profileRows] = $format === 'full'
    ? [[], $rows]
    : campaign_export_profile($format, $camp, $rows, $countryCode, $storeName);

  $summary = [
    'format' => $format,
    'total_queued' => count($rows),
    'opted_in' => 0,
    'with_email' => 0,
    'with_valid_phone' => 0,
    'export_count' => count($profileRows),
    'excluded_and_why' => [
      'missing_email' => 0,
      'invalid_phone' => 0,
      'missing_contact' => 0,
      'duplicate_email' => 0,
      'duplicate_phone' => 0,
      'duplicate_contact' => 0,
    ],
  ];

  $seenEmail = [];
  $seenPhone = [];
  $seenContact = [];
  foreach ($rows as $r) {
    if ((int)($r['marketing_opt_in'] ?? 0) === 1) $summary['opted_in']++;
    $email = campaign_recipient_email($r);
    $emailKey = strtolower($email);
    $e164 = normalize_e164((string)($r['phone'] ?? ''), $countryCode);
    if ($email !== '') $summary['with_email']++;
    if ($e164 !== null) $summary['with_valid_phone']++;

    if ($format === 'mailchimp') {
      if ($email === '') {
        $summary['excluded_and_why']['missing_email']++;
      } elseif (isset($seenEmail[$emailKey])) {
        $summary['excluded_and_why']['duplicate_email']++;
      } else {
        $seenEmail[$emailKey] = true;
      }
      continue;
    }

    if ($format === 'sms' || $format === 'whatsapp') {
      if ($e164 === null) {
        $summary['excluded_and_why']['invalid_phone']++;
      } elseif (isset($seenPhone[$e164])) {
        $summary['excluded_and_why']['duplicate_phone']++;
      } else {
        $seenPhone[$e164] = true;
      }
      continue;
    }

    if ($format === 'brevo') {
      if ($email === '' && $e164 === null) {
        $summary['excluded_and_why']['missing_contact']++;
        continue;
      }
      $key = $email !== '' ? 'email:'.$emailKey : 'phone:'.$e164;
      if (isset($seenContact[$key])) {
        $summary['excluded_and_why']['duplicate_contact']++;
      } else {
        $seenContact[$key] = true;
      }
    }
  }

  return $summary;
}

function campaign_queue_recipients(PDO $pdo, array $CONFIG, array $camp, array $segRow, bool $overrideOptIn, bool $withCoupons): int {
  $campaignId = (int)$camp['id'];
  $filters = parse_filters((string)$segRow['filters_json']);
  $filters['marketing_opt_in_only'] = ($CONFIG['REQUIRE_MARKETING_OPT_IN'] ?? true) ? ($overrideOptIn ? false : true) : false;

  $recipients = segment_query($pdo, $filters, 5000, 0);
  $pdo->prepare("DELETE FROM campaign_recipients WHERE campaign_id = ?")->execute([$campaignId]);

  $ins = $pdo->prepare("INSERT INTO campaign_recipients(campaign_id, customer_id, phone, email, coupon_code, sent_at, status, payload_json) VALUES(?,?,?,?,?,?,?,?)");
  $queued = 0;
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
      $campaignId,
      (int)$c['id'],
      (string)$c['phone'],
      (string)($c['email'] ?? ''),
      $coupon,
      null,
      'queued',
      json_encode($payload, JSON_UNESCAPED_SLASHES),
    ]);
    $queued++;
  }

  $pdo->prepare("UPDATE campaigns SET sent_count = ? WHERE id = ?")->execute([$queued, $campaignId]);
  return $queued;
}

function customer_rows_to_export_recipients(array $rows, string $messageTemplate = '', ?array $store = null): array {
  $out = [];
  foreach ($rows as $c) {
    $balanceCents = (int)($c['balance_cents'] ?? 0);
    $balance = $store ? money_fmt($store, $balanceCents) : number_format($balanceCents / 100, 2, '.', ',');
    $out[] = [
      'customer_id' => $c['id'] ?? null,
      'phone' => (string)($c['phone'] ?? ''),
      'recipient_email' => (string)($c['email'] ?? ''),
      'coupon_code' => '',
      'sent_at' => '',
      'redeemed_order_id' => '',
      'redeemed_at' => '',
      'status' => '',
      'payload_json' => json_encode(['message' => $messageTemplate, 'coupon_code' => '', 'balance' => $balance], JSON_UNESCAPED_SLASHES),
      'customer_name' => (string)($c['name'] ?? ''),
      'customer_email' => (string)($c['email'] ?? ''),
      'tags_text' => (string)($c['tags_text'] ?? ''),
      'marketing_opt_in' => $c['marketing_opt_in'] ?? null,
      'total_spent_cents' => $c['total_spent_cents'] ?? '',
      'order_count' => $c['order_count'] ?? '',
      'last_order_at' => $c['last_order_at'] ?? '',
      'balance_cents' => $balanceCents,
      'balance' => $balance,
    ];
  }
  return $out;
}

function rand_code(int $len): string {
  $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $out = '';
  for ($i = 0; $i < $len; $i++) $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
  return $out;
}

function require_login(): void {
  if (empty($_SESSION['uid'])) {
    $action = $_GET['action'] ?? '';
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    if ((is_string($action) && str_starts_with($action, 'api_')) || (is_string($accept) && stripos($accept, 'application/json') !== false)) {
      json_out(['ok' => false, 'error' => 'Authentication required'], 401);
    }
    redirect_to('?action=staff_login');
  }
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

function database_backup_snapshot(PDO $pdo): string {
  $tmp = tempnam(sys_get_temp_dir(), 'neighbourpos-backup-');
  if ($tmp === false) {
    throw new RuntimeException('Could not create backup temp file');
  }
  if (is_file($tmp)) @unlink($tmp);
  $pdo->exec('VACUUM INTO '.$pdo->quote($tmp));
  if (!is_file($tmp) || filesize($tmp) === 0) {
    @unlink($tmp);
    throw new RuntimeException('Backup snapshot failed');
  }
  return $tmp;
}

function ensure_column(PDO $pdo, string $table, string $column, string $definition): void {
  $st = $pdo->query("PRAGMA table_info({$table})");
  foreach ($st->fetchAll() as $row) {
    if ((string)$row['name'] === $column) return;
  }
  $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$definition}");
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
      default_country_code TEXT NOT NULL DEFAULT '+1',
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
      coupon_code_text TEXT,
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
    CREATE TABLE IF NOT EXISTS ledger_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      order_id INTEGER,
      type TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      note TEXT,
      created_by INTEGER,
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
      redeemed_order_id INTEGER,
      redeemed_at TEXT,
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
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_ledger_customer ON ledger_entries(customer_id);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_ledger_order ON ledger_entries(order_id);");
  $pdo->exec("CREATE INDEX IF NOT EXISTS idx_campaign_recipients_campaign ON campaign_recipients(campaign_id);");
  ensure_column($pdo, 'orders', 'coupon_code_text', 'TEXT');
  ensure_column($pdo, 'stores', 'default_country_code', "TEXT NOT NULL DEFAULT '+1'");
  ensure_column($pdo, 'campaign_recipients', 'redeemed_order_id', 'INTEGER');
  ensure_column($pdo, 'campaign_recipients', 'redeemed_at', 'TEXT');

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

function ledger_balance_expr(string $customerExpr = 'c.id'): string {
  return "(SELECT COALESCE(SUM(CASE WHEN le.type = 'credit' THEN le.amount_cents ELSE -le.amount_cents END), 0) FROM ledger_entries le WHERE le.customer_id = {$customerExpr})";
}

function ledger_balance_cents(PDO $pdo, int $customerId): int {
  $st = $pdo->prepare("
    SELECT COALESCE(SUM(CASE WHEN type = 'credit' THEN amount_cents ELSE -amount_cents END), 0) AS balance
    FROM ledger_entries
    WHERE customer_id = ?
  ");
  $st->execute([$customerId]);
  return (int)$st->fetchColumn();
}

function ledger_entries_for_customer(PDO $pdo, int $customerId, int $limit = 20): array {
  $st = $pdo->prepare("
    SELECT le.id, le.customer_id, le.order_id, le.type, le.amount_cents, le.note, le.created_by, le.created_at, o.order_code
    FROM ledger_entries le
    LEFT JOIN orders o ON o.id = le.order_id
    WHERE le.customer_id = ?
    ORDER BY le.created_at DESC, le.id DESC
    LIMIT ?
  ");
  $st->execute([$customerId, max(1, min(100, $limit))]);
  return $st->fetchAll();
}

function ledger_outstanding_credit_cents(PDO $pdo): int {
  $st = $pdo->query("
    SELECT COALESCE(SUM(balance), 0) AS total
    FROM (
      SELECT customer_id, SUM(CASE WHEN type = 'credit' THEN amount_cents ELSE -amount_cents END) AS balance
      FROM ledger_entries
      GROUP BY customer_id
      HAVING balance > 0
    )
  ");
  return (int)$st->fetchColumn();
}

function ledger_insert(PDO $pdo, int $customerId, ?int $orderId, string $type, int $amountCents, string $note, ?int $createdBy, string $createdAt): int {
  if (!in_array($type, ['credit', 'payment'], true)) throw new InvalidArgumentException('Invalid ledger type');
  if ($customerId <= 0 || $amountCents <= 0) throw new InvalidArgumentException('Invalid ledger entry');
  $note = trim($note);
  $ins = $pdo->prepare("INSERT INTO ledger_entries(customer_id, order_id, type, amount_cents, note, created_by, created_at) VALUES(?,?,?,?,?,?,?)");
  $ins->execute([$customerId, $orderId, $type, $amountCents, $note !== '' ? $note : null, $createdBy, $createdAt]);
  return (int)$pdo->lastInsertId();
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

function db_table_exists(PDO $pdo, string $table): bool {
  $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1");
  $st->execute([$table]);
  return (bool)$st->fetchColumn();
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

  $tagFilters = [];
  if (!empty($filters['tag']) && is_string($filters['tag'])) {
    $tagFilters[] = $filters['tag'];
  }
  if (!empty($filters['tag_any']) && is_array($filters['tag_any'])) {
    $tagFilters = array_merge($tagFilters, $filters['tag_any']);
  }
  if ($tagFilters) {
    $tagW = [];
    foreach ($tagFilters as $t) {
      $t = strtolower(preg_replace('/[^a-z0-9_\-]/', '', (string)$t));
      if ($t === '') continue;
      $tagW[] = "c.tags_text LIKE ?";
      $params[] = '%,' . $t . ',%';
    }
    if ($tagW) $where[] = '(' . implode(' OR ', $tagW) . ')';
  }

  if (!empty($filters['has_balance'])) {
    $where[] = ledger_balance_expr('c.id') . " > 0";
  }

  $sql = "SELECT c.*, " . ledger_balance_expr('c.id') . " AS balance_cents FROM customers c {$joins}";
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
if ($action === '' && empty($_SESSION['uid']) && PHP_SAPI !== 'cli') {
  $action = 'staff_login';
}

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
    'default_country_code' => '+1',
  ];
}

function dev_selftest_record(array &$tests, string $name, $expected, $actual, array $context = []): void {
  $passed = $actual === $expected;
  $tests[] = array_merge([
    'name' => $name,
    'expected' => $expected,
    'actual' => $actual,
    'passed' => $passed,
  ], $context);
}

function dev_selftest_fixture_pdo(): PDO {
  $pdo = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);
  $pdo->exec("PRAGMA foreign_keys=OFF;");
  init_db($pdo);

  $now = '2026-07-07 12:00:00';
  $old = '2026-05-20 12:00:00';
  $customers = [
    ['+15550101001', 'Amina Regular', 'amina@example.test', 1, ',vip,coffee,', 15000, 3, $now],
    ['+15550101002', 'Ben Lapsed', 'ben@example.test', 0, ',lapsed,', 3200, 1, $old],
    ['+15550101003', 'Cara Credit', '', 1, ',credit,', 5000, 2, $old],
  ];

  $insCust = $pdo->prepare("INSERT INTO customers(phone,name,email,marketing_opt_in,marketing_opt_in_ts,total_spent_cents,order_count,last_order_at,tags_text,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
  foreach ($customers as $c) {
    $insCust->execute([$c[0], $c[1], $c[2], $c[3], $c[3] ? $now : null, $c[5], $c[6], $c[7], $c[4], '{}', $c[7]]);
  }

  $pdo->prepare("INSERT INTO products(sku,name,price_cents,stock_qty,category,active,created_at) VALUES(?,?,?,?,?,?,?)")
    ->execute(['COF', 'Coffee Beans', 1200, 10, 'Grocery', 1, $now]);
  $productId = (int)$pdo->lastInsertId();
  $aminaId = (int)$pdo->query("SELECT id FROM customers WHERE phone = '+15550101001'")->fetch()['id'];
  $caraId = (int)$pdo->query("SELECT id FROM customers WHERE phone = '+15550101003'")->fetch()['id'];

  $pdo->prepare("INSERT INTO orders(order_code,customer_id,phone_text,order_type,items_json,subtotal_cents,tax_cents,tip_cents,total_cents,status,payment_method,payment_received,expected_eta_minutes,coupon_code_text,created_at,updated_at,stock_applied,metrics_applied) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    ->execute(['SELFTEST1', $aminaId, '+15550101001', 'pickup', '[]', 1200, 0, 0, 1200, 'completed', 'cash', 1, 15, null, $now, $now, 1, 1]);
  $orderId = (int)$pdo->lastInsertId();
  $pdo->prepare("INSERT INTO order_items(order_id,product_id,product_name,category,qty,price_cents,notes,created_at) VALUES(?,?,?,?,?,?,?,?)")
    ->execute([$orderId, $productId, 'Coffee Beans', 'Grocery', 1, 1200, '', $now]);
  $pdo->prepare("INSERT INTO ledger_entries(customer_id,order_id,type,amount_cents,note,created_by,created_at) VALUES(?,?,?,?,?,?,?)")
    ->execute([$caraId, null, 'credit', 2500, 'Self-test balance', null, $now]);

  return $pdo;
}

function dev_selftest_results(): array {
  $tests = [];

  foreach ([
    'bd_local' => ['phone' => '01712-345678', 'country_code' => '+880', 'expected' => '+8801712345678'],
    'us_local' => ['phone' => '(555) 010-1234', 'country_code' => '+1', 'expected' => '+15550101234'],
    'invalid' => ['phone' => 'garbage', 'country_code' => '+1', 'expected' => null],
  ] as $label => $case) {
    $actual = normalize_e164((string)$case['phone'], (string)$case['country_code']);
    dev_selftest_record($tests, 'normalize_e164:'.$label, $case['expected'], $actual, [
      'phone' => $case['phone'],
      'country_code' => $case['country_code'],
    ]);
  }

  try {
    $fixture = dev_selftest_fixture_pdo();
    $segmentCases = [
      'marketing_opt_in_only' => [['marketing_opt_in_only' => true], 2],
      'tag' => [['tag' => 'vip'], 1],
      'has_balance' => [['has_balance' => true], 1],
      'inactive_days' => [['inactive_days' => 30], 2],
      'purchased_product_id' => [['purchased_product_id' => 1], 1],
      'total_spent_min_cents' => [['total_spent_min_cents' => 10000], 1],
    ];
    foreach ($segmentCases as $label => [$filters, $expected]) {
      dev_selftest_record($tests, 'segment_filter:'.$label, $expected, segment_count($fixture, $filters), ['filters' => $filters]);
    }
  } catch (Throwable $e) {
    $tests[] = [
      'name' => 'segment_filter:fixture',
      'expected' => 'fixture self-test pass',
      'actual' => $e->getMessage(),
      'passed' => false,
    ];
  }

  $headerCases = [
    'mailchimp' => ['Email Address', 'First Name', 'Last Name', 'Phone', 'Tags'],
    'brevo' => ['EMAIL', 'SMS', 'FIRSTNAME', 'LASTNAME', 'COUPON_CODE'],
    'sms' => ['phone', 'name', 'coupon_code', 'message'],
    'whatsapp' => ['phone', 'name', 'message', 'wa_link'],
  ];
  foreach ($headerCases as $format => $expectedHeaders) {
    [$headers] = campaign_export_profile($format, ['name' => 'Self-test', 'message_template' => 'Hi {first_name}'], [], '+1', 'Neighbour Store');
    dev_selftest_record($tests, 'export_headers:'.$format, $expectedHeaders, $headers, ['format' => $format]);
  }

  $failures = count(array_filter($tests, fn($t) => empty($t['passed'])));
  return ['ok' => $failures === 0, 'data' => ['tests' => $tests, 'failures' => $failures]];
}

function report_date_bounds(array $input): array {
  $today = gmdate('Y-m-d');
  $from = (string)($input['from'] ?? gmdate('Y-m-d', time() - 6 * 86400));
  $to = (string)($input['to'] ?? $today);
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) $from = gmdate('Y-m-d', time() - 6 * 86400);
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) $to = $today;
  if ($from > $to) {
    $tmp = $from;
    $from = $to;
    $to = $tmp;
  }
  return [$from, $to, $from.' 00:00:00', $to.' 23:59:59'];
}

function sales_report_data(PDO $pdo, string $fromTs, string $toTs): array {
  $summary = $pdo->prepare("
    SELECT COUNT(*) AS order_count, COALESCE(SUM(total_cents),0) AS revenue_cents, COALESCE(AVG(total_cents),0) AS aov_cents
    FROM orders
    WHERE status = 'completed' AND created_at >= ? AND created_at <= ?
  ");
  $summary->execute([$fromTs, $toTs]);
  $sum = $summary->fetch() ?: ['order_count' => 0, 'revenue_cents' => 0, 'aov_cents' => 0];

  $top = $pdo->prepare("
    SELECT oi.product_name, COALESCE(NULLIF(oi.category,''),'Uncategorized') AS category, SUM(oi.qty) AS qty, SUM(oi.qty * oi.price_cents) AS revenue_cents
    FROM order_items oi
    INNER JOIN orders o ON o.id = oi.order_id
    WHERE o.status = 'completed' AND o.created_at >= ? AND o.created_at <= ?
    GROUP BY oi.product_name, COALESCE(NULLIF(oi.category,''),'Uncategorized')
    ORDER BY revenue_cents DESC, qty DESC
    LIMIT 10
  ");
  $top->execute([$fromTs, $toTs]);

  $cat = $pdo->prepare("
    SELECT COALESCE(NULLIF(oi.category,''),'Uncategorized') AS category, SUM(oi.qty) AS qty, SUM(oi.qty * oi.price_cents) AS revenue_cents
    FROM order_items oi
    INNER JOIN orders o ON o.id = oi.order_id
    WHERE o.status = 'completed' AND o.created_at >= ? AND o.created_at <= ?
    GROUP BY COALESCE(NULLIF(oi.category,''),'Uncategorized')
    ORDER BY revenue_cents DESC
    LIMIT 12
  ");
  $cat->execute([$fromTs, $toTs]);

  $dailyRows = $pdo->prepare("
    SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS order_count, COALESCE(SUM(total_cents),0) AS revenue_cents
    FROM orders
    WHERE status = 'completed' AND created_at >= ? AND created_at <= ?
    GROUP BY substr(created_at, 1, 10)
    ORDER BY day ASC
  ");
  $dailyRows->execute([$fromTs, $toTs]);
  $dailyMap = [];
  foreach ($dailyRows->fetchAll() as $row) {
    $dailyMap[(string)$row['day']] = [
      'order_count' => (int)$row['order_count'],
      'revenue_cents' => (int)$row['revenue_cents'],
    ];
  }

  $daily = [];
  $fromDay = substr($fromTs, 0, 10);
  $toDay = substr($toTs, 0, 10);
  $cursor = strtotime($fromDay.' 00:00:00 UTC');
  $end = strtotime($toDay.' 00:00:00 UTC');
  if ($cursor === false || $end === false) {
    $cursor = time();
    $end = $cursor;
  }
  while ($cursor <= $end) {
    $day = gmdate('Y-m-d', $cursor);
    $daily[] = [
      'date' => $day,
      'order_count' => (int)($dailyMap[$day]['order_count'] ?? 0),
      'revenue_cents' => (int)($dailyMap[$day]['revenue_cents'] ?? 0),
    ];
    $cursor += 86400;
  }

  return [
    'summary' => [
      'order_count' => (int)$sum['order_count'],
      'revenue_cents' => (int)$sum['revenue_cents'],
      'aov_cents' => (int)round((float)$sum['aov_cents']),
    ],
    'today_close' => sales_report_close_summary($pdo, gmdate('Y-m-d').' 00:00:00', gmdate('Y-m-d').' 23:59:59'),
    'top_products' => $top->fetchAll(),
    'category_mix' => $cat->fetchAll(),
    'daily' => $daily,
  ];
}

function sales_report_close_summary(PDO $pdo, string $fromTs, string $toTs): array {
  $methods = [
    'cash' => ['order_count' => 0, 'gross_cents' => 0],
    'card' => ['order_count' => 0, 'gross_cents' => 0],
    'mobile' => ['order_count' => 0, 'gross_cents' => 0],
    'credit' => ['order_count' => 0, 'gross_cents' => 0],
  ];

  $byMethod = $pdo->prepare("
    SELECT payment_method, COUNT(*) AS order_count, COALESCE(SUM(total_cents),0) AS gross_cents
    FROM orders
    WHERE status = 'completed' AND created_at >= ? AND created_at <= ?
    GROUP BY payment_method
  ");
  $byMethod->execute([$fromTs, $toTs]);

  $orderCount = 0;
  $gross = 0;
  foreach ($byMethod->fetchAll() as $row) {
    $method = (string)$row['payment_method'];
    $bucket = ($method === 'online' || $method === 'mobile') ? 'mobile' : $method;
    if (!isset($methods[$bucket])) $bucket = 'cash';
    $count = (int)$row['order_count'];
    $amount = (int)$row['gross_cents'];
    $methods[$bucket]['order_count'] += $count;
    $methods[$bucket]['gross_cents'] += $amount;
    $orderCount += $count;
    $gross += $amount;
  }

  $coupons = $pdo->prepare("
    SELECT COUNT(*) AS c
    FROM orders
    WHERE status = 'completed'
      AND created_at >= ? AND created_at <= ?
      AND coupon_code_text IS NOT NULL
      AND TRIM(coupon_code_text) <> ''
  ");
  $coupons->execute([$fromTs, $toTs]);

  $customers = $pdo->prepare("
    SELECT COUNT(*) AS c
    FROM customers
    WHERE created_at >= ? AND created_at <= ?
  ");
  $customers->execute([$fromTs, $toTs]);

  return [
    'from' => substr($fromTs, 0, 10),
    'to' => substr($toTs, 0, 10),
    'order_count' => $orderCount,
    'gross_cents' => $gross,
    'payment_methods' => $methods,
    'coupons_redeemed' => (int)($coupons->fetch()['c'] ?? 0),
    'new_customers' => (int)($customers->fetch()['c'] ?? 0),
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
  echo "<title>".h($CONFIG['APP_NAME'])." - Staff Login</title>";
  echo "<link rel='icon' type='image/svg+xml' href='".h(brand_favicon_href())."'>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>".public_page_css($accent)."</style></head><body>";
  echo "<main class='publicShell'><div class='publicWrap'>";
  echo public_brand_html($CONFIG, 'Mobile-first POS + CRM for neighborhood stores.');
  echo "<section class='publicCard'>";
  echo "<div class='h1'>Staff sign in</div><div class='p'>Open the cashier station, customer list, campaigns, and reports.</div>";
  echo "<form method='post' action='?action=staff_login'>";
  echo "<input type='hidden' name='csrf' value='".h($csrf)."'>";
  echo "<label>Email</label><input name='email' type='email' autocomplete='username' required>";
  echo "<label>Password</label><input name='password' type='password' autocomplete='current-password' required>";
  echo "<button class='btn primary' type='submit'>Sign in</button>";
  if (!empty($err)) echo "<div class='err'>".h($err)."</div>";
  echo "</form>";
  echo "<div class='foot'>Compliance note: you are responsible for SMS/email marketing laws and costs. NeighbourPOS does not process payments. <a href='SETUP.md'>Docs</a>  -  <a href='SECURITY.md'>Security</a></div>";
  echo "</section>";
  echo "</div></main></body></html>";
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
  echo "<title>".h($CONFIG['APP_NAME'])." - Staff Register</title>";
  echo "<link rel='icon' type='image/svg+xml' href='".h(brand_favicon_href())."'>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>".public_page_css($accent)."</style></head><body>";
  echo "<main class='publicShell'><div class='publicWrap'>";
  echo public_brand_html($CONFIG, 'Create a staff login for this store.');
  echo "<section class='publicCard'>";
  echo "<div class='h1'>Create staff account</div><div class='p'>Add an operator account without leaving the single-file install.</div>";
  echo "<form method='post' action='?action=staff_register'>";
  echo "<input type='hidden' name='csrf' value='".h($csrf)."'>";
  echo "<label>Email</label><input name='email' type='email' autocomplete='username' required>";
  echo "<label>Password</label><input name='password' type='password' autocomplete='new-password' minlength='8' required>";
  if (is_admin() || $userCount === 0) {
    echo "<label>Role</label><select name='role'><option value='staff'>staff</option><option value='admin'>admin</option></select>";
  }
  echo "<button class='btn primary' type='submit'>Create account</button>";
  if (!empty($err)) echo "<div class='err'>".h($err)."</div>";
  echo "</form>";
  echo "<div class='muted'>Anti-gaming note: to flag device/IP creating many accounts with different phones, add counters in audit_log keyed by ip or a device fingerprint. <a href='SETUP.md'>Docs</a>  -  <a href='SECURITY.md'>Security</a></div>";
  echo "</section></div></main></body></html>";
  exit;
}

/* =========================
   Campaign CSV export
   ========================= */

if ($action === 'campaign_export') {
  require_login();
  $uid = (int)($_SESSION['uid'] ?? 0);
  $id = (int)($_GET['id'] ?? 0);
  $formatWasExplicit = array_key_exists('format', $_GET);
  $format = strtolower(trim((string)($_GET['format'] ?? 'full')));
  if ($format === '') $format = 'full';
  $bom = !empty($_GET['bom']);
  $includeBalance = !empty($_GET['include_balance']) ? 1 : 0;

  if ($id <= 0) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing or invalid campaign id";
    exit;
  }

  if (!campaign_export_allowed_format($format)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Invalid export format";
    exit;
  }

  $campSt = $pdo->prepare("
    SELECT c.id, c.name, c.channel, c.message_template, c.sent_count, s.name AS segment_name
    FROM campaigns c
    LEFT JOIN segments s ON s.id = c.segment_id
    WHERE c.id = ?
  ");
  $campSt->execute([$id]);
  $camp = $campSt->fetch();
  if (!$camp) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Campaign not found";
    exit;
  }

  $rowSt = $pdo->prepare("
    SELECT
      cr.customer_id,
      cr.phone,
      cr.email AS recipient_email,
      cr.coupon_code,
      cr.sent_at,
      cr.redeemed_order_id,
      cr.redeemed_at,
      cr.status,
      cr.payload_json,
      cust.name AS customer_name,
      cust.email AS customer_email,
      cust.tags_text,
      cust.marketing_opt_in,
      cust.total_spent_cents,
      cust.order_count,
      cust.last_order_at,
      ".ledger_balance_expr('cust.id')." AS balance_cents
    FROM campaign_recipients cr
    LEFT JOIN customers cust ON cust.id = cr.customer_id
    WHERE cr.campaign_id = ?
    ORDER BY cr.id ASC
  ");
  $rowSt->execute([$id]);
  $rows = $rowSt->fetchAll();

  if (!$rows) {
    http_response_code(409);
    header('Content-Type: text/plain; charset=utf-8');
    echo "No queued recipients. Queue campaign recipients before exporting.";
    exit;
  }

  $store = current_store($pdo, $CONFIG);
  $storeName = (string)($store['name'] ?? '');
  $profileRows = [];
  if ($format !== 'full') {
    [, $profileRows] = campaign_export_profile($format, $camp, $rows, (string)($store['default_country_code'] ?? '+1'), $storeName);
  }

  audit($pdo, $uid, 'campaigns.export', [
    'id' => $id,
    'count' => count($rows),
    'format' => $format,
    'export_count' => $format === 'full' ? count($rows) : count($profileRows),
  ]);

  header('Content-Type: text/csv; charset=utf-8');
  $filename = campaign_export_filename($camp, $format, $format === 'full' && !$formatWasExplicit);
  header('Content-Disposition: attachment; filename="'.$filename.'"');
  header('Cache-Control: no-store');

  $out = fopen('php://output', 'w');
  if ($bom) fwrite($out, "\xEF\xBB\xBF");
  if ($format !== 'full') {
    [$headers, $profileRows] = campaign_export_profile($format, $camp, $rows, (string)($store['default_country_code'] ?? '+1'), $storeName);
    fwrite($out, implode(',', $headers)."\n");
    foreach ($profileRows as $profileRow) {
      fputcsv($out, $profileRow);
    }
    fclose($out);
    exit;
  }

  $headers = [
    'campaign_id',
    'campaign_name',
    'segment_name',
    'channel',
    'customer_id',
    'customer_name',
    'phone',
    'email',
    'marketing_opt_in',
    'coupon_code',
    'status',
    'message',
    'opt_in_required',
    'opt_in_overridden',
    'total_spent_cents',
    'order_count',
    'last_order_at',
    'sent_at',
    'redeemed_order_id',
    'redeemed_at',
  ];
  if ($includeBalance) $headers[] = 'balance';
  fputcsv($out, $headers);

  foreach ($rows as $r) {
    $payload = json_decode((string)$r['payload_json'], true);
    if (!is_array($payload)) $payload = [];

    $message = campaign_render_message($camp, $r, $storeName);
    $coupon = (string)($r['coupon_code'] ?: ($payload['coupon_code'] ?? ''));
    $optInRequired = array_key_exists('opt_in_required', $payload) ? (!empty($payload['opt_in_required']) ? '1' : '0') : '';
    $optInOverridden = array_key_exists('opt_in_overridden', $payload) ? (!empty($payload['opt_in_overridden']) ? '1' : '0') : '';
    $email = (string)($r['recipient_email'] ?: ($r['customer_email'] ?? ''));
    $marketingOptIn = ($r['marketing_opt_in'] === null) ? '' : (string)(int)$r['marketing_opt_in'];

    $csvRow = [
      'campaign_id' => csv_safe_cell($camp['id']),
      'campaign_name' => csv_safe_cell($camp['name']),
      'segment_name' => csv_safe_cell($camp['segment_name'] ?? ''),
      'channel' => csv_safe_cell($camp['channel']),
      'customer_id' => csv_safe_cell($r['customer_id']),
      'customer_name' => csv_safe_cell($r['customer_name'] ?? ''),
      'phone' => csv_safe_cell($r['phone']),
      'email' => csv_safe_cell($email),
      'marketing_opt_in' => csv_safe_cell($marketingOptIn),
      'coupon_code' => csv_safe_cell($coupon),
      'status' => csv_safe_cell($r['status']),
      'message' => csv_safe_cell($message),
      'opt_in_required' => csv_safe_cell($optInRequired),
      'opt_in_overridden' => csv_safe_cell($optInOverridden),
      'total_spent_cents' => csv_safe_cell($r['total_spent_cents'] ?? ''),
      'order_count' => csv_safe_cell($r['order_count'] ?? ''),
      'last_order_at' => csv_safe_cell($r['last_order_at'] ?? ''),
      'sent_at' => csv_safe_cell($r['sent_at'] ?? ''),
      'redeemed_order_id' => csv_safe_cell($r['redeemed_order_id'] ?? ''),
      'redeemed_at' => csv_safe_cell($r['redeemed_at'] ?? ''),
    ];
    if ($includeBalance) $csvRow['balance'] = csv_safe_cell(money_fmt($store, (int)($r['balance_cents'] ?? 0)));
    fputcsv($out, array_values($csvRow));
  }

  fclose($out);
  exit;
}

if ($action === 'customer_export') {
  require_login();
  $uid = (int)($_SESSION['uid'] ?? 0);
  $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
  rate_limit_or_fail($pdo, 'customer_export:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), false);

  $format = strtolower(trim((string)($_GET['format'] ?? 'sms')));
  if ($format === '') $format = 'sms';
  if (!campaign_export_allowed_format($format)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Invalid export format";
    exit;
  }

  $segmentId = (int)($_GET['segment_id'] ?? 0);
  $q = trim((string)($_GET['q'] ?? ''));
  $overrideOptIn = !empty($_GET['override_opt_in']) ? 1 : 0;
  $bom = !empty($_GET['bom']);
  $messageTemplate = trim((string)($_GET['message_template'] ?? ''));
  $debtorsOnly = !empty($_GET['debtors']) ? 1 : 0;
  $includeBalance = !empty($_GET['include_balance']) ? 1 : 0;
  $filters = [];
  $exportName = 'customer-export';

  if ($debtorsOnly) {
    $filters = ['has_balance' => true];
    $exportName = 'debtors';
  } elseif ($segmentId > 0) {
    $segSt = $pdo->prepare("SELECT * FROM segments WHERE id = ?");
    $segSt->execute([$segmentId]);
    $seg = $segSt->fetch();
    if (!$seg) {
      http_response_code(404);
      header('Content-Type: text/plain; charset=utf-8');
      echo "Segment not found";
      exit;
    }
    $filters = parse_filters((string)$seg['filters_json']);
    $exportName = (string)($seg['name'] ?? $exportName);
  } elseif ($q !== '') {
    $exportName = 'customer-search';
  }

  $optInOnly = (bool)(($CONFIG['REQUIRE_MARKETING_OPT_IN'] ?? true) && !$overrideOptIn);
  if ($optInOnly) {
    $filters['marketing_opt_in_only'] = true;
  }

  if (!$debtorsOnly && $segmentId <= 0 && $q !== '') {
    $phone = normalize_phone($q);
    $where = "(phone LIKE ? OR name LIKE ? OR email LIKE ? OR tags_text LIKE ?)";
    $params = ['%'.$q.'%', '%'.$q.'%', '%'.$q.'%', '%'.$q.'%'];
    if ($phone !== '') {
      $where = "(".$where." OR phone = ?)";
      $params[] = $phone;
    }
    if ($optInOnly) $where .= " AND marketing_opt_in = 1";
    $st = $pdo->prepare("SELECT c.*, ".ledger_balance_expr('c.id')." AS balance_cents FROM customers c WHERE {$where} ORDER BY COALESCE(last_order_at, created_at) DESC LIMIT 5000");
    $st->execute($params);
    $customers = $st->fetchAll();
  } else {
    $customers = segment_query($pdo, $filters, 5000, 0);
  }
  if (!$customers) {
    http_response_code(409);
    header('Content-Type: text/plain; charset=utf-8');
    echo "No matching customers to export.";
    exit;
  }

  $store = current_store($pdo, $CONFIG);
  $camp = [
    'id' => 0,
    'name' => $exportName,
    'channel' => 'export',
    'message_template' => $messageTemplate,
    'include_campaign_tag' => false,
  ];

  audit($pdo, $uid, 'customers.export', [
    'segment_id' => $segmentId ?: null,
    'q' => $q,
    'format' => $format,
    'count' => count($customers),
    'override_opt_in' => $overrideOptIn,
    'debtors_only' => $debtorsOnly,
  ]);

  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="'.campaign_export_filename($camp, $format, false).'"');
  header('Cache-Control: no-store');
  $out = fopen('php://output', 'w');
  if ($bom) fwrite($out, "\xEF\xBB\xBF");

  if ($format === 'full') {
    $headers = ['customer_id', 'name', 'phone', 'email', 'marketing_opt_in', 'total_spent_cents', 'order_count', 'last_order_at', 'tags'];
    if ($includeBalance) $headers[] = 'balance';
    fputcsv($out, $headers);
    foreach ($customers as $c) {
      $csvRow = [
        csv_safe_cell($c['id'] ?? ''),
        csv_safe_cell($c['name'] ?? ''),
        csv_safe_cell($c['phone'] ?? ''),
        csv_safe_cell($c['email'] ?? ''),
        csv_safe_cell((string)(int)($c['marketing_opt_in'] ?? 0)),
        csv_safe_cell($c['total_spent_cents'] ?? ''),
        csv_safe_cell($c['order_count'] ?? ''),
        csv_safe_cell($c['last_order_at'] ?? ''),
        csv_safe_cell(trim(str_replace(',', ' ', (string)($c['tags_text'] ?? '')))),
      ];
      if ($includeBalance) $csvRow[] = csv_safe_cell(money_fmt($store, (int)($c['balance_cents'] ?? 0)));
      fputcsv($out, $csvRow);
    }
    fclose($out);
    exit;
  }

  [$headers, $profileRows] = campaign_export_profile(
    $format,
    $camp,
    customer_rows_to_export_recipients($customers, $messageTemplate, $store),
    (string)($store['default_country_code'] ?? '+1'),
    (string)($store['name'] ?? '')
  );
  fwrite($out, implode(',', $headers)."\n");
  foreach ($profileRows as $profileRow) {
    fputcsv($out, $profileRow);
  }
  fclose($out);
  exit;
}

if ($action === 'product_import_template') {
  require_login();
  if (!is_admin()) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Admin only';
    exit;
  }
  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="product-import-template.csv"');
  header('Cache-Control: no-store');
  $out = fopen('php://output', 'w');
  fputcsv($out, ['sku', 'name', 'price', 'stock', 'category']);
  fputcsv($out, ['COF-250', 'Neighbour Blend Coffee', '8.50', '24', 'Grocery']);
  fclose($out);
  exit;
}

if ($action === 'inventory_low_stock_export') {
  require_login();
  $threshold = (int)($CONFIG['LOW_STOCK_THRESHOLD'] ?? 5);
  $st = $pdo->prepare("SELECT sku, name, category, price_cents, stock_qty FROM products WHERE active = 1 AND stock_qty <= ? ORDER BY stock_qty ASC, name ASC");
  $st->execute([$threshold]);

  audit($pdo, (int)($_SESSION['uid'] ?? 0), 'inventory.low_stock_export', ['threshold' => $threshold]);

  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="low-stock-products.csv"');
  header('Cache-Control: no-store');
  $out = fopen('php://output', 'w');
  fputcsv($out, ['sku', 'name', 'category', 'price_cents', 'stock_qty', 'threshold']);
  foreach ($st->fetchAll() as $r) {
    fputcsv($out, [
      csv_safe_cell($r['sku'] ?? ''),
      csv_safe_cell($r['name'] ?? ''),
      csv_safe_cell($r['category'] ?? ''),
      csv_safe_cell($r['price_cents'] ?? ''),
      csv_safe_cell($r['stock_qty'] ?? ''),
      csv_safe_cell($threshold),
    ]);
  }
  fclose($out);
  exit;
}

if ($action === 'sales_report_export') {
  require_login();
  [$from, $to, $fromTs, $toTs] = report_date_bounds($_GET);
  $data = sales_report_data($pdo, $fromTs, $toTs);
  audit($pdo, (int)($_SESSION['uid'] ?? 0), 'reports.sales_export', ['from' => $from, 'to' => $to]);

  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="sales-report-'.$from.'-'.$to.'.csv"');
  header('Cache-Control: no-store');
  $out = fopen('php://output', 'w');
  fputcsv($out, ['section', 'name', 'category', 'qty', 'revenue_cents', 'order_count', 'aov_cents']);
  fputcsv($out, ['summary', 'completed orders', '', '', $data['summary']['revenue_cents'], $data['summary']['order_count'], $data['summary']['aov_cents']]);
  foreach ($data['top_products'] as $p) {
    fputcsv($out, ['top_product', csv_safe_cell($p['product_name']), csv_safe_cell($p['category']), $p['qty'], $p['revenue_cents'], '', '']);
  }
  foreach ($data['category_mix'] as $c) {
    fputcsv($out, ['category', '', csv_safe_cell($c['category']), $c['qty'], $c['revenue_cents'], '', '']);
  }
  fclose($out);
  exit;
}

if ($action === 'database_backup') {
  require_login();
  if (!is_admin()) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Admin only";
    exit;
  }
  $dbPath = __DIR__.DIRECTORY_SEPARATOR.'neighbourpos.db';
  if (!is_file($dbPath)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Database file not found";
    exit;
  }
  audit($pdo, (int)($_SESSION['uid'] ?? 0), 'database.backup_download', ['ip' => client_ip()]);
  try {
    $backupPath = database_backup_snapshot($pdo);
  } catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Backup failed";
    exit;
  }
  header('Content-Type: application/octet-stream');
  header('Content-Disposition: attachment; filename="neighbourpos-backup-'.gmdate('Ymd-His').'.db"');
  header('Content-Length: '.filesize($backupPath));
  header('Cache-Control: no-store');
  readfile($backupPath);
  @unlink($backupPath);
  exit;
}

if ($action === 'portal_opt_in_update') {
  if ($method !== 'POST') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Method Not Allowed";
    exit;
  }
  require_csrf();
  $phone = normalize_phone((string)($_POST['phone'] ?? ''));
  $optIn = !empty($_POST['marketing_opt_in']) ? 1 : 0;
  if ($phone !== '') {
    $st = $pdo->prepare("SELECT id, marketing_opt_in FROM customers WHERE phone = ?");
    $st->execute([$phone]);
    $cust = $st->fetch();
    if ($cust) {
      $optTs = ($optIn === 1 && (int)$cust['marketing_opt_in'] === 0) ? now_iso() : null;
      $up = $pdo->prepare("UPDATE customers SET marketing_opt_in = ?, marketing_opt_in_ts = COALESCE(?, marketing_opt_in_ts) WHERE id = ?");
      $up->execute([$optIn, $optTs, (int)$cust['id']]);
      audit($pdo, null, 'portal.opt_in_update', ['phone' => $phone, 'marketing_opt_in' => $optIn, 'ip' => client_ip()]);
    }
  }
  redirect_to('?action=portal&phone='.urlencode($phone));
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

if ($action === 'api_dev_selftest' && PHP_SAPI === 'cli') {
  $result = dev_selftest_results();
  json_out($result, $result['ok'] ? 200 : 500);
}

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

  if ($action === 'api_dev_selftest') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $result = dev_selftest_results();
    json_out($result, $result['ok'] ? 200 : 500);
  }

  if ($action === 'api_today_snapshot') {
    $start = gmdate('Y-m-d').' 00:00:00';
    $end = gmdate('Y-m-d').' 23:59:59';
    $prevStart = gmdate('Y-m-d', time() - 86400).' 00:00:00';
    $prevEnd = gmdate('Y-m-d', time() - 86400).' 23:59:59';

    $today = $pdo->prepare("SELECT COUNT(*) AS c, COALESCE(SUM(total_cents),0) AS revenue FROM orders WHERE created_at >= ? AND created_at <= ?");
    $today->execute([$start, $end]);
    $t = $today->fetch() ?: ['c' => 0, 'revenue' => 0];
    $prev = $pdo->prepare("SELECT COUNT(*) AS c, COALESCE(SUM(total_cents),0) AS revenue FROM orders WHERE created_at >= ? AND created_at <= ?");
    $prev->execute([$prevStart, $prevEnd]);
    $p = $prev->fetch() ?: ['c' => 0, 'revenue' => 0];

    $completed = $pdo->prepare("SELECT COALESCE(SUM(total_cents),0) AS revenue FROM orders WHERE status = 'completed' AND created_at >= ? AND created_at <= ?");
    $completed->execute([$start, $end]);
    $done = $completed->fetch() ?: ['revenue' => 0];
    $prevCompleted = $pdo->prepare("SELECT COALESCE(SUM(total_cents),0) AS revenue FROM orders WHERE status = 'completed' AND created_at >= ? AND created_at <= ?");
    $prevCompleted->execute([$prevStart, $prevEnd]);
    $prevDone = $prevCompleted->fetch() ?: ['revenue' => 0];

    $active = (int)$pdo->query("SELECT COUNT(*) AS c FROM orders WHERE status IN ('new','preparing','ready_for_pickup','out_for_delivery')")->fetch()['c'];
    $prevActiveSt = $pdo->prepare("SELECT COUNT(*) AS c FROM orders WHERE status IN ('new','preparing','ready_for_pickup','out_for_delivery') AND created_at >= ? AND created_at <= ?");
    $prevActiveSt->execute([$prevStart, $prevEnd]);
    $prevActive = (int)$prevActiveSt->fetch()['c'];
    $unpaid = (int)$pdo->query("SELECT COUNT(*) AS c FROM orders WHERE payment_received = 0 AND status NOT IN ('completed','cancelled')")->fetch()['c'];
    $threshold = (int)($CONFIG['LOW_STOCK_THRESHOLD'] ?? 5);
    $low = $pdo->prepare("SELECT COUNT(*) AS c FROM products WHERE active = 1 AND stock_qty <= ?");
    $low->execute([$threshold]);
    $campaigns = (int)$pdo->query("SELECT COUNT(DISTINCT campaign_id) AS c FROM campaign_recipients WHERE status IN ('pending','queued')")->fetch()['c'];
    $recipients = (int)$pdo->query("SELECT COUNT(*) AS c FROM campaign_recipients WHERE status IN ('pending','queued')")->fetch()['c'];
    $outstandingCredit = ledger_outstanding_credit_cents($pdo);
    json_out(['ok' => true, 'data' => [
      'today_order_count' => (int)$t['c'],
      'today_revenue_cents' => (int)$t['revenue'],
      'today_completed_revenue_cents' => (int)$done['revenue'],
      'active_orders_count' => $active,
      'unpaid_orders_count' => $unpaid,
      'outstanding_credit_cents' => $outstandingCredit,
      'low_stock_count' => (int)$low->fetch()['c'],
      'queued_campaigns_count' => $campaigns,
      'queued_recipients_count' => $recipients,
      'previous' => [
        'order_count' => (int)$p['c'],
        'revenue_cents' => (int)$p['revenue'],
        'completed_revenue_cents' => (int)$prevDone['revenue'],
        'active_orders_count' => $prevActive,
      ],
      'deltas' => [
        'today_order_count' => (int)$t['c'] - (int)$p['c'],
        'today_revenue_cents' => (int)$t['revenue'] - (int)$p['revenue'],
        'today_completed_revenue_cents' => (int)$done['revenue'] - (int)$prevDone['revenue'],
        'active_orders_count' => $active - $prevActive,
      ],
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
    $countryCode = normalize_country_code((string)($body['default_country_code'] ?? ($store['default_country_code'] ?? '+1')));

    $st = $pdo->prepare("UPDATE stores SET name=?, enable_delivery=?, tax_rate=?, accent=?, currency=?, currency_symbol=?, default_country_code=? WHERE id=?");
    $st->execute([$name, $enableDelivery, $tax, $accentOk, (string)$store['currency'], $sym, $countryCode, (int)$store['id']]);
    audit($pdo, $uid, 'store.update', ['name' => $name, 'enable_delivery' => $enableDelivery, 'tax_rate' => $tax, 'accent' => $accentOk, 'default_country_code' => $countryCode]);
    json_out(['ok' => true]);
  }

  if ($action === 'api_products_list') {
    $q = trim((string)($_GET['q'] ?? ''));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per = min(50, max(10, (int)($_GET['per'] ?? 25)));
    $off = ($page - 1) * $per;

    $includeInactive = !empty($_GET['include_inactive']) && is_admin();
    $where = $includeInactive ? "WHERE 1=1" : "WHERE active = 1";
    $params = [];
    if ($q !== '') {
      $where .= " AND (name LIKE ? OR sku LIKE ?)";
      $params[] = '%'.$q.'%';
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

  if ($action === 'api_product_save') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);

    $id = (int)($body['id'] ?? 0);
    $sku = substr(trim((string)($body['sku'] ?? '')), 0, 64);
    $name = trim((string)($body['name'] ?? ''));
    $price = max(0, (int)($body['price_cents'] ?? 0));
    $stock = (int)($body['stock_qty'] ?? 0);
    $category = substr(trim((string)($body['category'] ?? '')), 0, 80);
    $active = !empty($body['active']) ? 1 : 0;
    if ($name === '') json_out(['ok' => false, 'error' => 'Product name required'], 400);

    if ($id > 0) {
      $st = $pdo->prepare("UPDATE products SET sku=?, name=?, price_cents=?, stock_qty=?, category=?, active=? WHERE id=?");
      $st->execute([$sku ?: null, $name, $price, $stock, $category ?: null, $active, $id]);
      audit($pdo, $uid, 'products.save', ['id' => $id, 'name' => $name, 'active' => $active]);
    } else {
      $st = $pdo->prepare("INSERT INTO products(sku,name,price_cents,stock_qty,category,active,created_at) VALUES(?,?,?,?,?,?,?)");
      $st->execute([$sku ?: null, $name, $price, $stock, $category ?: null, $active, now_iso()]);
      $id = (int)$pdo->lastInsertId();
      audit($pdo, $uid, 'products.create', ['id' => $id, 'name' => $name, 'active' => $active]);
    }

    json_out(['ok' => true, 'data' => ['id' => $id]]);
  }

  if ($action === 'api_product_import_preview') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'product_import_preview:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);

    $parsed = product_import_parse_csv((string)($body['csv'] ?? ''));
    if (!empty($parsed['too_many'])) json_out(['ok' => false, 'error' => $parsed['error'] ?? 'Product import is capped at 500 rows'], 400);
    json_out(['ok' => true, 'data' => $parsed]);
  }

  if ($action === 'api_product_import_commit') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'product_import_commit:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);

    $filename = substr(trim((string)($body['filename'] ?? 'products.csv')), 0, 180);
    if ($filename === '') $filename = 'products.csv';
    $parsed = product_import_parse_csv((string)($body['csv'] ?? ''));
    if (!empty($parsed['too_many'])) json_out(['ok' => false, 'error' => $parsed['error'] ?? 'Product import is capped at 500 rows'], 400);

    $ts = now_iso();
    $pdo->beginTransaction();
    $imported = product_import_apply($pdo, (array)$parsed['rows'], $ts);
    $ins = $pdo->prepare("INSERT INTO imports(filename,rows_total,rows_imported,errors_json,created_at) VALUES(?,?,?,?,?)");
    $ins->execute([
      $filename,
      (int)$parsed['rows_total'],
      $imported,
      json_encode($parsed['errors'], JSON_UNESCAPED_SLASHES),
      $ts,
    ]);
    $importId = (int)$pdo->lastInsertId();
    audit($pdo, $uid, 'product_import.commit', ['id' => $importId, 'filename' => $filename, 'rows_total' => (int)$parsed['rows_total'], 'rows_imported' => $imported, 'errors' => count((array)$parsed['errors'])]);
    $pdo->commit();

    json_out(['ok' => true, 'data' => [
      'import_id' => $importId,
      'filename' => $filename,
      'rows_total' => (int)$parsed['rows_total'],
      'rows_imported' => $imported,
      'errors' => $parsed['errors'],
    ]]);
  }

  if ($action === 'api_product_imports_list') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $rows = $pdo->query("SELECT id, filename, rows_total, rows_imported, errors_json, created_at FROM imports ORDER BY id DESC LIMIT 20")->fetchAll();
    foreach ($rows as &$row) {
      $errors = json_decode((string)($row['errors_json'] ?? '[]'), true);
      $row['errors'] = is_array($errors) ? $errors : [];
    }
    unset($row);
    json_out(['ok' => true, 'data' => $rows]);
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
    $owes = !empty($_GET['owes']);
    $phone = normalize_phone($q);
    if ($q === '' && $phone === '' && !$owes) json_out(['ok' => true, 'data' => []]);

    $params = [];
    $where = '';
    if ($q === '' && $phone !== '') {
      $where = "WHERE c.phone = ?";
      $params[] = $phone;
    } elseif ($q !== '') {
      $where = "WHERE (c.phone LIKE ? OR c.name LIKE ? OR c.email LIKE ?";
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
      if ($phone !== '') {
        $where .= " OR c.phone = ?";
        $params[] = $phone;
      }
      $where .= ")";
    } else {
      $where = "WHERE 1=1";
    }
    if ($owes) {
      $where .= " AND " . ledger_balance_expr('c.id') . " > 0";
    }

    $st = $pdo->prepare("SELECT c.id, c.phone, c.name, c.marketing_opt_in, c.last_order_at, c.total_spent_cents, c.order_count, c.tags_text, c.created_at, ".ledger_balance_expr('c.id')." AS balance_cents FROM customers c {$where} ORDER BY COALESCE(c.last_order_at, c.created_at) DESC LIMIT 50");
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
    $cust['balance_cents'] = ledger_balance_cents($pdo, (int)$cust['id']);

    $o = $pdo->prepare("SELECT id, order_code, order_type, status, total_cents, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT 20");
    $o->execute([(int)$cust['id']]);

    $cust['ltv_estimate'] = calc_customer_ltv($CONFIG, $cust);
    json_out(['ok' => true, 'data' => ['customer' => $cust, 'orders' => $o->fetchAll(), 'ledger_entries' => ledger_entries_for_customer($pdo, (int)$cust['id'])]]);
  }

  if ($action === 'api_customer_timeline') {
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) json_out(['ok' => false, 'error' => 'Missing customer id'], 400);

    $events = [];
    $orders = $pdo->prepare("SELECT id, order_code, status, total_cents, created_at, coupon_code_text FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT 20");
    $orders->execute([$id]);
    foreach ($orders->fetchAll() as $o) {
      $events[] = [
        'ts' => (string)$o['created_at'],
        'type' => 'order',
        'label' => (string)$o['order_code'].' '.$o['status'],
        'amount_cents' => (int)$o['total_cents'],
        'meta' => (string)($o['coupon_code_text'] ? 'coupon '.$o['coupon_code_text'] : ''),
      ];
    }

    $campaigns = $pdo->prepare("
      SELECT c.name, cr.status, cr.coupon_code, cr.sent_at, cr.redeemed_at, cr.redeemed_order_id, c.created_at
      FROM campaign_recipients cr
      INNER JOIN campaigns c ON c.id = cr.campaign_id
      WHERE cr.customer_id = ?
      ORDER BY COALESCE(cr.sent_at, c.created_at) DESC
      LIMIT 20
    ");
    $campaigns->execute([$id]);
    foreach ($campaigns->fetchAll() as $c) {
      $events[] = [
        'ts' => (string)($c['sent_at'] ?: $c['created_at']),
        'type' => 'campaign',
        'label' => (string)$c['name'],
        'amount_cents' => null,
        'meta' => trim((string)$c['status'].' '.($c['coupon_code'] ? 'coupon '.$c['coupon_code'] : '')),
      ];
      if (!empty($c['redeemed_at'])) {
        $events[] = [
          'ts' => (string)$c['redeemed_at'],
          'type' => 'coupon_redeemed',
          'label' => 'Coupon redeemed',
          'amount_cents' => null,
          'meta' => (string)$c['coupon_code'].' on order #'.$c['redeemed_order_id'],
        ];
      }
    }

    foreach (ledger_entries_for_customer($pdo, $id, 20) as $le) {
      $events[] = [
        'ts' => (string)$le['created_at'],
        'type' => (string)($le['type'] === 'payment' ? 'ledger_payment' : 'ledger_credit'),
        'label' => (string)($le['type'] === 'payment' ? 'Payment recorded' : 'Credit added'),
        'amount_cents' => (int)$le['amount_cents'],
        'meta' => trim((string)(($le['order_code'] ? 'order '.$le['order_code'].' ' : '') . ($le['note'] ?? ''))),
      ];
    }

    usort($events, fn($a, $b) => strcmp((string)$b['ts'], (string)$a['ts']));
    json_out(['ok' => true, 'data' => array_slice($events, 0, 30)]);
  }

  if ($action === 'api_ledger_payment') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $customerId = (int)($body['customer_id'] ?? 0);
    $amount = (int)($body['amount_cents'] ?? 0);
    $note = trim((string)($body['note'] ?? ''));
    if ($customerId <= 0) json_out(['ok' => false, 'error' => 'Customer required'], 400);
    if ($amount <= 0) json_out(['ok' => false, 'error' => 'Payment amount must be positive'], 400);

    $st = $pdo->prepare("SELECT id, phone, name FROM customers WHERE id = ?");
    $st->execute([$customerId]);
    $cust = $st->fetch();
    if (!$cust) json_out(['ok' => false, 'error' => 'Customer not found'], 404);

    $balance = ledger_balance_cents($pdo, $customerId);
    if ($balance <= 0) json_out(['ok' => false, 'error' => 'Customer has no outstanding balance'], 400);
    if ($amount > $balance) json_out(['ok' => false, 'error' => 'Payment exceeds outstanding balance'], 400);

    $ts = now_iso();
    $entryId = ledger_insert($pdo, $customerId, null, 'payment', $amount, $note, $uid, $ts);
    $nextBalance = ledger_balance_cents($pdo, $customerId);
    audit($pdo, $uid, 'ledger.payment', ['entry_id' => $entryId, 'customer_id' => $customerId, 'amount_cents' => $amount, 'balance_cents' => $nextBalance]);
    json_out(['ok' => true, 'data' => ['entry_id' => $entryId, 'balance_cents' => $nextBalance]]);
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

      if ($pid > 0) {
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
        continue;
      }

      $price = (int)max(0, (int)($line['price_cents'] ?? $line['amount_cents'] ?? 0));
      if ($price <= 0) continue;
      $name = trim((string)($line['name'] ?? $line['label'] ?? ''));
      $name = substr($name !== '' ? $name : 'Quick sale', 0, 120);
      $category = '(quick sale)';
      $lineTotal = $price * $qty;
      $subtotal += $lineTotal;

      $itemsOut[] = [
        'product_id' => null,
        'name' => $name,
        'qty' => $qty,
        'price_cents' => $price,
        'notes' => $notes,
        'line_total_cents' => $lineTotal,
        'category' => $category,
      ];

      $itemsForDb[] = [null, $name, $category, $qty, $price, $notes];
    }

    if (count($itemsOut) === 0) json_out(['ok' => false, 'error' => 'No valid items'], 400);

    $taxRate = (float)$store['tax_rate'];
    $tax = (int)round($subtotal * $taxRate);
    $tip = (int)max(0, (int)($body['tip_cents'] ?? 0));
    $total = $subtotal + $tax + $tip;

    $eta = (int)max(5, (int)($body['expected_eta_minutes'] ?? 15));
    $paymentMethod = (string)($body['payment_method'] ?? 'cash');
    if (!in_array($paymentMethod, ['cash','card','online','credit'], true)) $paymentMethod = 'cash';
    if ($paymentMethod === 'credit' && ($walkin === 1 || !$custId)) {
      json_out(['ok' => false, 'error' => 'On-credit orders require a customer phone'], 400);
    }
    $paid = !empty($body['payment_received']) ? 1 : 0;
    if ($paymentMethod === 'credit') $paid = 0;
    $couponCode = strtoupper(trim((string)($body['coupon_code'] ?? '')));
    $couponCode = substr((string)preg_replace('/[^A-Z0-9\-]/', '', $couponCode), 0, 40);

    $orderCode = rand_code(8);
    $ts = now_iso();

    $pdo->beginTransaction();

    $ins = $pdo->prepare("
      INSERT INTO orders(order_code,customer_id,phone_text,order_type,items_json,subtotal_cents,tax_cents,tip_cents,total_cents,status,payment_method,payment_received,expected_eta_minutes,coupon_code_text,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
      $couponCode ?: null,
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

    if ($couponCode !== '' && $custId) {
      $couponSt = $pdo->prepare("
        SELECT id FROM campaign_recipients
        WHERE customer_id = ? AND coupon_code = ? AND redeemed_order_id IS NULL
        ORDER BY id DESC
        LIMIT 1
      ");
      $couponSt->execute([$custId, $couponCode]);
      $couponRow = $couponSt->fetch();
      if ($couponRow) {
        $pdo->prepare("UPDATE campaign_recipients SET redeemed_order_id = ?, redeemed_at = ?, status = 'redeemed' WHERE id = ?")
          ->execute([$orderId, $ts, (int)$couponRow['id']]);
        audit($pdo, $uid, 'coupon.redeemed', ['order_id' => $orderId, 'coupon_code' => $couponCode, 'campaign_recipient_id' => (int)$couponRow['id']]);
      }
    }

    if ($paymentMethod === 'credit' && $custId) {
      $entryId = ledger_insert($pdo, $custId, $orderId, 'credit', $total, 'Order '.$orderCode, $uid, $ts);
      audit($pdo, $uid, 'ledger.credit', ['entry_id' => $entryId, 'customer_id' => $custId, 'order_id' => $orderId, 'amount_cents' => $total]);
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

  if ($action === 'api_orders_search') {
    $q = trim((string)($_GET['q'] ?? ''));
    $status = trim((string)($_GET['status'] ?? ''));
    [$from, $to, $fromTs, $toTs] = report_date_bounds($_GET);
    $where = "WHERE created_at >= ? AND created_at <= ?";
    $params = [$fromTs, $toTs];
    if ($q !== '') {
      $where .= " AND (order_code LIKE ? OR phone_text LIKE ?)";
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
    }
    if ($status !== '' && $status !== 'all') {
      $where .= " AND status = ?";
      $params[] = $status;
    }
    $st = $pdo->prepare("SELECT id, order_code, order_type, phone_text, total_cents, status, payment_method, payment_received, coupon_code_text, created_at, updated_at FROM orders {$where} ORDER BY created_at DESC LIMIT 50");
    $st->execute($params);
    json_out(['ok' => true, 'data' => ['from' => $from, 'to' => $to, 'items' => $st->fetchAll()]]);
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

  if ($action === 'api_sales_report') {
    [$from, $to, $fromTs, $toTs] = report_date_bounds($_GET);
    $data = sales_report_data($pdo, $fromTs, $toTs);
    $data['from'] = $from;
    $data['to'] = $to;
    json_out(['ok' => true, 'data' => $data]);
  }

  if ($action === 'api_segments_list') {
    $rows = $pdo->query("SELECT id, name, filters_json, last_run_at FROM segments ORDER BY id DESC LIMIT 50")->fetchAll();
    foreach ($rows as &$row) {
      $row['count'] = segment_count($pdo, parse_filters((string)$row['filters_json']));
    }
    unset($row);
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
    $segmentId = (int)$pdo->lastInsertId();
    audit($pdo, $uid, 'segments.create', ['name' => $name]);

    json_out(['ok' => true, 'data' => ['id' => $segmentId]]);
  }

  if ($action === 'api_segment_duplicate') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $id = (int)($body['id'] ?? 0);
    if ($id <= 0) json_out(['ok' => false, 'error' => 'Segment id required'], 400);
    $segSt = $pdo->prepare("SELECT * FROM segments WHERE id = ?");
    $segSt->execute([$id]);
    $seg = $segSt->fetch();
    if (!$seg) json_out(['ok' => false, 'error' => 'Segment not found'], 404);

    $copyName = trim((string)$seg['name']).' copy';
    $st = $pdo->prepare("INSERT INTO segments(name, filters_json, last_run_at) VALUES(?,?,NULL)");
    $st->execute([$copyName, (string)$seg['filters_json']]);
    $newId = (int)$pdo->lastInsertId();
    audit($pdo, $uid, 'segments.duplicate', ['id' => $id, 'new_id' => $newId]);
    json_out(['ok' => true, 'data' => ['id' => $newId]]);
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

  if ($action === 'api_campaign_export_preview') {
    $id = (int)($body['id'] ?? 0);
    $format = strtolower(trim((string)($body['format'] ?? 'full')));
    if ($format === '') $format = 'full';
    if ($id <= 0) json_out(['ok' => false, 'error' => 'Campaign id required'], 400);
    if (!campaign_export_allowed_format($format)) json_out(['ok' => false, 'error' => 'Invalid export format'], 400);

    $campSt = $pdo->prepare("
      SELECT c.id, c.name, c.channel, c.message_template, c.sent_count, s.name AS segment_name
      FROM campaigns c
      LEFT JOIN segments s ON s.id = c.segment_id
      WHERE c.id = ?
    ");
    $campSt->execute([$id]);
    $camp = $campSt->fetch();
    if (!$camp) json_out(['ok' => false, 'error' => 'Campaign not found'], 404);

    $rowSt = $pdo->prepare("
      SELECT
        cr.customer_id,
        cr.phone,
        cr.email AS recipient_email,
        cr.coupon_code,
        cr.sent_at,
        cr.redeemed_order_id,
        cr.redeemed_at,
        cr.status,
        cr.payload_json,
        cust.name AS customer_name,
        cust.email AS customer_email,
        cust.tags_text,
        cust.marketing_opt_in,
        cust.total_spent_cents,
        cust.order_count,
        cust.last_order_at
      FROM campaign_recipients cr
      LEFT JOIN customers cust ON cust.id = cr.customer_id
      WHERE cr.campaign_id = ?
      ORDER BY cr.id ASC
    ");
    $rowSt->execute([$id]);
    $rows = $rowSt->fetchAll();

    $store = current_store($pdo, $CONFIG);
    $summary = campaign_export_preview_summary(
      $format,
      $camp,
      $rows,
      (string)($store['default_country_code'] ?? '+1'),
      (string)($store['name'] ?? '')
    );
    $summary['filename'] = campaign_export_filename($camp, $format, false);
    json_out(['ok' => true, 'data' => $summary]);
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

  if ($action === 'api_campaign_preset_create') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $preset = (string)($body['preset'] ?? 'winback');
    $category = trim((string)($body['category'] ?? 'Deli'));
    $spendMin = max(0, (int)($body['spend_min_cents'] ?? 1000));
    $inactiveDays = max(1, (int)($body['inactive_days'] ?? 30));

    $defs = [
      'reward_top_spenders' => [
        'segment' => 'Preset: Reward top spenders',
        'filters' => ['total_spent_min_cents' => $spendMin, 'order_count_min' => 1],
        'campaign' => 'Reward top spenders',
        'message' => 'Thanks for being one of our top customers. Use {coupon_code} on your next visit.',
        'auto_queue' => true,
        'with_coupons' => true,
        'export_format' => 'sms',
      ],
      'win_back_lapsed' => [
        'segment' => 'Preset: Win back lapsed',
        'filters' => ['inactive_days' => $inactiveDays, 'order_count_min' => 1],
        'campaign' => 'Win back lapsed customers',
        'message' => 'We miss you. Use {coupon_code} this week and stop by when convenient.',
        'auto_queue' => true,
        'with_coupons' => true,
        'export_format' => 'sms',
      ],
      'winback' => [
        'segment' => 'Preset: Winback 30d',
        'filters' => ['inactive_days' => 30, 'order_count_min' => 1],
        'campaign' => 'Winback thank-you offer',
        'message' => 'We miss you. Come back this week for a thank-you offer.',
      ],
      'vip' => [
        'segment' => 'Preset: VIP customers',
        'filters' => ['total_spent_min_cents' => 2000, 'order_count_min' => 2],
        'campaign' => 'VIP appreciation',
        'message' => 'Thanks for being a regular. Show this message for a VIP perk.',
      ],
      'new_customers' => [
        'segment' => 'Preset: New customers',
        'filters' => ['recency_days' => 14, 'order_count_max' => 1],
        'campaign' => 'Second visit nudge',
        'message' => 'Thanks for trying us. Your next visit has a small thank-you waiting.',
      ],
      'product_fans' => [
        'segment' => 'Preset: '.$category.' fans',
        'filters' => ['purchased_category' => $category],
        'campaign' => $category.' fan offer',
        'message' => 'You might like what is new in '.$category.'. Stop by this week.',
      ],
    ];
    if (!isset($defs[$preset])) json_out(['ok' => false, 'error' => 'Unknown preset'], 400);
    $def = $defs[$preset];

    $pdo->beginTransaction();
    $seg = $pdo->prepare("INSERT INTO segments(name, filters_json, last_run_at) VALUES(?,?,NULL)");
    $seg->execute([$def['segment'], json_encode($def['filters'], JSON_UNESCAPED_SLASHES)]);
    $segmentId = (int)$pdo->lastInsertId();
    $camp = $pdo->prepare("INSERT INTO campaigns(name, segment_id, channel, message_template, scheduled_at, sent_count, created_at) VALUES(?,?,?,?,NULL,0,?)");
    $camp->execute([$def['campaign'], $segmentId, 'export', $def['message'], now_iso()]);
    $campaignId = (int)$pdo->lastInsertId();
    $queued = 0;
    if (!empty($def['auto_queue'])) {
      $queued = campaign_queue_recipients(
        $pdo,
        $CONFIG,
        ['id' => $campaignId, 'segment_id' => $segmentId, 'message_template' => $def['message']],
        ['id' => $segmentId, 'filters_json' => json_encode($def['filters'], JSON_UNESCAPED_SLASHES)],
        false,
        !empty($def['with_coupons'])
      );
      audit($pdo, $uid, 'campaigns.queue', ['id' => $campaignId, 'count' => $queued, 'override_opt_in' => 0, 'with_coupons' => !empty($def['with_coupons']) ? 1 : 0, 'source' => 'preset']);
    }
    audit($pdo, $uid, 'campaigns.preset_create', ['preset' => $preset, 'segment_id' => $segmentId, 'campaign_id' => $campaignId]);
    $pdo->commit();

    json_out(['ok' => true, 'data' => [
      'segment_id' => $segmentId,
      'campaign_id' => $campaignId,
      'queued' => $queued,
      'focus_campaign_id' => $campaignId,
      'export_format' => (string)($def['export_format'] ?? 'mailchimp'),
      'with_coupons' => !empty($def['with_coupons']) ? 1 : 0,
    ]]);
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

    $pdo->beginTransaction();
    $sentCount = campaign_queue_recipients($pdo, $CONFIG, $camp, $segRow, (bool)$overrideOptIn, (bool)$withCoupons);
    audit($pdo, $uid, 'campaigns.queue', ['id' => $id, 'count' => $sentCount, 'override_opt_in' => $overrideOptIn, 'with_coupons' => $withCoupons]);

    $pdo->commit();

    json_out(['ok' => true, 'data' => ['queued' => $sentCount]]);
  }

  if ($action === 'api_campaign_simulate') {
    $segmentId = (int)($body['segment_id'] ?? 0);
    $red = (float)($body['redemption_rate'] ?? ($CONFIG['SIMULATOR']['DEFAULT_REDEMPTION_RATE'] ?? 0.06));
    $lift = (float)($body['coupon_lift'] ?? ($CONFIG['SIMULATOR']['DEFAULT_COUPON_LIFT'] ?? 0.12));
    $overrideOptIn = !empty($body['override_opt_in']) ? 1 : 0;
    $messageTemplate = trim((string)($body['message_template'] ?? ''));
    $sampleCoupon = strtoupper(trim((string)($body['sample_coupon_code'] ?? '')));
    $sampleCoupon = substr((string)preg_replace('/[^A-Z0-9\-]/', '', $sampleCoupon), 0, 40);
    if ($sampleCoupon === '') $sampleCoupon = (string)($CONFIG['COUPON']['PREFIX'] ?? 'NP').'-PREVIEW';

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
    $store = current_store($pdo, $CONFIG);
    $previewMessages = [];
    if ($messageTemplate !== '') {
      foreach (array_slice($rows, 0, 3) as $c) {
        $previewRow = [
          'customer_id' => $c['id'] ?? null,
          'customer_name' => (string)($c['name'] ?? ''),
          'phone' => (string)($c['phone'] ?? ''),
          'coupon_code' => $sampleCoupon,
          'payload_json' => json_encode([
            'message' => $messageTemplate,
            'coupon_code' => $sampleCoupon,
          ], JSON_UNESCAPED_SLASHES),
        ];
        $previewMessages[] = [
          'customer_id' => (int)($c['id'] ?? 0),
          'name' => (string)($c['name'] ?? ''),
          'phone' => (string)($c['phone'] ?? ''),
          'message' => campaign_render_message(['message_template' => $messageTemplate], $previewRow, (string)($store['name'] ?? '')),
        ];
      }
    }

    json_out(['ok' => true, 'data' => [
      'recipients' => $expectedRecipients,
      'expected_redemptions' => $expectedRedemptions,
      'expected_revenue_cents' => $expectedRevenueCents,
      'avg_order_value_cents_est' => (int)round($avgSpend),
      'assumptions' => ['redemption_rate' => $red, 'coupon_lift' => $lift],
      'preview_messages' => $previewMessages,
    ]]);
  }

  if ($action === 'api_audit_log') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $q = trim((string)($_GET['q'] ?? ''));
    $where = "WHERE 1=1";
    $params = [];
    if ($q !== '') {
      $where .= " AND (a.action LIKE ? OR a.payload_json LIKE ? OR u.email LIKE ?)";
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
      $params[] = '%'.$q.'%';
    }
    $params[] = min(200, max(25, (int)($_GET['limit'] ?? 100)));
    $st = $pdo->prepare("
      SELECT a.id, a.action, a.payload_json, a.ts, u.email AS user_email
      FROM audit_log a
      LEFT JOIN users u ON u.id = a.user_id
      {$where}
      ORDER BY a.id DESC
      LIMIT ?
    ");
    $st->execute($params);
    json_out(['ok' => true, 'data' => $st->fetchAll()]);
  }

  if ($action === 'api_password_change') {
    $rl = (array)($CONFIG['RATE_LIMITS']['API_WRITE'] ?? ['limit' => 120, 'window_seconds' => 300]);
    rate_limit_or_fail($pdo, 'api_write:ip:'.client_ip(), (int)($rl['limit'] ?? 120), (int)($rl['window_seconds'] ?? 300), true);
    $current = (string)($body['current_password'] ?? '');
    $new = (string)($body['new_password'] ?? '');
    if (strlen($new) < 8) json_out(['ok' => false, 'error' => 'New password must be 8+ characters'], 400);
    $st = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
    $st->execute([$uid]);
    $u = $st->fetch();
    if (!$u || !password_verify($current, (string)$u['password_hash'])) json_out(['ok' => false, 'error' => 'Current password incorrect'], 403);
    $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([password_hash($new, PASSWORD_DEFAULT), $uid]);
    audit($pdo, $uid, 'users.password_change', ['ip' => client_ip()]);
    json_out(['ok' => true]);
  }

  if ($action === 'api_admin_password_reset') {
    if (!is_admin()) json_out(['ok' => false, 'error' => 'Admin only'], 403);
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $new = (string)($body['new_password'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($new) < 8) json_out(['ok' => false, 'error' => 'Valid email and 8+ character password required'], 400);
    $st = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $st->execute([$email]);
    $target = $st->fetch();
    if (!$target) json_out(['ok' => false, 'error' => 'User not found'], 404);
    $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([password_hash($new, PASSWORD_DEFAULT), (int)$target['id']]);
    audit($pdo, $uid, 'users.password_reset', ['target_email' => $email, 'ip' => client_ip()]);
    json_out(['ok' => true]);
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
  $csrf = csrf_token();

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
  echo "<title>".h($CONFIG['APP_NAME'])." - Order Status</title>";
  echo "<link rel='icon' type='image/svg+xml' href='".h(brand_favicon_href())."'>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>".public_page_css($accent)."</style></head><body><main class='publicShell'><div class='publicWrap wide'>";
  echo public_brand_html($CONFIG, 'Customer order status and marketing consent.');
  echo "<section class='publicCard'><div class='h1'>Order status lookup</div><div class='p'>Enter your phone number to see recent orders and current status.</div>";
  echo "<form method='get'><input type='hidden' name='action' value='portal'>";
  echo "<label>Phone</label><input name='phone' inputmode='tel' autocomplete='tel' placeholder='Phone (e.g., +14155550101)' value='".h((string)($_GET['phone'] ?? ''))."'>";
  echo "<button class='btn primary' type='submit'>Lookup</button></form></section>";

  if ($phone !== '') {
    if (!$cust) {
      echo "<section class='publicCard'><div class='h1'>Not found</div><div class='muted'>No customer record for ".h($phone).". Ask staff to add you at checkout.</div></section>";
    } else {
      echo "<section class='publicCard'><div class='h1'>".h($cust['name'] ?: $cust['phone'])."</div>";
      echo "<div class='muted'>Marketing opt-in: ".(((int)$cust['marketing_opt_in'] === 1) ? "Yes" : "No")."</div>";
      echo "<form method='post' action='?action=portal_opt_in_update'>";
      echo "<input type='hidden' name='csrf' value='".h($csrf)."'>";
      echo "<input type='hidden' name='phone' value='".h($cust['phone'])."'>";
      echo "<label class='muted' style='display:block;margin-top:10px'><input type='checkbox' name='marketing_opt_in' value='1' ".(((int)$cust['marketing_opt_in'] === 1) ? "checked" : "")."> Marketing opt-in</label>";
      echo "<button class='btn primary' type='submit'>Update opt-in</button></form></section>";

      echo "<section class='publicCard'><div class='h1'>Recent orders</div>";
      if (!$orders) echo "<div class='muted' style='margin-top:8px'>No orders yet.</div>";
      foreach ($orders as $o) {
        $st = (string)$o['status'];
        $cls = 'b-new';
        if ($st === 'preparing') $cls = 'b-prep';
        if ($st === 'ready_for_pickup') $cls = 'b-ready';
        if ($st === 'out_for_delivery') $cls = 'b-out';
        if ($st === 'completed' || $st === 'cancelled') $cls = 'b-done';
        echo "<div class='orderRow'>";
        echo "<div class='row'><div><div style='font-weight:600'>".h($o['order_code'])."</div><div class='muted'>".h($o['order_type'])."  -  ".h($o['created_at'])."</div></div>";
        echo "<div class='badge {$cls}'>".h($st)."</div></div>";
        echo "<div class='muted' style='margin-top:6px'>Total: ".h(money_fmt($store, (int)$o['total_cents']))."  -  ETA: ".(int)$o['expected_eta_minutes']." min</div>";
        echo "</div>";
      }
      echo "</section>";
    }
  }

  echo "<section class='publicCard'><div class='muted'>Disclaimer: Status updates depend on staff actions. For marketing messages, opt-in is required by default; stores must comply with local laws and keep consent proof. <a href='SECURITY.md'>Security</a></div></section>";
  echo "</div></main></body></html>";
  exit;
}

/* =========================
   Receipt (printable)
   ========================= */

if ($action === 'receipt') {
  $code = strtoupper(trim((string)($_GET['code'] ?? '')));
  $id = (int)($_GET['id'] ?? 0);
  if ($code !== '') {
    $st = $pdo->prepare("SELECT * FROM orders WHERE order_code = ?");
    $st->execute([$code]);
  } else {
    require_login();
    $st = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
    $st->execute([$id]);
  }
  $o = $st->fetch();
  if (!$o) { http_response_code(404); echo "Not found"; exit; }

  $store = current_store($pdo, $CONFIG);
  $accent = store_accent_safe($store, $CONFIG);
  $items = json_decode((string)$o['items_json'], true) ?: [];
  $receiptUrl = receipt_public_url((string)$o['order_code']);

  echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  echo "<title>Receipt ".h($o['order_code'])."</title>";
  echo "<link rel='icon' type='image/svg+xml' href='".h(brand_favicon_href())."'>";
  echo "<link rel='preconnect' href='https://fonts.googleapis.com'><link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>";
  echo "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>";
  echo "<style>".receipt_page_css($accent)."</style></head><body><main class='receiptShell'><div class='receiptWrap'>";
  echo "<div class='receiptToolbar'><div class='muted'>Public receipt link</div><div class='toolbarActions'>";
  echo "<button class='btn' type='button' onclick='window.print()'>Print</button>";
  echo "<button class='btn primary' type='button' id='shareReceipt' data-url='".h($receiptUrl)."' data-code='".h((string)$o['order_code'])."'>Share</button>";
  echo "</div><div class='shareStatus' id='shareStatus' aria-live='polite'></div></div>";
  echo "<section class='receiptPaper'>";
  echo "<div class='brandLine'><div class='brandMark' aria-hidden='true'><span>NP</span></div><div><div class='h1'>".h($store['name'])."</div><div class='muted'>Order ".h($o['order_code'])."  -  ".h($o['created_at'])."</div></div></div>";
  echo "<div class='muted'>Type: ".h($o['order_type'])."  -  Status: ".h($o['status'])."</div>";
  echo "<div class='muted'>Customer: ".h((string)($o['phone_text'] ?? ''))."</div>";

  echo "<table>";
  foreach ($items as $it) {
    $name = (string)($it['name'] ?? 'Item');
    $qty = (int)($it['qty'] ?? 1);
    $price = (int)($it['price_cents'] ?? 0);
    $notes = (string)($it['notes'] ?? '');
    echo "<tr><td>".h($qty."x ".$name).($notes ? "<div class='muted'>".h($notes)."</div>" : "")."</td><td class='right'>".h(money_fmt($store, $price*$qty))."</td></tr>";
  }
  echo "</table>";

  echo "<div class='receiptTotals'>";
  echo "<div class='totalRow'><span>Subtotal</span><span>".h(money_fmt($store, (int)$o['subtotal_cents']))."</span></div>";
  echo "<div class='totalRow'><span>Tax</span><span>".h(money_fmt($store, (int)$o['tax_cents']))."</span></div>";
  echo "<div class='totalRow'><span>Tip</span><span>".h(money_fmt($store, (int)$o['tip_cents']))."</span></div>";
  echo "<div class='totalRow total'><span>Total</span><span>".h(money_fmt($store, (int)$o['total_cents']))."</span></div>";
  echo "<div class='totalRow'><span>Payment</span><span>".h($o['payment_method'])." - ".(((int)$o['payment_received']===1) ? "received" : "pending")."</span></div>";
  echo "</div>";
  echo "<div class='muted' style='margin-top:14px'>Platform records payments only; it does not process payments. Thank you!</div>";
  echo "</section></div></main>";
  echo "<script>
    (function(){
      const btn = document.getElementById('shareReceipt');
      const status = document.getElementById('shareStatus');
      if (!btn || !status) return;
      btn.addEventListener('click', async function(){
        const url = btn.dataset.url || window.location.href;
        const payload = {title: document.title, text: 'Receipt '+(btn.dataset.code || ''), url};
        try {
          if (navigator.share) {
            await navigator.share(payload);
            status.textContent = 'Share sheet opened.';
          } else if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(url);
            status.textContent = 'Receipt link copied.';
          } else {
            status.textContent = 'Copy receipt link: '+url;
          }
        } catch (err) {
          status.textContent = 'Copy receipt link: '+url;
        }
      });
    })();
  </script>";
  echo "</body></html>";
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
  <link rel="icon" type="image/svg+xml" href="<?=h(brand_favicon_href())?>">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root{
      --accent: <?=$accent?>;
      --bg:#f6f8fc;
      --panel:#ffffff;
      --card:#ffffff;
      --line:#e5ebf3;
      --line2:#d8e0eb;
      --txt:#090b10;
      --muted:#5c6472;
      --good:#177a3b;
      --warn:#946200;
      --bad:#b42318;
      --violet:#6d35c9;
      --wash:#edf2f8;
      --blueWash:#eaf1ff;
      --greenWash:#eaf7ef;
      --amberWash:#fff5dc;
      --redWash:#fff0ee;
      --violetWash:#f1ecff;
      --shadow-sm:0 1px 2px rgb(9 11 16 / .06);
      --shadow-md:0 4px 12px rgb(9 11 16 / .08);
      --radius-control:6px;
      --radius-card:10px;
      --radius-modal:14px;
    }
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--txt);font-size:14px}
    a{color:inherit}
    button,input,select,textarea{font-family:inherit}
    input,select,textarea{border:0;border-radius:var(--radius-control);background:var(--wash);color:var(--txt);outline:none}
    input:focus,select:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 28%,transparent);background:#fff}
    .iconSprite{position:absolute;width:0;height:0;overflow:hidden}
    .icon{width:18px;height:18px;display:block;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}
    .appShell{min-height:100vh;display:grid;grid-template-columns:214px minmax(0,1fr);transition:grid-template-columns .18s ease}
    .appShell.navCollapsed{grid-template-columns:72px minmax(0,1fr)}
    .app{max-width:1360px;width:100%;margin:0 auto;padding:14px 18px 32px;min-width:0}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
    .brand{display:flex;align-items:center;gap:10px}
    .brandMark{width:40px;height:40px;border-radius:var(--radius-card);display:grid;place-items:center;background:#090b10;color:#fff;font-size:14px;font-weight:900;letter-spacing:0;position:relative;overflow:hidden;box-shadow:var(--shadow-sm);flex:0 0 auto}
    .brandMark::after{content:'';position:absolute;right:6px;top:7px;width:4px;height:26px;border-radius:999px;background:var(--accent)}
    .brandMark span{position:relative;z-index:1;transform:translateX(-1px)}
    .titleRow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    .title{font-weight:700;font-size:15px}
    .sub{color:var(--muted);font-size:12px;margin-top:2px}
    .pill{border:0;background:var(--wash);padding:6px 10px;border-radius:var(--radius-control);font-size:12px;color:var(--muted);font-weight:500}
    .versionPill{background:var(--blueWash);color:var(--accent);font-size:11px;padding:4px 7px}
    .grid{display:grid;grid-template-columns:1fr;gap:12px;min-width:0}
    @media(min-width:980px){ .grid{grid-template-columns: 1.2fr .8fr} }

    .pageHeader{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:14px}
    .pageHeader .h1{font-size:18px;line-height:1.2}
    .pageHeader .muted{max-width:680px}
    .pageActions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex:0 0 auto;flex-wrap:wrap}
    .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-card);padding:16px;box-shadow:var(--shadow-sm);min-width:0}
    .h1{font-size:14px;font-weight:700;margin:0}
    .muted{color:var(--muted);font-size:12px;line-height:1.4}
    .row{display:flex;gap:10px;align-items:center;min-width:0}
    .row > *{flex:1;min-width:0}
    .topbar .row > *,.exportPanel .row > *{flex:0 0 auto}
    .field label{display:block;color:var(--muted);font-size:11px;margin:10px 0 6px}
    .field input,.field select,.field textarea{width:100%;padding:10px 12px;border-radius:var(--radius-control);border:0;background:var(--wash);color:var(--txt);font-size:13px;outline:none}
    .field textarea{min-height:70px;resize:vertical}
    .field input:focus,.field select:focus,.field textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 28%,transparent);background:#fff}

    .btn{padding:9px 11px;border-radius:var(--radius-control);border:0;background:var(--wash);color:var(--txt);font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;font-size:13px;font-weight:500}
    .btn.primary{background:var(--accent);color:#fff}
    .btn.danger{background:var(--redWash);color:var(--bad)}
    .btn.ghost{background:var(--wash)}
    .btn:active{transform:translateY(1px)}
    .btn.small{padding:8px 10px;border-radius:var(--radius-control);font-size:12px}
    .btn:disabled{opacity:.5}

    .nav{position:sticky;top:0;height:100vh;background:#fff;border-right:1px solid var(--line);box-shadow:var(--shadow-sm);z-index:10;padding:14px 10px;display:flex;flex-direction:column;gap:14px}
    .navHead{display:flex;align-items:center;justify-content:space-between;gap:8px}
    .navBrandText{min-width:0}
    .navin{display:grid;gap:4px;padding:0;overflow:visible}
    .tab{--nav-bg:var(--wash);--nav-color:var(--muted);min-width:0;display:grid;grid-template-columns:32px 1fr;align-items:center;gap:10px;padding:7px 8px;border-radius:var(--radius-card);border:0;background:transparent;font-size:13px;color:var(--muted);font-weight:500;text-align:left}
    .tab[data-tab="pos"]{--nav-bg:var(--blueWash);--nav-color:var(--accent)}
    .tab[data-tab="dashboard"]{--nav-bg:var(--greenWash);--nav-color:var(--good)}
    .tab[data-tab="orders"]{--nav-bg:var(--amberWash);--nav-color:var(--warn)}
    .tab[data-tab="inventory"]{--nav-bg:#e9f7f7;--nav-color:#0f766e}
    .tab[data-tab="crm"]{--nav-bg:var(--violetWash);--nav-color:var(--violet)}
    .tab[data-tab="campaigns"]{--nav-bg:#edf8e8;--nav-color:#4d7c0f}
    .tab[data-tab="reports"]{--nav-bg:var(--redWash);--nav-color:var(--bad)}
    .tab[data-tab="admin"]{--nav-bg:#eef0f4;--nav-color:#4b5563}
    .navIcon{width:32px;height:32px;border-radius:var(--radius-card);background:var(--nav-bg);color:var(--nav-color);display:grid;place-items:center}
    .navIcon .icon{width:17px;height:17px}
    .tab:hover,.tab.active{background:var(--nav-bg);color:var(--nav-color)}
    .tab.active .navIcon{background:#fff}
    .sideToggle{width:34px;height:34px;border:0;border-radius:var(--radius-card);background:var(--wash);color:var(--muted);font-weight:700;display:grid;place-items:center;flex:0 0 auto}
    .sideToggle:hover{background:var(--blueWash);color:var(--accent)}
    .navCopy{margin-top:auto;border-radius:var(--radius-card);background:var(--wash);padding:12px;color:var(--muted);font-size:12px;line-height:1.45}
    .appShell.navCollapsed .nav{align-items:center}
    .appShell.navCollapsed .navHead{display:grid;justify-items:center}
    .appShell.navCollapsed .navBrandText,.appShell.navCollapsed .navLabel,.appShell.navCollapsed .navCopy{display:none}
    .appShell.navCollapsed .tab{width:44px;grid-template-columns:1fr;justify-items:center;padding:6px}
    .appShell.navCollapsed .sideToggle span{transform:rotate(180deg)}

    .list{display:flex;flex-direction:column;gap:0;margin-top:10px}
    .emptyState{border:1px dashed var(--line2);border-radius:var(--radius-card);background:#fff;padding:16px;display:grid;gap:8px;color:var(--muted)}
    .emptyIcon{width:36px;height:36px;border-radius:var(--radius-card);background:var(--wash);color:var(--accent);display:grid;place-items:center}
    .emptyIcon .icon{width:18px;height:18px}
    .emptyTitle{color:var(--txt);font-size:15px;font-weight:700}
    .emptyActions{display:flex;gap:8px;flex-wrap:wrap;margin-top:2px}
    .retryCard{border:1px solid var(--line);border-radius:var(--radius-card);background:var(--redWash);color:#8a1f17;padding:14px;display:grid;gap:8px}
    .retryCard .muted{color:#8a1f17}
    .retryCard .btn{justify-self:start;background:#fff}
    .saleGrid .retryCard,.saleGrid .emptyState,.kpi .retryCard{grid-column:1/-1}
    .offlineBanner{margin:-2px 0 12px;padding:10px 12px;border-radius:var(--radius-card);background:var(--redWash);color:#8a1f17;font-size:13px;font-weight:500}
    .offlineBanner[hidden]{display:none}
    .skeletonStack{display:grid;gap:10px;margin-top:10px}
    .skeletonRow,.skeletonTile,.skeletonKpi{position:relative;overflow:hidden;border-radius:var(--radius-card);background:var(--wash)}
    .skeletonRow{height:54px}
    .skeletonTile{min-height:150px;border:1px solid var(--line);background:#fff}
    .skeletonKpi{height:76px;border:1px solid var(--line);background:#fff}
    .skeletonRow::after,.skeletonTile::after,.skeletonKpi::after{content:'';position:absolute;inset:0;transform:translateX(-100%);background:linear-gradient(90deg,transparent,rgba(255,255,255,.72),transparent);animation:skeletonSweep 1.2s infinite}
    .skeletonGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:12px;margin-top:10px}
    @keyframes skeletonSweep{to{transform:translateX(100%)}}
    .item{padding:12px 0;border-radius:0;border:0;background:#fff}
    .item + .item{border-top:1px solid var(--line2)}
    .item.focusedItem{margin:8px -8px 0;padding:12px 8px;border:1px solid color-mix(in srgb,var(--accent) 24%,var(--line));border-radius:var(--radius-card);background:var(--blueWash)}
    .item .name{font-weight:500;font-size:13px}
    .item .meta{color:var(--muted);font-size:12px;margin-top:4px}
    .exportPanel{margin-top:10px;padding-top:10px;border-top:1px solid var(--line2)}
    .exportPanel .row{flex-wrap:wrap}
    .exportPanel .field{flex:1 1 150px;min-width:150px;max-width:220px}
    .checkRow{display:flex;align-items:center;gap:8px;min-height:40px;padding:0 10px;border-radius:var(--radius-control);background:var(--wash);color:var(--txt);font-size:12px;font-weight:500;white-space:nowrap}
    .checkRow input{width:16px;height:16px;margin:0;accent-color:var(--accent)}
    .exportSummary{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
    .exportSummary span{display:inline-flex;align-items:center;min-height:28px;border-radius:var(--radius-control);background:var(--blueWash);color:#1642a6;padding:0 8px;font-size:12px}
    .dataTableWrap{max-width:100%;overflow:auto;margin-top:10px;border:1px solid var(--line);border-radius:var(--radius-card);background:#fff}
    .dataTable{width:100%;min-width:720px;border-collapse:separate;border-spacing:0;font-size:13px}
    .dataTable th{position:sticky;top:0;z-index:1;background:#f8fafc;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
    .dataTable td{min-height:54px;padding:10px 12px;border-top:1px solid var(--line2);vertical-align:middle}
    .dataTable tbody tr:first-child td{border-top:0}
    .dataTable tbody tr:hover{background:#f8fafc}
    .dataTable .num{text-align:right;font-variant-numeric:tabular-nums}
    .dataTable .actions{text-align:right;white-space:nowrap}
    .dataTitle{font-weight:600;color:var(--txt)}
    .dataMeta{color:var(--muted);font-size:12px;margin-top:3px;line-height:1.35}
    .statusBadge,.badge{display:inline-flex;align-items:center;min-height:23px;font-size:11px;padding:0 8px;border-radius:999px;border:0;color:#445064;white-space:nowrap;font-weight:600}
    .b-new{background:var(--blueWash)}
    .b-prep{background:var(--amberWash)}
    .b-ready{background:var(--greenWash)}
    .b-out{background:var(--violetWash)}
    .b-done{background:#eef0f4}
    .kpi{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px}
    .k{padding:14px;border-radius:var(--radius-card);border:1px solid var(--line);background:#fff;box-shadow:var(--shadow-sm)}
    .kHead{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
    .kIcon{width:32px;height:32px;border-radius:var(--radius-card);display:grid;place-items:center;background:var(--wash);color:var(--accent)}
    .kIcon .icon{width:17px;height:17px}
    .k .v{font-weight:700;font-size:16px}
    .k .l{color:var(--muted);font-size:11px;margin-top:4px}
    .kDelta{display:inline-flex;align-items:center;min-height:22px;border-radius:999px;padding:0 8px;font-size:11px;font-weight:600;background:var(--wash);color:var(--muted);white-space:nowrap}
    .kDelta.up{background:var(--greenWash);color:var(--good)}
    .kDelta.down{background:var(--redWash);color:var(--bad)}
    .closeCard{display:grid;gap:12px}
    .closeHead{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
    .closeMetrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
    .closeMetric{border-radius:var(--radius-control);background:var(--wash);padding:10px}
    .closeMetric strong{display:block;font-size:20px;line-height:1.1}
    .closeMetric span{display:block;margin-top:4px;color:var(--muted);font-size:11px}
    .closeRows{display:grid;gap:0;border-top:1px solid var(--line2)}
    .closeRow{display:grid;grid-template-columns:1fr auto;gap:12px;padding:8px 0;border-bottom:1px solid var(--line2);font-size:13px}
    .closeRow span{color:var(--muted);font-size:12px}
    .closeRow strong{text-align:right}
    .sparklineWrap{margin-top:14px;border-radius:var(--radius-card);background:#f8fafc;border:1px solid var(--line);padding:12px}
    .sparklineMeta{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;color:var(--muted);font-size:12px}
    .sparkline{display:block;width:100%;height:150px;overflow:visible}
    .sparklineGrid{stroke:var(--line);stroke-width:1}
    .sparklineArea{fill:color-mix(in srgb,var(--accent) 14%,transparent)}
    .sparklineLine{fill:none;stroke:var(--accent);stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
    .attentionList{display:grid;gap:10px;margin-top:12px}
    .attentionItem{display:grid;grid-template-columns:34px 1fr auto;align-items:center;gap:10px;padding:10px;border-radius:var(--radius-card);background:#fff;border:1px solid var(--line)}
    .attentionIcon{width:34px;height:34px;border-radius:var(--radius-card);display:grid;place-items:center;background:var(--wash);color:var(--accent)}
    .attentionIcon.warn{background:var(--amberWash);color:var(--warn)}
    .attentionIcon.bad{background:var(--redWash);color:var(--bad)}
    .attentionIcon.good{background:var(--greenWash);color:var(--good)}
    .attentionIcon .icon{width:17px;height:17px}
    .attentionItem .name{font-size:13px;font-weight:600}
    .attentionItem .meta{margin-top:3px;color:var(--muted);font-size:12px;line-height:1.35}
    .attentionValue{font-weight:700}
    .warnbox{margin-top:10px;padding:10px;border-radius:var(--radius-card);border:0;background:var(--amberWash);color:#744800;font-size:12px;line-height:1.35}
    .okbox{margin-top:10px;padding:10px;border-radius:var(--radius-card);border:0;background:var(--greenWash);color:#145c2e;font-size:12px;line-height:1.35}
    .errbox{margin-top:10px;padding:10px;border-radius:var(--radius-card);border:0;background:var(--redWash);color:#8a1f17;font-size:12px;line-height:1.35}
    .checkoutShell{display:grid;grid-template-columns:minmax(0,1fr) 372px;gap:16px;align-items:start}
    .stationPanel,.cartPanel{background:#fff;border:1px solid var(--line);border-radius:var(--radius-card);box-shadow:var(--shadow-sm)}
    .stationPanel{padding:16px;min-width:0}
    .cartPanel{position:sticky;top:14px;display:grid;gap:12px;padding:14px;max-height:calc(100vh - 112px);overflow:auto}
    .saleToolbar{display:grid;grid-template-columns:minmax(0,1fr) 42px 42px;gap:8px;margin-bottom:12px}
    .saleSearch{height:42px;padding-left:38px;background:#fff url("data:image/svg+xml,%3Csvg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='%235c6472' stroke-width='2' xmlns='http://www.w3.org/2000/svg'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m21 21-4.3-4.3'/%3E%3C/svg%3E") no-repeat 12px center}
    .iconBtn{width:42px;height:42px;border:0;border-radius:var(--radius-control);background:var(--wash);color:#1f2a3d;display:grid;place-items:center}
    .iconBtn .icon{width:20px;height:20px}
    .categoryTabs{display:flex;gap:4px;border:0;border-radius:var(--radius-card);overflow:auto;margin-bottom:14px;background:var(--wash);padding:4px}
    .categoryTabs button{min-width:104px;height:34px;border:0;border-radius:var(--radius-control);background:transparent;color:var(--muted);font-size:13px;font-weight:500}
    .categoryTabs button:last-child{border-right:0}
    .categoryTabs button.active{background:var(--accent);color:#fff}
    .saleGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:12px}
    .saleTile{min-height:150px;padding:12px;align-content:space-between;text-align:left;border:1px solid var(--line);border-radius:var(--radius-card);background:#fff;box-shadow:var(--shadow-sm);transition:background .12s ease,transform .12s ease,box-shadow .12s ease}
    .saleTile:hover{background:var(--blueWash);transform:translateY(-1px);box-shadow:var(--shadow-md)}
    .saleTile:active{transform:translateY(0);box-shadow:var(--shadow-sm)}
    .quickSaleTile{border-color:color-mix(in srgb,var(--accent) 24%,var(--line));background:var(--blueWash)}
    .quickSaleTile .productVisual{background:#090b10;color:#fff}
    .productVisual{width:48px;height:48px;border-radius:var(--radius-card);display:grid;place-items:center;background:#eef5ff;color:var(--accent);font-size:18px;font-weight:700}
    .productVisual .icon{width:19px;height:19px}
    .productMeta{display:grid;gap:4px;margin-top:10px;justify-items:start}
    .stockText{font-size:12px;font-weight:500;color:var(--good)}
    .stockText.low{color:var(--warn)}
    .cartTitle{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .cartTitle .h1{font-size:18px}
    .customerLookup{display:grid;gap:8px}
    .customerChip{border:0;border-radius:var(--radius-card);background:var(--greenWash);padding:10px;display:flex;gap:10px;align-items:center}
    .avatar{width:38px;height:38px;border-radius:var(--radius-card);background:var(--good);color:#fff;display:grid;place-items:center;font-weight:700;flex:0 0 auto}
    .chipMain{min-width:0;flex:1}
    .chipMain strong{display:block;font-size:13px;font-weight:500}
    .chipMain span{display:block;font-size:12px;color:var(--muted);margin-top:2px}
    .chipMeta{font-size:12px;font-weight:500;color:var(--good);white-space:nowrap}
    .compactFields{display:grid;grid-template-columns:1fr 112px;gap:8px}
    .cartLine{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start;border-top:1px solid var(--line2);background:#fff;border-radius:0;padding:9px 0}
    .cartLine:first-child{border-top:0}
    .lineControls{display:flex;align-items:center;gap:5px}
    .lineControls .btn.small{padding:8px}
    .lineControls .icon{width:14px;height:14px}
    .lineControls [data-note-prompt]{min-width:52px}
    .noteText{display:block;color:var(--muted);font-size:12px;margin-top:3px}
    .couponRow{display:grid;grid-template-columns:1fr;gap:8px}
    .totals{border:1px solid color-mix(in srgb,var(--accent) 12%,var(--line));border-radius:var(--radius-card);background:var(--blueWash);padding:10px;display:grid;gap:8px;box-shadow:var(--shadow-sm)}
    .totalRow{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:13px;color:var(--muted)}
    .totalRow strong{font-size:22px;color:var(--txt);font-weight:700}
    .segmented{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
    .segmented button{height:36px;border:0;border-radius:var(--radius-control);background:var(--wash);font-size:13px;font-weight:500;color:#445064}
    .segmented button.active{color:var(--accent);background:var(--blueWash)}
    .tenderGrid{display:grid;grid-template-columns:1fr 98px;gap:8px}
    .cashTender{display:grid;grid-template-columns:1fr 132px;gap:8px;align-items:end}
    .cashTender label{display:block;color:var(--muted);font-size:11px;margin:0 0 6px}
    .changeDue{border-radius:var(--radius-card);background:var(--greenWash);padding:10px;color:#145c2e;font-size:12px}
    .changeDue strong{display:block;margin-top:3px;font-size:16px;color:#145c2e}
    .paidRow{display:flex;align-items:center;justify-content:space-between;gap:8px;font-weight:500}
    .switch{width:43px;height:24px;border-radius:999px;border:0;background:#dbe1ea;padding:2px;display:flex;justify-content:flex-start}
    .switch.on{background:var(--good);border-color:var(--good);justify-content:flex-end}
    .switch i{display:block;width:18px;height:18px;border-radius:999px;background:#fff}
    .tinyStatus{display:flex;align-items:center;gap:16px;overflow:auto;border:0;border-radius:var(--radius-card);background:var(--wash);padding:10px;margin-top:12px;color:var(--muted);font-size:12px;font-weight:500}
    .toastHost{position:fixed;top:16px;right:16px;z-index:80;display:grid;gap:8px;max-width:min(360px,calc(100vw - 32px))}
    .toast{border:1px solid var(--line);border-radius:var(--radius-card);background:#fff;box-shadow:var(--shadow-md);padding:10px 12px;font-size:13px;color:var(--txt)}
    .toast.ok{border-color:#c7ecd5;background:#f1fbf5;color:#145c2e}
    .toast.err{border-color:#ffd2cc;background:#fff6f4;color:#8a1f17}
    .toast.info{border-color:#d8e3ff;background:#f4f7ff;color:#1f3f9a}
    .modalRoot{position:fixed;inset:0;z-index:90;display:none;place-items:center;padding:18px}
    .modalRoot.open{display:grid}
    .modalBackdrop{position:absolute;inset:0;background:rgba(9,11,16,.32)}
    .modalCard{position:relative;width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius-modal);background:#fff;box-shadow:var(--shadow-md);padding:18px;display:grid;gap:12px}
    .modalActions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap}
    .modalCard input{width:100%;padding:10px 12px}
    .saleTile strong,.saleTile .name{font-size:18px;font-weight:500;line-height:1.18}
    .cartLine strong,td strong{font-size:13px;font-weight:500}
    .tinyStatus span{white-space:nowrap}
    .tinyStatus b{display:inline-grid;place-items:center;min-width:22px;height:22px;border-radius:999px;background:#eaf0ff;color:var(--accent);margin-left:4px}
    @media(max-width:980px){
      .appShell,.appShell.navCollapsed{grid-template-columns:1fr}
      .nav{height:auto;position:sticky;top:0;align-items:stretch}
      .navHead{display:flex}
      .sideToggle{display:none}
      .navin{grid-template-columns:repeat(4,minmax(0,1fr));overflow:auto}
      .tab,.appShell.navCollapsed .tab{width:100%;grid-template-columns:32px 1fr;justify-items:start}
      .appShell.navCollapsed .navBrandText,.appShell.navCollapsed .navLabel{display:block}
      .navCopy{display:none}
      .checkoutShell{grid-template-columns:1fr}
      .cartPanel{position:static;max-height:none}
      .btn,.btn.small,.iconBtn,.categoryTabs button,.segmented button,.tab,input,select,textarea{min-height:44px}
      .iconBtn,input[type="checkbox"]{min-width:44px}
      .lineControls .btn.small,.switch{min-width:44px;min-height:44px}
    }
    @media(max-width:620px){
      .app{padding:12px}
      .topbar{display:grid}
      .pageHeader{display:grid}
      .pageActions{justify-content:flex-start}
      .row{flex-wrap:wrap}
      .navin{grid-template-columns:repeat(2,minmax(0,1fr))}
      .kpi{grid-template-columns:1fr}
      .dataTable{min-width:640px}
      .saleToolbar,.compactFields,.tenderGrid,.cashTender{grid-template-columns:1fr}
      .segmented{grid-template-columns:1fr}
      .saleGrid{grid-template-columns:repeat(2,minmax(0,1fr))}
    }
    @page{size:80mm auto;margin:4mm}
    @media print{
      html,body{width:80mm;margin:0;background:#fff}
      body{font-size:11px;color:#111}
      .appShell{display:block;min-height:0}
      .nav,.topbar,.pageHeader,.card:not(.closeCard),.noPrint{display:none!important}
      .app{width:72mm;max-width:none;margin:0 auto;padding:0}
      .grid{display:block}
      .closeCard{display:block;border:0;border-radius:0;box-shadow:none;padding:0;width:72mm;background:#fff}
      .closeHead{display:flex;align-items:flex-start;justify-content:space-between;border-bottom:1px solid #ddd;padding-bottom:6px;margin-bottom:8px}
      .closeCard .h1{font-size:14px}
      .closeCard .muted{font-size:10px;color:#222}
      .closeMetrics{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-bottom:8px}
      .closeMetric{border-radius:0;background:#fff;border:1px solid #ddd;padding:6px}
      .closeMetric strong{font-size:13px}
      .closeMetric span{font-size:9.5px;color:#222}
      .closeRows{border-top:1px solid #ddd}
      .closeRow{font-size:10.5px;padding:5px 0;border-bottom:1px solid #ddd}
      .closeRow span{font-size:9.5px;color:#222}
    }
  </style>
</head>
<body>
<svg class="iconSprite" aria-hidden="true" focusable="false">
  <symbol id="i-pos" viewBox="0 0 24 24"><path d="M4 7h16"/><path d="M6 7l1-3h10l1 3"/><path d="M5 7v12h14V7"/><path d="M9 11h6"/><path d="M9 15h6"/></symbol>
  <symbol id="i-dashboard" viewBox="0 0 24 24"><path d="M4 13a8 8 0 0 1 16 0"/><path d="M12 13l4-5"/><path d="M5 17h14"/></symbol>
  <symbol id="i-orders" viewBox="0 0 24 24"><path d="M7 4h10l2 3v13H5V7z"/><path d="M8 9h8"/><path d="M8 13h8"/><path d="M8 17h5"/></symbol>
  <symbol id="i-inventory" viewBox="0 0 24 24"><path d="M4 7l8-4 8 4-8 4z"/><path d="M4 7v10l8 4 8-4V7"/><path d="M12 11v10"/></symbol>
  <symbol id="i-crm" viewBox="0 0 24 24"><path d="M16 19a4 4 0 0 0-8 0"/><circle cx="12" cy="8" r="3"/><path d="M19 17a3 3 0 0 0-3-3"/><path d="M5 17a3 3 0 0 1 3-3"/></symbol>
  <symbol id="i-campaigns" viewBox="0 0 24 24"><path d="M4 13V9l11-4v12z"/><path d="M15 9h3a3 3 0 0 1 0 6h-3"/><path d="M8 14l1 5"/></symbol>
  <symbol id="i-reports" viewBox="0 0 24 24"><path d="M5 19V5"/><path d="M5 19h14"/><path d="M9 16v-5"/><path d="M13 16V8"/><path d="M17 16v-3"/></symbol>
  <symbol id="i-admin" viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-5"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14"/><path d="M5 12h14"/></symbol>
  <symbol id="i-minus" viewBox="0 0 24 24"><path d="M5 12h14"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 14h10l1-14"/><path d="M9 7V4h6v3"/></symbol>
  <symbol id="i-export" viewBox="0 0 24 24"><path d="M12 4v11"/><path d="M8 8l4-4 4 4"/><path d="M5 15v4h14v-4"/></symbol>
  <symbol id="i-print" viewBox="0 0 24 24"><path d="M7 9V4h10v5"/><path d="M7 17H5a2 2 0 0 1-2-2v-4h18v4a2 2 0 0 1-2 2h-2"/><path d="M7 14h10v6H7z"/></symbol>
  <symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></symbol>
  <symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 4l9 16H3z"/><path d="M12 9v5"/><path d="M12 18h.01"/></symbol>
  <symbol id="i-barcode" viewBox="0 0 24 24"><path d="M4 5v14"/><path d="M8 5v14"/><path d="M11 5v14"/><path d="M16 5v14"/><path d="M20 5v14"/></symbol>
  <symbol id="i-keyboard" viewBox="0 0 24 24"><path d="M4 7h16v10H4z"/><path d="M7 10h.01"/><path d="M10 10h.01"/><path d="M13 10h.01"/><path d="M16 10h.01"/><path d="M8 14h8"/></symbol>
  <symbol id="i-note" viewBox="0 0 24 24"><path d="M6 4h9l3 3v13H6z"/><path d="M15 4v4h4"/><path d="M9 12h6"/><path d="M9 16h4"/></symbol>
  <symbol id="i-chevron-left" viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></symbol>
</svg>
<div class="appShell" id="appShell">
  <aside class="nav" aria-label="Primary">
    <div class="navHead">
      <div class="brand">
        <div class="brandMark" aria-hidden="true"><span>NP</span></div>
        <div class="navBrandText">
          <div class="title"><?=h($CONFIG['APP_NAME'])?></div>
          <div class="sub"><?=h((string)$store['name'])?></div>
        </div>
      </div>
      <button class="sideToggle" id="navToggle" type="button" aria-label="Collapse sidebar" aria-pressed="false" title="Collapse sidebar"><span aria-hidden="true"><svg class="icon"><use href="#i-chevron-left"></use></svg></span></button>
    </div>
    <div class="navin">
      <button class="tab" data-tab="dashboard"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-dashboard"></use></svg></span><span class="navLabel">Dashboard</span></button>
      <button class="tab" data-tab="pos"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-pos"></use></svg></span><span class="navLabel">POS</span></button>
      <button class="tab" data-tab="orders"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-orders"></use></svg></span><span class="navLabel">Orders</span></button>
      <button class="tab" data-tab="inventory"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-inventory"></use></svg></span><span class="navLabel">Inventory</span></button>
      <button class="tab" data-tab="crm"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-crm"></use></svg></span><span class="navLabel">CRM</span></button>
      <button class="tab" data-tab="campaigns"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-campaigns"></use></svg></span><span class="navLabel">Campaigns</span></button>
      <button class="tab" data-tab="reports"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-reports"></use></svg></span><span class="navLabel">Reports</span></button>
      <button class="tab" data-tab="admin"><span class="navIcon" aria-hidden="true"><svg class="icon"><use href="#i-admin"></use></svg></span><span class="navLabel">Admin</span></button>
    </div>
    <div class="navCopy">Flat local POS + CRM with owned data, CSV exports, and SQLite backups.</div>
  </aside>

  <main class="app">
  <div class="topbar">
    <div class="brand">
      <div>
        <div class="titleRow"><div class="title"><?=h((string)$store['name'])?> counter</div><span class="pill versionPill mono">v<?=h(APP_VERSION)?></span></div>
        <div class="sub">POS convenience, customer memory, campaigns, and local data ownership.</div>
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

  <div id="offlineBanner" class="offlineBanner" role="status" aria-live="polite" hidden>Connection lost - changes can't save</div>
  <div id="view"></div>
  <div id="toastHost" class="toastHost" aria-live="polite" aria-atomic="true"></div>
  <div id="modalRoot" class="modalRoot" aria-hidden="true"></div>
  </main>
</div>

<script>
  const CSRF = document.querySelector('meta[name="csrf-token"]').getAttribute('content')
  const $view = document.getElementById('view')
  const state = {
    me: null,
    store: null,
    tab: 'pos',
    dashboard: null,
    dashboardTrend: null,
    report: null,
    reportFrom: '',
    reportTo: '',
    products: [],
    cart: [],
    categoryFilter: 'All',
    attachedCustomer: null,
    customerLookupStatus: 'empty',
    customerLookupError: '',
    pos: {
      q: '',
      phone: '',
      name: '',
      address: '',
      optIn: '0',
      walkin: false,
      coupon: '',
      tipCents: 0,
      amountTenderedCents: 0,
      payMethod: 'cash',
      paid: false,
      type: 'pickup',
      eta: 15
    },
    lastTouchedProductId: null,
    lastTouchedLineId: null,
    lowStock: [],
    productImports: [],
    productImport: {
      filename: 'products.csv',
      csv: '',
      preview: null,
      busy: false
    },
    orders: [],
    orderSearch: [],
    selectedOrder: null,
    customerSearch: [],
    customerOwesOnly: false,
    selectedCustomer: null,
    customerOrders: [],
    customerTimeline: [],
    segments: [],
    campaigns: [],
    auditLogs: [],
    campaignExport: {},
    focus_campaign_id: null,
    customerExport: { format: 'sms', segmentId: '', q: '', bom: false, override: false },
    loading: {},
    errors: {},
    lastCustomerId: null,
    connectionFetchFailed: false,
    sim: null
  }

  function qs(sel, el=document){ return el.querySelector(sel) }
  function qsa(sel, el=document){ return [...el.querySelectorAll(sel)] }
  function esc(s){ return (s??'').toString().replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])) }
  function icon(id){ return `<svg class="icon" aria-hidden="true"><use href="#i-${id}"></use></svg>` }
  function pageHeader(title, description, actionHtml=''){
    return `<div class="pageHeader">
      <div><div class="h1">${esc(title)}</div><div class="muted">${esc(description)}</div></div>
      ${actionHtml ? `<div class="pageActions">${actionHtml}</div>` : ''}
    </div>`
  }
  function emptyState(iconId, title, body, actionHtml=''){
    return `<div class="emptyState">
      <span class="emptyIcon">${icon(iconId)}</span>
      <div class="emptyTitle">${esc(title)}</div>
      <div>${esc(body)}</div>
      ${actionHtml ? `<div class="emptyActions">${actionHtml}</div>` : ''}
    </div>`
  }
  function skeletonList(count=3){ return `<div class="skeletonStack" aria-label="Loading">${Array.from({length:count},()=>'<div class="skeletonRow"></div>').join('')}</div>` }
  function skeletonTiles(count=8){ return `<div class="skeletonGrid" aria-label="Loading products">${Array.from({length:count},()=>'<div class="skeletonTile"></div>').join('')}</div>` }
  function skeletonKpis(count=4){ return `<div class="kpi" aria-label="Loading metrics">${Array.from({length:count},()=>'<div class="skeletonKpi"></div>').join('')}</div>` }
  function retryState(key, title='Could not load this section', body='Check the connection and try again.'){
    return `<div class="retryCard">
      <div class="h1">${esc(title)}</div>
      <div class="muted">${esc(body)}</div>
      <button class="btn small" type="button" data-retry="${esc(key)}">Retry</button>
    </div>`
  }
  function regionState(key, loadingHtml, errorTitle, errorBody){
    if (state.loading[key]) return loadingHtml
    if (state.errors[key]) return retryState(key, errorTitle, state.errors[key] || errorBody)
    return ''
  }
  function setRegionLoading(key, loading){
    state.loading[key] = loading
    if (loading) state.errors[key] = ''
  }
  async function withRegionLoad(key, work, {renderStart=true, renderEnd=false} = {}){
    setRegionLoading(key, true)
    if (renderStart) render()
    try {
      const out = await work()
      state.errors[key] = ''
      return out
    } catch (e) {
      state.errors[key] = e.message || String(e)
      return null
    } finally {
      state.loading[key] = false
      if (renderEnd) render()
    }
  }
  function updateConnectionBanner(){
    const banner = qs('#offlineBanner')
    if (!banner) return
    const offline = state.connectionFetchFailed || navigator.onLine === false
    banner.hidden = !offline
  }
  function setConnectionFetchFailed(failed){
    state.connectionFetchFailed = failed
    updateConnectionBanner()
  }
  function clearConnectionIfHealthy(keys=[]){
    if (!keys.some(key=>state.errors[key])) setConnectionFetchFailed(false)
  }
  function toast(type, text){
    const host = qs('#toastHost')
    if (!host) return
    const kind = type === 'ok' ? 'ok' : (type === 'err' ? 'err' : 'info')
    const el = document.createElement('div')
    el.className = `toast ${kind}`
    el.textContent = text
    host.appendChild(el)
    window.setTimeout(()=>el.remove(), 3500)
  }
  function closeModal(value){
    const root = qs('#modalRoot')
    if (!root) return
    const done = root._resolve
    root.classList.remove('open')
    root.setAttribute('aria-hidden', 'true')
    root.innerHTML = ''
    root._resolve = null
    if (done) done(value)
  }
  function uiConfirm(title, body, danger=false){
    const root = qs('#modalRoot')
    if (!root) return Promise.resolve(false)
    root.innerHTML = `<div class="modalBackdrop" data-modal-cancel></div>
      <div class="modalCard" role="dialog" aria-modal="true" aria-label="${esc(title)}">
        <div class="h1">${esc(title)}</div>
        <div class="muted">${esc(body)}</div>
        <div class="modalActions">
          <button class="btn" type="button" data-modal-cancel>Cancel</button>
          <button class="btn ${danger ? 'danger' : 'primary'}" type="button" data-modal-ok>Continue</button>
        </div>
      </div>`
    root.classList.add('open')
    root.setAttribute('aria-hidden', 'false')
    return new Promise(resolve=>{
      root._resolve = resolve
      qsa('[data-modal-cancel]', root).forEach(el=>el.onclick=()=>closeModal(false))
      qs('[data-modal-ok]', root).onclick=()=>closeModal(true)
      qs('[data-modal-ok]', root).focus()
    })
  }
  function uiPrompt(title, body, initial=''){
    const root = qs('#modalRoot')
    if (!root) return Promise.resolve(null)
    root.innerHTML = `<div class="modalBackdrop" data-modal-cancel></div>
      <div class="modalCard" role="dialog" aria-modal="true" aria-label="${esc(title)}">
        <div class="h1">${esc(title)}</div>
        <div class="muted">${esc(body)}</div>
        <input id="modalPromptInput" value="${esc(initial)}">
        <div class="modalActions">
          <button class="btn" type="button" data-modal-cancel>Cancel</button>
          <button class="btn primary" type="button" data-modal-ok>Save</button>
        </div>
      </div>`
    root.classList.add('open')
    root.setAttribute('aria-hidden', 'false')
    return new Promise(resolve=>{
      root._resolve = resolve
      const input = qs('#modalPromptInput', root)
      qsa('[data-modal-cancel]', root).forEach(el=>el.onclick=()=>closeModal(null))
      qs('[data-modal-ok]', root).onclick=()=>closeModal(input.value)
      input.onkeydown = e => {
        if (e.key === 'Enter') closeModal(input.value)
        if (e.key === 'Escape') closeModal(null)
      }
      input.focus()
      input.select()
    })
  }
  function uiQuickAmount(){
    const root = qs('#modalRoot')
    if (!root) return Promise.resolve(null)
    root.innerHTML = `<div class="modalBackdrop" data-modal-cancel></div>
      <div class="modalCard" role="dialog" aria-modal="true" aria-label="Quick amount">
        <div class="h1">Quick amount</div>
        <div class="muted">Enter an amount for a custom sale line. Add a label if it helps the receipt.</div>
        <div class="field">
          <label>Amount</label>
          <input id="quickAmountInput" inputmode="decimal" placeholder="0.00">
        </div>
        <div class="field">
          <label>Label</label>
          <input id="quickLabelInput" placeholder="Quick sale">
        </div>
        <div class="modalActions">
          <button class="btn" type="button" data-modal-cancel>Cancel</button>
          <button class="btn primary" type="button" data-modal-ok>Add line</button>
        </div>
      </div>`
    root.classList.add('open')
    root.setAttribute('aria-hidden', 'false')
    return new Promise(resolve=>{
      root._resolve = resolve
      const amount = qs('#quickAmountInput', root)
      const label = qs('#quickLabelInput', root)
      const submit = () => closeModal({ amount: amount.value, label: label.value })
      qsa('[data-modal-cancel]', root).forEach(el=>el.onclick=()=>closeModal(null))
      qs('[data-modal-ok]', root).onclick=submit
      ;[amount, label].forEach(input=>input.onkeydown = e => {
        if (e.key === 'Enter') submit()
        if (e.key === 'Escape') closeModal(null)
      })
      amount.focus()
    })
  }
  function setAppSidebarCollapsed(collapsed){
    const shell = qs('#appShell')
    const toggle = qs('#navToggle')
    if (!shell) return
    shell.classList.toggle('navCollapsed', collapsed)
    if (toggle) {
      toggle.setAttribute('aria-pressed', collapsed ? 'true' : 'false')
      toggle.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar')
      toggle.title = collapsed ? 'Expand sidebar' : 'Collapse sidebar'
    }
    localStorage.setItem('neighbourposSidebarCollapsed', collapsed ? '1' : '0')
  }

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
    let res
    try {
      res = await fetch(url, opt)
    } catch (e) {
      const err = new Error("Connection lost - changes can't save")
      err.network = true
      setConnectionFetchFailed(true)
      throw err
    }
    const data = await res.json().catch(()=>({ok:false,error:'Bad JSON'}))
    if (!res.ok || data.ok === false) {
      const err = new Error(data.error || `HTTP ${res.status}`)
      err.status = res.status
      throw err
    }
    return data.data
  }

  function fmtMoney(cents){
    const sym = state.store?.currency_symbol || ''
    const value = (Number(cents || 0) / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    return `${sym}${value}`
  }
  function parseAppDate(iso){
    if (!iso) return null
    const text = String(iso)
    const normalized = text.includes('T') ? text : text.replace(' ', 'T')
    const withZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(normalized) ? normalized : normalized + 'Z'
    const date = new Date(withZone)
    return Number.isNaN(date.getTime()) ? null : date
  }
  function fmtDate(iso){
    const date = parseAppDate(iso)
    if (!date) return iso ? String(iso) : '-'
    const diff = Date.now() - date.getTime()
    const abs = Math.abs(diff)
    const future = diff < 0
    if (abs < 48 * 60 * 60 * 1000) {
      if (abs < 60 * 1000) return future ? 'in a moment' : 'just now'
      if (abs < 60 * 60 * 1000) {
        const mins = Math.max(1, Math.round(abs / (60 * 1000)))
        return future ? `in ${mins}m` : `${mins}m ago`
      }
      const hours = Math.max(1, Math.round(abs / (60 * 60 * 1000)))
      return future ? `in ${hours}h` : `${hours}h ago`
    }
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
  }
  function centsFromAmount(value){
    const n = Number(String(value || '').replace(/[^\d.]/g, ''))
    return Number.isFinite(n) ? Math.max(0, Math.round(n * 100)) : 0
  }
  function amountValue(cents){
    return cents ? (cents/100).toFixed(2) : ''
  }

  function badge(status){
    const cls = {
      'new':'b-new','preparing':'b-prep','ready_for_pickup':'b-ready','out_for_delivery':'b-out',
      'completed':'b-done','cancelled':'b-done'
    }[status] || 'b-new'
    return `<span class="statusBadge ${cls}">${esc(status)}</span>`
  }

  function dataTable(headers, bodyHtml, emptyHtml=''){
    if (!bodyHtml) return emptyHtml
    return `<div class="dataTableWrap">
      <table class="dataTable">
        <thead><tr>${headers.map(h=>`<th class="${esc(h.className || '')}">${esc(h.label || h)}</th>`).join('')}</tr></thead>
        <tbody>${bodyHtml}</tbody>
      </table>
    </div>`
  }

  async function setTab(tab){
    state.tab = tab
    qsa('.tab').forEach(b=>b.classList.toggle('active', b.dataset.tab===tab))
    window.location.hash = tab
    render()
    if (tab === 'dashboard') { await loadDashboard(); clearConnectionIfHealthy(['dashboard']) }
    if (tab === 'pos') { await Promise.all([loadProducts(state.pos.q || '', false), loadOrders('active'), loadLowStock()]); clearConnectionIfHealthy(['products','orders','lowStock']) }
    if (tab === 'inventory') { await Promise.all([loadProducts('', true), loadLowStock(), loadProductImports()]); clearConnectionIfHealthy(['products','lowStock','productImports']) }
    if (tab === 'orders') { await loadOrders('active'); clearConnectionIfHealthy(['orders']) }
    if (tab === 'crm') { await loadSegments(); clearConnectionIfHealthy(['segments']) }
    if (tab === 'campaigns') { await Promise.all([loadSegments(), loadCampaigns()]); clearConnectionIfHealthy(['segments','campaigns']) }
    if (tab === 'reports') { await loadSalesReport(); clearConnectionIfHealthy(['report']) }
    if (tab === 'admin') { await loadAuditLog(''); clearConnectionIfHealthy(['audit']) }
    render()
  }

  function newCartLineId(prefix='q'){
    return `${prefix}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2,8)}`
  }
  function cartLineId(it){
    if (!it.line_id) it.line_id = it.product_id ? `p:${it.product_id}` : newCartLineId('q')
    return it.line_id
  }
  function cartLineById(lineId){
    return state.cart.find(x=>cartLineId(x) === lineId)
  }
  function cartAdd(p){
    const productId = Number(p.id)
    const found = state.cart.find(x=>Number(x.product_id)===productId)
    if (found) found.qty += 1
    else state.cart.push({ line_id:`p:${productId}`, product_id:productId, name:p.name, price_cents:p.price_cents, qty:1, notes:'', category:p.category || '' })
    state.lastTouchedProductId = productId
    state.lastTouchedLineId = `p:${productId}`
    render()
  }
  async function addQuickSaleLine(){
    const quick = await uiQuickAmount()
    if (!quick) return
    const price = centsFromAmount(quick.amount)
    if (price <= 0) {
      toast('Enter an amount greater than zero.', 'error')
      return
    }
    const label = String(quick.label || '').trim() || 'Quick sale'
    const line = {
      line_id: newCartLineId('q'),
      product_id: null,
      name: label,
      price_cents: price,
      qty: 1,
      notes: '',
      category: '(quick sale)',
      quick_sale: true
    }
    state.cart.push(line)
    state.lastTouchedProductId = null
    state.lastTouchedLineId = line.line_id
    render()
  }
  function cartQty(lineId, delta){
    const it = cartLineById(lineId)
    if (!it) return
    it.qty = Math.max(1, it.qty + delta)
    state.lastTouchedProductId = it.product_id || null
    state.lastTouchedLineId = cartLineId(it)
    render()
  }
  function cartRemove(lineId){
    state.cart = state.cart.filter(x=>cartLineId(x)!==lineId)
    const last = state.cart.length ? state.cart[state.cart.length - 1] : null
    state.lastTouchedProductId = last ? (last.product_id || null) : null
    state.lastTouchedLineId = last ? cartLineId(last) : null
    render()
  }
  function adjustLastTouchedLine(delta){
    const it = cartLineById(state.lastTouchedLineId) || state.cart[state.cart.length - 1]
    if (!it) return
    cartQty(cartLineId(it), delta)
  }

  function cartTotals(){
    let subtotal = 0
    for (const it of state.cart) subtotal += it.price_cents * it.qty
    const taxRate = Number(state.store?.tax_rate ?? 0)
    const tax = Math.round(subtotal * taxRate)
    const tip = Math.max(0, parseInt(state.pos.tipCents || 0, 10) || 0)
    return { subtotal, tax, tip, total: subtotal + tax + tip }
  }

  async function loadMe(){
    const data = await api('api_me')
    state.me = data.user
    state.store = data.store
    document.documentElement.style.setProperty('--accent', state.store.accent)
  }

  async function loadDashboard(options={}){
    return withRegionLoad('dashboard', async ()=>{
      const to = new Date()
      const from = new Date()
      from.setDate(to.getDate() - 13)
      const params = { from: from.toISOString().slice(0,10), to: to.toISOString().slice(0,10) }
      const [snapshot, trend] = await Promise.all([
        api('api_today_snapshot'),
        api('api_sales_report', { params })
      ])
      state.dashboard = snapshot
      state.dashboardTrend = trend
    }, options)
  }

  async function loadProducts(q='', includeInactive=false, options={}){
    return withRegionLoad('products', async ()=>{
      const data = await api('api_products_list', { params: { q, page: 1, per: 30, include_inactive: includeInactive ? 1 : 0 }})
      state.products = data.items
    }, options)
  }

  async function loadLowStock(options={}){
    return withRegionLoad('lowStock', async ()=>{
      const data = await api('api_low_stock')
      state.lowStock = data.items
    }, options)
  }

  async function loadProductImports(options={}){
    if (state.me?.role !== 'admin') return
    return withRegionLoad('productImports', async ()=>{
      state.productImports = await api('api_product_imports_list')
    }, options)
  }

  async function loadOrders(status='active', options={}){
    return withRegionLoad('orders', async ()=>{
      state.orders = await api('api_orders_list', { params: { status, page: 1, per: 25 } })
    }, options)
  }

  async function loadSegments(options={}){
    return withRegionLoad('segments', async ()=>{
      state.segments = await api('api_segments_list')
    }, options)
  }

  async function loadCampaigns(options={}){
    return withRegionLoad('campaigns', async ()=>{
      state.campaigns = await api('api_campaigns_list')
    }, options)
  }

  async function loadSalesReport(options={}){
    const today = new Date().toISOString().slice(0,10)
    if (!state.reportTo) state.reportTo = today
    if (!state.reportFrom) {
      const d = new Date()
      d.setDate(d.getDate() - 6)
      state.reportFrom = d.toISOString().slice(0,10)
    }
    return withRegionLoad('report', async ()=>{
      state.report = await api('api_sales_report', { params: { from: state.reportFrom, to: state.reportTo }})
    }, options)
  }

  async function loadAuditLog(q='', options={}){
    if (state.me?.role !== 'admin') return
    return withRegionLoad('audit', async ()=>{
      state.auditLogs = await api('api_audit_log', { params: { q, limit: 50 }})
    }, options)
  }

  async function loadOrderSearch(options={}){
    const q = qs('#order_q')?.value || ''
    const status = qs('#order_status')?.value || 'all'
    const from = qs('#order_from')?.value || ''
    const to = qs('#order_to')?.value || ''
    return withRegionLoad('orderSearch', async ()=>{
      const data = await api('api_orders_search', { params: { q, status, from, to }})
      state.orderSearch = data.items
    }, options)
  }

  async function loadCustomerSearch(q='', options={}){
    return withRegionLoad('customerSearch', async ()=>{
      state.customerSearch = await api('api_customers_search', { params: { q, owes: state.customerOwesOnly ? 1 : 0 }})
    }, options)
  }

  async function loadCustomerProfile(id, options={}){
    state.lastCustomerId = id
    return withRegionLoad('customerProfile', async ()=>{
      state.selectedCustomer = await api('api_customer_get', { params: { id }})
      state.customerTimeline = await api('api_customer_timeline', { params: { id }})
    }, options)
  }

  function dashboardDelta(delta, type='count'){
    const n = Number(delta || 0)
    const cls = n > 0 ? 'up' : (n < 0 ? 'down' : '')
    const value = type === 'money' ? fmtMoney(Math.abs(n)) : Math.abs(n).toLocaleString()
    const label = n === 0 ? 'no change' : `${n > 0 ? '+' : '-'}${value}`
    return `<span class="kDelta ${cls}">${label} vs yesterday</span>`
  }

  function dashboardKpi(iconId, value, label, delta, deltaType='count'){
    return `<div class="k">
      <div class="kHead"><span class="kIcon">${icon(iconId)}</span>${dashboardDelta(delta, deltaType)}</div>
      <div class="v">${value}</div>
      <div class="l">${esc(label)}</div>
    </div>`
  }

  function sparklinePath(points, width=520, height=150, pad=12){
    const series = points.length ? points : [{ revenue_cents: 0 }, { revenue_cents: 0 }]
    const max = Math.max(0, ...series.map(p=>Number(p.revenue_cents || 0)))
    const step = (width - pad * 2) / Math.max(1, series.length - 1)
    const coords = series.map((p, i)=>{
      const x = pad + i * step
      const y = max > 0 ? (height - pad - (Number(p.revenue_cents || 0) / max) * (height - pad * 2)) : (height - pad)
      return [Number(x.toFixed(2)), Number(y.toFixed(2))]
    })
    const line = coords.map((p, i)=>`${i === 0 ? 'M' : 'L'} ${p[0]} ${p[1]}`).join(' ')
    const area = `M ${coords[0][0]} ${height - pad} ${coords.map(p=>`L ${p[0]} ${p[1]}`).join(' ')} L ${coords[coords.length - 1][0]} ${height - pad} Z`
    return { line, area, width, height, baseline: height - pad }
  }

  function salesTrendSparkline(report){
    const daily = report?.daily || []
    const path = sparklinePath(daily)
    const total = Number(report?.summary?.revenue_cents || 0)
    const first = daily[0]?.date || ''
    const last = daily[daily.length - 1]?.date || ''
    return `<div class="sparklineWrap">
      <div class="sparklineMeta"><span>14-day completed sales</span><strong>${fmtMoney(total)}</strong></div>
      <svg class="sparkline" viewBox="0 0 ${path.width} ${path.height}" role="img" aria-label="14-day sales sparkline">
        <path class="sparklineGrid" d="M 12 ${path.baseline} L ${path.width - 12} ${path.baseline}"></path>
        <path class="sparklineArea" d="${path.area}"></path>
        <path class="sparklineLine" d="${path.line}"></path>
      </svg>
      <div class="sparklineMeta"><span>${esc(first)}</span><span>${esc(last)}</span></div>
    </div>`
  }

  function campaignExportState(id){
    const key = String(id)
    if (!state.campaignExport[key]) state.campaignExport[key] = { format: 'mailchimp', bom: false, preview: null, loading: false, error: '' }
    return state.campaignExport[key]
  }

  function campaignExportHref(c){
    const ex = campaignExportState(c.id)
    const params = new URLSearchParams({ action: 'campaign_export', id: String(c.id), format: ex.format || 'mailchimp' })
    if (ex.bom) params.set('bom', '1')
    return `?${params.toString()}`
  }

  function exportReasonSummary(reasons){
    const labels = {
      missing_email: 'missing email',
      invalid_phone: 'invalid phone',
      missing_contact: 'missing email/phone',
      duplicate_email: 'duplicate email',
      duplicate_phone: 'duplicate phone',
      duplicate_contact: 'duplicate contact'
    }
    return Object.entries(reasons || {})
      .filter(([,v])=>Number(v || 0) > 0)
      .map(([k,v])=>`${labels[k] || k}: ${Number(v || 0).toLocaleString()}`)
      .join(' - ') || 'none'
  }

  function campaignExportPanel(c){
    const ex = campaignExportState(c.id)
    const summary = ex.preview
    return `
      <div class="exportPanel">
        <div class="row" style="align-items:flex-end">
          <div class="field">
            <label>Export format</label>
            <select data-export-format="${c.id}">
              <option value="mailchimp" ${ex.format === 'mailchimp' ? 'selected' : ''}>Mailchimp</option>
              <option value="brevo" ${ex.format === 'brevo' ? 'selected' : ''}>Brevo</option>
              <option value="sms" ${ex.format === 'sms' ? 'selected' : ''}>SMS</option>
              <option value="whatsapp" ${ex.format === 'whatsapp' ? 'selected' : ''}>WhatsApp</option>
              <option value="full" ${ex.format === 'full' ? 'selected' : ''}>Full archive</option>
            </select>
          </div>
          <label class="checkRow">
            <input type="checkbox" data-export-bom="${c.id}" ${ex.bom ? 'checked' : ''}>
            <span>Excel-friendly</span>
          </label>
          <button class="btn small" data-export-preview="${c.id}">${ex.loading ? 'Checking...' : 'Preview'}</button>
          <a class="btn small primary" href="${campaignExportHref(c)}">Download CSV</a>
        </div>
        <div class="meta">Works with: Mailchimp / Brevo / any SMS tool / WhatsApp manual</div>
        ${ex.error ? `<div class="errbox">${esc(ex.error)}</div>` : ``}
        ${summary ? `
          <div class="exportSummary">
            <span>Queued <b>${Number(summary.total_queued || 0).toLocaleString()}</b></span>
            <span>Opted-in <b>${Number(summary.opted_in || 0).toLocaleString()}</b></span>
            <span>Email <b>${Number(summary.with_email || 0).toLocaleString()}</b></span>
            <span>Valid phone <b>${Number(summary.with_valid_phone || 0).toLocaleString()}</b></span>
            <span>Export rows <b>${Number(summary.export_count || 0).toLocaleString()}</b></span>
            <span>Excluded: ${esc(exportReasonSummary(summary.excluded_and_why))}</span>
          </div>
        ` : ``}
      </div>
    `
  }

  function customerExportHref(){
    const ex = state.customerExport || {}
    const params = new URLSearchParams({ action: 'customer_export', format: ex.format || 'sms' })
    if (ex.segmentId) params.set('segment_id', String(ex.segmentId))
    else if ((ex.q || '').trim().length >= 2) params.set('q', (ex.q || '').trim())
    if (ex.bom) params.set('bom', '1')
    if (ex.override) params.set('override_opt_in', '1')
    return `?${params.toString()}`
  }

  function debtorReminderHref(){
    const params = new URLSearchParams({
      action: 'customer_export',
      format: 'sms',
      debtors: '1',
      message_template: 'Hi {first_name}, you owe {balance}. Please pay when convenient.'
    })
    return `?${params.toString()}`
  }

  function attentionItem(iconId, title, body, value, tone, goTab){
    return `<div class="attentionItem">
      <span class="attentionIcon ${esc(tone)}">${icon(iconId)}</span>
      <div><div class="name">${esc(title)}</div><div class="meta">${esc(body)}</div></div>
      <button class="btn small" data-go="${esc(goTab)}"><span class="attentionValue">${esc(value)}</span></button>
    </div>`
  }

  function renderDashboard(){
    const d = state.dashboard || {}
    const trend = state.dashboardTrend || {}
    const deltas = d.deltas || {}
    const dashboardStatus = regionState('dashboard', `<div class="card"><div class="h1">Loading dashboard</div>${skeletonKpis(4)}${skeletonList(2)}</div>`, 'Dashboard could not load', 'Try refreshing today snapshot.')
    if (dashboardStatus) {
      return `${pageHeader('Dashboard', 'Today at a glance across checkout, orders, stock, and campaign queues.', `<button class="btn primary" data-go="pos">New order</button>`)}${dashboardStatus}`
    }
    return `
      ${pageHeader('Dashboard', 'Today at a glance across checkout, orders, stock, and campaign queues.', `<button class="btn primary" data-go="pos">New order</button>`)}
      <div class="grid">
        <div class="card">
          <div class="h1">Today snapshot dashboard</div>
          <div class="muted">A tiny control room for sales, service, stock, and queued CRM work.</div>
          <div class="kpi">
            ${dashboardKpi('reports', fmtMoney(d.today_revenue_cents || 0), 'Today revenue', deltas.today_revenue_cents, 'money')}
            ${dashboardKpi('pos', fmtMoney(d.today_completed_revenue_cents || 0), 'Completed revenue', deltas.today_completed_revenue_cents, 'money')}
            ${dashboardKpi('orders', esc(d.today_order_count || 0), 'Today orders', deltas.today_order_count)}
            ${dashboardKpi('dashboard', esc(d.active_orders_count || 0), 'Active orders', deltas.active_orders_count)}
            ${dashboardKpi('crm', fmtMoney(d.outstanding_credit_cents || 0), 'Outstanding credit', 0, 'money')}
          </div>
          ${salesTrendSparkline(trend)}
          <div class="row" style="margin-top:12px;flex-wrap:wrap">
            <button class="btn small primary" data-go="pos">New order</button>
            <button class="btn small" data-go="orders">Orders</button>
            <button class="btn small" data-go="inventory">Inventory</button>
            <button class="btn small" data-go="reports">Reports</button>
          </div>
        </div>
        <div class="card">
          <div class="h1">Needs attention</div>
          <div class="muted">Current store work that may need a staff action.</div>
          <div class="attentionList">
            ${attentionItem('inventory', 'Low stock', 'Products at or below the alert threshold.', d.low_stock_count || 0, Number(d.low_stock_count || 0) ? 'warn' : 'good', 'inventory')}
            ${attentionItem('orders', 'Unpaid active orders', 'Open orders where payment is still pending.', d.unpaid_orders_count || 0, Number(d.unpaid_orders_count || 0) ? 'bad' : 'good', 'orders')}
            ${attentionItem('campaigns', 'Queued export work', 'Recipients waiting in campaign export queues.', d.queued_recipients_count || 0, Number(d.queued_recipients_count || 0) ? 'warn' : 'good', 'campaigns')}
          </div>
          <div class="list">
            <div class="item"><div class="name">CRM loop</div><div class="meta">Orders feed recency, spend, campaigns, coupon redemptions, and timeline events.</div></div>
            <div class="item"><div class="name">Shared hosting fit</div><div class="meta">No workers, no services, no build step. Exports are direct CSV downloads.</div></div>
          </div>
        </div>
      </div>
    `
  }

  function productInitials(name){
    return String(name || 'NP').split(/\s+/).filter(Boolean).map(w=>w[0]).join('').slice(0,2).toUpperCase()
  }

  function checkoutCategories(){
    return ['All', ...new Set(state.products.map(p=>p.category || 'Uncategorized'))]
  }

  function visibleCheckoutProducts(){
    return state.products.filter(p=>state.categoryFilter === 'All' || (p.category || 'Uncategorized') === state.categoryFilter)
  }

  async function addExactSkuFromSearch(value){
    const code = String(value || '').trim()
    if (!code) return false
    await loadProducts(code, false, {renderStart:false})
    const match = state.products.find(p=>String(p.sku || '').trim().toLowerCase() === code.toLowerCase())
    if (!match || Number(match.stock_qty) <= 0) {
      render()
      return false
    }
    state.pos.q = ''
    state.categoryFilter = 'All'
    cartAdd(match)
    return true
  }

  function customerSummaryHtml(){
    const found = state.attachedCustomer?.customer
    if (state.pos.walkin) {
      return `<div class="customerChip"><span class="avatar">WI</span><span class="chipMain"><strong>Walk-in</strong><span>Customer lookup skipped</span></span><span class="chipMeta">Anonymous</span></div>`
    }
    if (found) {
      return `<div class="customerChip">
        <span class="avatar">${esc(productInitials(found.name || found.phone))}</span>
        <span class="chipMain"><strong>${esc(found.name || found.phone)}</strong><span>${esc(found.phone)} / ${fmtMoney(found.total_spent_cents || 0)} / ${esc(found.order_count || 0)} orders</span></span>
        <span class="chipMeta">${found.marketing_opt_in ? 'Opt-in' : 'No opt-in'}</span>
      </div>`
    }
    if (state.customerLookupStatus === 'checking') {
      return `<div class="customerChip"><span class="avatar">${icon('user')}</span><span class="chipMain"><strong>Checking customer</strong><span>Looking up this phone number...</span></span><span class="chipMeta">Wait</span></div>`
    }
    if (state.customerLookupStatus === 'error') {
      return `<div class="errbox">Customer lookup failed. Check the connection and try again.</div>`
    }
    return `<div class="compactFields">
      <input id="pos_name" placeholder="${state.customerLookupStatus === 'new' ? 'New customer name' : 'Customer name'}" value="${esc(state.pos.name)}">
      <select id="pos_optin">
        <option value="0" ${state.pos.optIn === '1' ? '' : 'selected'}>No opt-in</option>
        <option value="1" ${state.pos.optIn === '1' ? 'selected' : ''}>Opt-in</option>
      </select>
    </div>`
  }

  function checkoutStatusHtml(){
    if (state.loading.orders || state.loading.lowStock) return `<span>Refreshing status...</span>`
    if (state.errors.orders || state.errors.lowStock) return `<span>Some status data could not load</span>`
    const active = state.orders.length
    const low = state.lowStock || []
    return [
      `<span>Active orders <b>${esc(active)}</b></span>`,
      `<span>Low stock <b>${esc(low.length)}</b></span>`,
      ...low.slice(0,3).map(p=>`<span>${esc(p.name)} (${esc(p.stock_qty)} left)</span>`)
    ].join('')
  }

  let customerLookupTimer = null
  async function lookupCustomerByPhone(phone){
    const value = String(phone || '').trim()
    state.pos.phone = value
    state.customerLookupError = ''
    state.attachedCustomer = null
    if (!value || state.pos.walkin) {
      state.customerLookupStatus = value ? 'walkin' : 'empty'
      render()
      return
    }
    state.customerLookupStatus = 'checking'
    render()
    try {
      state.attachedCustomer = await api('api_customer_get', { params: { phone: value }})
      state.customerLookupStatus = 'found'
      const c = state.attachedCustomer?.customer
      if (c) {
        state.pos.name = c.name || ''
        state.pos.address = c.address || ''
        state.pos.optIn = c.marketing_opt_in ? '1' : '0'
      }
    } catch (e) {
      state.attachedCustomer = null
      state.customerLookupStatus = e.network ? 'error' : 'new'
      state.customerLookupError = e.message || ''
    }
    render()
  }

  function renderPOS(){
    const enableDelivery = Number(state.store?.enable_delivery ?? 1) === 1
    const totals = cartTotals()
    const products = visibleCheckoutProducts()
    const count = state.cart.reduce((sum,it)=>sum+it.qty,0)
    const changeDue = Math.max(0, state.pos.amountTenderedCents - totals.total)
    const productGridStatus = regionState('products', Array.from({length:8},()=>'<div class="skeletonTile"></div>').join(''), 'Products could not load', 'Retry the product catalog.')

    return `
      ${pageHeader('Checkout', 'Search or scan items, attach a customer, tender payment, and place the order.', `<button class="btn primary" data-focus="#pos_q">Find item</button>`)}
      <div class="checkoutShell">
        <div class="stationPanel">
          <div class="saleToolbar">
            <input class="saleSearch" id="pos_q" placeholder="Search or scan" value="${esc(state.pos.q)}">
            <button class="iconBtn" type="button" aria-label="Scan barcode">${icon('barcode')}</button>
            <button class="iconBtn" type="button" aria-label="Keyboard shortcuts">${icon('keyboard')}</button>
          </div>

          <div class="categoryTabs" id="pos_category" aria-label="Product categories">
            ${checkoutCategories().map(cat=>`
              <button type="button" class="${state.categoryFilter === cat ? 'active' : ''}" data-poscat="${esc(cat)}">${esc(cat)}</button>
            `).join('')}
          </div>

          <div class="saleGrid" id="pos_products">
            <button class="item saleTile quickSaleTile" type="button" id="quick_amount_tile" data-quick-amount="1">
              <span class="productVisual">${icon('plus')}</span>
              <span class="productMeta">
                <span class="name">Quick amount</span>
                <span>Custom sale line</span>
                <span class="stockText">No product needed</span>
              </span>
            </button>
            ${productGridStatus || (products.length === 0 ? emptyState('search', 'No matching products', 'Try another search or add the first product in Inventory.', `<button class="btn small primary" data-go="inventory">Add product</button>`) : products.map(p=>`
              <button class="item saleTile" type="button" data-add="${p.id}" ${Number(p.stock_qty) <= 0 ? 'disabled' : ''}>
                <span class="productVisual">${esc(productInitials(p.name))}</span>
                <span class="productMeta">
                  <span class="name">${esc(p.name)}</span>
                  <span>${fmtMoney(p.price_cents)}</span>
                  <span class="stockText ${Number(p.stock_qty) <= Number(state.store?.low_stock_threshold ?? 5) ? 'low' : ''}">In stock ${esc(p.stock_qty)}</span>
                </span>
              </button>
            `).join(''))}
          </div>
          <div class="tinyStatus" id="tinyStatus">${checkoutStatusHtml()}</div>
        </div>

        <aside class="cartPanel" aria-label="Current checkout">
          <div class="cartTitle">
            <div class="h1">Cart</div>
            <span class="pill">${esc(count)} ${count === 1 ? 'item' : 'items'}</span>
          </div>

          <div class="customerLookup" id="customerLookup">
            <input id="pos_phone" placeholder="Enter phone number" value="${esc(state.pos.phone)}" ${state.pos.walkin ? 'disabled' : ''}>
            ${customerSummaryHtml()}
            <label class="muted"><input id="pos_walkin" type="checkbox" ${state.pos.walkin ? 'checked' : ''}> Walk-in anonymous</label>
          </div>

          <div class="list">
            ${state.cart.length === 0 ? emptyState('pos', 'Cart empty', 'Add items from the product grid to start a sale.') : state.cart.map(it=>`
              <div class="cartLine">
                <div><strong>${esc(it.name)}</strong><br><span class="muted">${fmtMoney(it.price_cents)} each</span>${it.notes ? `<span class="noteText">Note: ${esc(it.notes)}</span>` : ''}</div>
                <div class="lineControls">
                  <button class="btn small" data-qtyminus="${esc(cartLineId(it))}" aria-label="Decrease ${esc(it.name)} quantity">${icon('minus')}</button>
                  <span class="pill">${esc(it.qty)}</span>
                  <button class="btn small" data-qtyplus="${esc(cartLineId(it))}" aria-label="Increase ${esc(it.name)} quantity">${icon('plus')}</button>
                  <button class="btn small" data-note-prompt="${esc(cartLineId(it))}" aria-label="Add note for ${esc(it.name)}">${icon('note')}</button>
                  <button class="btn small danger" data-remove="${esc(cartLineId(it))}" aria-label="Remove ${esc(it.name)}">${icon('trash')}</button>
                </div>
              </div>
            `).join('')}
          </div>

          <div class="field couponRow">
            <label>Coupon code</label>
            <input id="pos_coupon" placeholder="Optional campaign coupon code" value="${esc(state.pos.coupon)}">
          </div>

          <div class="totals">
            <div class="totalRow"><span>Subtotal</span><span>${fmtMoney(totals.subtotal)}</span></div>
            <div class="totalRow"><span>Tax</span><span>${fmtMoney(totals.tax)}</span></div>
            <div class="totalRow"><span>Tip (cents)</span><input id="pos_tip" style="max-width:104px;text-align:right" type="number" min="0" value="${esc(state.pos.tipCents)}"></div>
            <div class="totalRow"><span>Total</span><strong>${fmtMoney(totals.total)}</strong></div>
          </div>

          <div class="segmented" id="pos_paymethod" aria-label="Payment method">
            ${[{id:'cash',label:'Cash'},{id:'card',label:'Card'},{id:'online',label:'Online'},{id:'credit',label:'On credit'}].map(method=>`
              <button type="button" class="${state.pos.payMethod === method.id ? 'active' : ''}" data-paymethod="${method.id}">${method.label}</button>
            `).join('')}
          </div>

          ${state.pos.payMethod === 'cash' ? `
            <div class="cashTender">
              <div>
                <label for="pos_amount_received">Cash received</label>
                <input id="pos_amount_received" type="number" min="0" step="0.01" inputmode="decimal" placeholder="0.00" value="${esc(amountValue(state.pos.amountTenderedCents))}">
              </div>
              <div class="changeDue">Change due<strong id="change_due">${fmtMoney(changeDue)}</strong></div>
            </div>
          ` : ``}

          <div class="paidRow">
            <span>${state.pos.payMethod === 'credit' ? 'Add to customer credit tab' : 'Mark payment received'}</span>
            <button type="button" class="switch ${state.pos.paid && state.pos.payMethod !== 'credit' ? 'on' : ''}" id="pos_paid" aria-label="Mark payment received" ${state.pos.payMethod === 'credit' ? 'disabled' : ''}><i></i></button>
          </div>

          <div class="tenderGrid">
            <select id="pos_type">
              <option value="pickup" ${state.pos.type === 'pickup' ? 'selected' : ''}>pickup</option>
              <option value="dine_in" ${state.pos.type === 'dine_in' ? 'selected' : ''}>dine-in</option>
              ${enableDelivery ? `<option value="delivery" ${state.pos.type === 'delivery' ? 'selected' : ''}>delivery</option>` : ``}
            </select>
            <input id="pos_eta" type="number" min="5" value="${esc(state.pos.eta)}">
          </div>

          <div class="field">
            <input id="pos_addr" placeholder="Address (optional)" value="${esc(state.pos.address)}">
          </div>

          <button class="btn primary" style="width:100%" id="pos_place" ${state.cart.length===0?'disabled':''}>Place order</button>

          <div class="warnbox">
            Compliance warning: only message customers who explicitly opted in. This app defaults marketing_opt_in=false and audits campaign runs.
          </div>
          <div id="pos_msg"></div>
        </aside>
      </div>
    `
  }

  function renderOrders(){
    const orderSearchStatus = regionState('orderSearch', skeletonList(3), 'Order search failed', 'Adjust the search or retry.')
    const ordersStatus = regionState('orders', skeletonList(4), 'Orders could not load', 'Retry active orders.')
    return `
      ${pageHeader('Orders', 'Search, open receipts, and move active orders through fulfillment.', `<button class="btn primary" data-go="pos">New order</button>`)}
      <div class="card">
        <div class="row" style="align-items:flex-start">
          <div>
            <div class="h1">Active Orders</div>
            <div class="muted">Fast status updates: new -> preparing -> ready/out -> completed/cancelled.</div>
          </div>
          <div style="flex:1 1 220px;display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">
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

        <div class="item" style="margin-top:10px">
          <div class="h1">Order search</div>
          <div class="row" style="align-items:flex-end;flex-wrap:wrap">
            <div class="field"><label>Code or phone</label><input id="order_q" placeholder="Order code or phone"></div>
            <div class="field"><label>Status</label><select id="order_status"><option value="all">all</option><option value="new">new</option><option value="preparing">preparing</option><option value="ready_for_pickup">ready</option><option value="out_for_delivery">out</option><option value="completed">completed</option><option value="cancelled">cancelled</option></select></div>
            <div class="field"><label>From</label><input id="order_from" type="date"></div>
            <div class="field"><label>To</label><input id="order_to" type="date"></div>
            <button class="btn small primary" id="order_search_btn">Search</button>
          </div>
          ${orderSearchStatus || dataTable(
            [{label:'Order'}, {label:'Customer'}, {label:'Total', className:'num'}, {label:'Created'}, {label:'Action', className:'actions'}],
            state.orderSearch.map(o=>`
              <tr>
                <td><div class="dataTitle">${esc(o.order_code)}</div><div class="dataMeta">${badge(o.status)} ${esc(o.order_type || '')}</div></td>
                <td>${esc(o.phone_text || '')}</td>
                <td class="num">${fmtMoney(o.total_cents)}</td>
                <td>${fmtDate(o.created_at)}</td>
                <td class="actions"><button class="btn small" data-open-order="${o.id}">Open</button></td>
              </tr>
            `).join(''),
            emptyState('search', 'Search recent orders', 'Use code, phone, status, or date filters to find an order.')
          )}
          ${state.selectedOrder ? `
            <div class="okbox">
              <b>${esc(state.selectedOrder.order_code)}</b> ${badge(state.selectedOrder.status)}<br>
              ${(state.selectedOrder.items || []).map(it=>`${esc(it.qty)} x ${esc(it.name)} ${it.notes ? '('+esc(it.notes)+')' : ''}`).join('<br>')}
            </div>
          ` : ``}
        </div>

        ${ordersStatus || dataTable(
          [{label:'Order'}, {label:'Type'}, {label:'Customer'}, {label:'Total', className:'num'}, {label:'Payment'}, {label:'Actions', className:'actions'}],
          state.orders.map(o=>`
            <tr>
              <td><div class="dataTitle">${esc(o.order_code)}</div><div class="dataMeta">${badge(o.status)} ${fmtDate(o.created_at)}</div></td>
              <td>${esc(o.order_type)}</td>
              <td>${esc(o.phone_text || '')}</td>
              <td class="num">${fmtMoney(o.total_cents)}</td>
              <td><div class="dataTitle">${esc(o.payment_method)}</div><div class="dataMeta">${o.payment_received ? 'received' : 'pending'}</div></td>
              <td class="actions">
                <a class="btn small ghost" target="_blank" href="?action=receipt&code=${encodeURIComponent(o.order_code)}">Receipt</a>
                <button class="btn small" data-st="${o.id}" data-next="preparing">Preparing</button>
                <button class="btn small" data-st="${o.id}" data-next="${o.order_type==='delivery'?'out_for_delivery':'ready_for_pickup'}">${o.order_type==='delivery'?'Out':'Ready'}</button>
                <button class="btn small primary" data-st="${o.id}" data-next="completed">Complete</button>
                <button class="btn small danger" data-st="${o.id}" data-next="cancelled">Cancel</button>
              </td>
            </tr>
          `).join(''),
          emptyState('orders', 'No active orders', 'New checkout orders will appear here for fulfillment.', `<button class="btn small primary" data-go="pos">Start checkout</button>`)
        )}
        <div id="orders_msg"></div>
      </div>
    `
  }

  function productImportPreviewHtml(){
    const preview = state.productImport.preview
    if (!preview) return `<div class="muted">Preview checks the first <?=PRODUCT_IMPORT_MAX_ROWS?> rows before anything is saved.</div>`
    const errors = preview.errors || []
    const rows = preview.rows || []
    return `
      <div class="exportSummary">
        <span>Total ${esc(preview.rows_total || 0)}</span>
        <span>Ready ${esc(preview.valid_count || 0)}</span>
        <span>Errors ${esc(errors.length)}</span>
      </div>
      ${errors.length ? `<div class="warnbox">${errors.map(e=>`Row ${esc(e.row)}: ${esc((e.errors || []).join(', '))}`).join('<br>')}</div>` : `<div class="okbox">All previewed rows look ready to import.</div>`}
      ${rows.length ? dataTable(
        [{label:'SKU'}, {label:'Name'}, {label:'Price', className:'num'}, {label:'Stock', className:'num'}, {label:'Category'}],
        rows.slice(0, 5).map(r=>`<tr><td>${esc(r.sku || '')}</td><td>${esc(r.name)}</td><td class="num">${fmtMoney(r.price_cents)}</td><td class="num">${esc(r.stock_qty)}</td><td>${esc(r.category || '')}</td></tr>`),
        ''
      ) : ''}
    `
  }

  function productImportLogHtml(){
    const importsStatus = regionState('productImports', skeletonList(3), 'Import history could not load', 'Retry product import history.')
    if (importsStatus) return importsStatus
    if (!state.productImports.length) return emptyState('inventory', 'No imports yet', 'Committed product CSV imports will appear here.')
    return state.productImports.map(row=>{
      const errors = row.errors || []
      return `<div class="item">
        <div class="row">
          <div><div class="name">${esc(row.filename)}</div><div class="meta">${esc(fmtDate(row.created_at))} - ${esc(row.rows_imported)} of ${esc(row.rows_total)} imported</div></div>
          <span class="statusBadge ${errors.length ? 'warn' : 'good'}">${esc(errors.length)} errors</span>
        </div>
        ${errors.length ? `<div class="noteText">${errors.slice(0, 3).map(e=>`Row ${esc(e.row)}: ${esc((e.errors || []).join(', '))}`).join('<br>')}</div>` : ''}
      </div>`
    }).join('')
  }

  function renderInventory(){
    const productsStatus = regionState('products', skeletonList(5), 'Products could not load', 'Retry the inventory catalog.')
    const lowStockStatus = regionState('lowStock', skeletonList(3), 'Low-stock list could not load', 'Retry low-stock alerts.')
    return `
      ${pageHeader('Inventory', 'Maintain products, stock counts, categories, and low-stock restock exports.', `<button class="btn primary" data-focus="#prod_name">Add product</button>`)}
      <div class="grid">
        <div class="card">
          <div class="h1">Inventory</div>
          <div class="muted">Search products (server-side) and adjust stock. Low-stock alert threshold: <b>${esc(state.me ? '<?=h((string)$CONFIG['LOW_STOCK_THRESHOLD'])?>' : '')}</b></div>

          <div class="field">
            <label>Search</label>
            <input id="inv_q" placeholder="Search inventory">
          </div>

          <div class="item">
            <div class="h1">Save product</div>
            <div class="row" style="flex-wrap:wrap">
              <input id="prod_id" type="hidden">
              <div class="field"><label>SKU</label><input id="prod_sku" placeholder="SKU"></div>
              <div class="field"><label>Name</label><input id="prod_name" placeholder="Product name"></div>
              <div class="field"><label>Price cents</label><input id="prod_price" type="number" min="0" value="0"></div>
            </div>
            <div class="row" style="flex-wrap:wrap">
              <div class="field"><label>Stock</label><input id="prod_stock" type="number" value="0"></div>
              <div class="field"><label>Category</label><input id="prod_cat" placeholder="Category"></div>
              <div class="field"><label>Active</label><select id="prod_active"><option value="1">active</option><option value="0">inactive</option></select></div>
            </div>
            <button class="btn small primary" id="prod_save">Save product</button>
            <button class="btn small ghost" id="prod_clear">Clear</button>
          </div>

          <div class="item">
            <div class="row" style="align-items:flex-start">
              <div>
                <div class="h1">Import CSV</div>
                <div class="muted">Columns: sku, name, price, stock, category. Price is entered in currency units.</div>
              </div>
              <a class="btn small ghost" href="?action=product_import_template">Template CSV</a>
            </div>
            <div class="row" style="flex-wrap:wrap">
              <div class="field"><label>File</label><input id="prod_import_file" type="file" accept=".csv,text/csv"></div>
              <div class="field"><label>Filename</label><input id="prod_import_filename" value="${esc(state.productImport.filename)}"></div>
            </div>
            <div class="field">
              <label>CSV content</label>
              <textarea id="prod_import_csv" rows="6" placeholder="sku,name,price,stock,category">${esc(state.productImport.csv)}</textarea>
            </div>
            <div class="row">
              <button class="btn small" id="prod_import_preview" ${state.productImport.busy ? 'disabled' : ''}>Preview import</button>
              <button class="btn small primary" id="prod_import_commit" ${(!state.productImport.preview || state.productImport.busy) ? 'disabled' : ''}>Import valid rows</button>
            </div>
            <div id="prod_import_result">${productImportPreviewHtml()}</div>
          </div>

          ${productsStatus || dataTable(
            [{label:'Product'}, {label:'Category'}, {label:'Price', className:'num'}, {label:'Stock', className:'num'}, {label:'Actions', className:'actions'}],
            state.products.map(p=>`
              <tr>
                <td><div class="dataTitle">${esc(p.name)}</div><div class="dataMeta">SKU ${esc(p.sku || '')} - ID ${esc(p.id)}</div></td>
                <td>${esc(p.category || 'Uncategorized')}</td>
                <td class="num">${fmtMoney(p.price_cents)}</td>
                <td class="num"><input data-stock="${p.id}" type="number" value="${esc(p.stock_qty)}" style="width:84px;text-align:right"></td>
                <td class="actions"><button class="btn small" data-saveprod="${p.id}">Save</button> <button class="btn small ghost" data-editprod="${p.id}">Edit</button></td>
              </tr>
            `).join(''),
            emptyState('inventory', 'No products yet', 'Add your first product or load sample data from Admin.', `<button class="btn small primary" data-focus="#prod_name">Add product</button>`)
          )}

          <div id="inv_msg"></div>
        </div>

        <div class="card">
          <div class="h1">Low-stock alerts</div>
          <div class="muted">Export lists to CSV for restocking workflows.</div>

          <button class="btn small" id="low_refresh">Refresh</button>
          <a class="btn small ghost" href="?action=inventory_low_stock_export">Export low-stock CSV</a>
          <div class="h1" style="margin-top:14px">Recent imports</div>
          <div class="list">${productImportLogHtml()}</div>
          <div class="list">
            ${lowStockStatus || (state.lowStock.length===0 ? emptyState('alert', 'Stock looks healthy', 'Products under the low-stock threshold will appear here.') : state.lowStock.map(p=>`
              <div class="item">
                <div class="name">${esc(p.name)}</div>
                <div class="meta">${esc(p.category || '')}  -  Stock: <b>${esc(p.stock_qty)}</b></div>
              </div>
            `).join(''))}
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
    const ltvCents = Math.round(Number(cust?.ltv_estimate || 0) * 100)
    const customerSearchStatus = regionState('customerSearch', skeletonList(4), 'Customer search failed', 'Retry the customer search.')
    const profileStatus = regionState('customerProfile', skeletonList(5), 'Customer profile could not load', 'Retry the customer profile.')
    return `
      ${pageHeader('CRM', 'Find customers by phone, maintain consent, and review purchase history.', `<button class="btn primary" data-focus="#crm_q">Find customer</button>`)}
      <div class="grid">
        <div class="card">
          <div class="h1">Customers (CRM)</div>
          <div class="muted">Primary identifier is phone. Keep profiles minimal: phone + optional name/address + opt-in.</div>

          <div class="field">
            <label>Search by phone/name/email</label>
            <input id="crm_q" placeholder="e.g., +1415..., Maya, vip">
          </div>
          <label class="checkRow" style="margin:8px 0 12px">
            <input type="checkbox" id="crm_owes" ${state.customerOwesOnly ? 'checked' : ''}>
            <span>Owes money</span>
          </label>

          <div class="exportPanel">
            <div class="h1">Export customers</div>
            <div class="meta">Download the opted-in phone book or a saved segment using the same provider-ready formats as campaigns. <a href="EXPORTS.md" target="_blank" rel="noopener">Export guide</a></div>
            <div class="row" style="align-items:flex-end">
              <div class="field">
                <label>Segment</label>
                <select id="crm_export_segment">
                  <option value="">All opted-in customers</option>
                  ${state.loading.segments ? `<option value="" disabled>Loading segments...</option>` : state.segments.map(s=>`<option value="${s.id}" ${String(state.customerExport.segmentId || '') === String(s.id) ? 'selected' : ''}>#${s.id} ${esc(s.name)}</option>`).join('')}
                </select>
              </div>
              <div class="field">
                <label>Format</label>
                <select id="crm_export_format">
                  <option value="sms" ${state.customerExport.format === 'sms' ? 'selected' : ''}>SMS</option>
                  <option value="whatsapp" ${state.customerExport.format === 'whatsapp' ? 'selected' : ''}>WhatsApp</option>
                  <option value="mailchimp" ${state.customerExport.format === 'mailchimp' ? 'selected' : ''}>Mailchimp</option>
                  <option value="brevo" ${state.customerExport.format === 'brevo' ? 'selected' : ''}>Brevo</option>
                  <option value="full" ${state.customerExport.format === 'full' ? 'selected' : ''}>Full archive</option>
                </select>
              </div>
              <label class="checkRow">
                <input type="checkbox" id="crm_export_bom" ${state.customerExport.bom ? 'checked' : ''}>
                <span>Excel-friendly</span>
              </label>
              <label class="checkRow">
                <input type="checkbox" id="crm_export_override" ${state.customerExport.override ? 'checked' : ''}>
                <span>Include non-opted-in (audited)</span>
              </label>
              <a class="btn small primary" href="${customerExportHref()}">Download customers</a>
              <a class="btn small" href="${debtorReminderHref()}">Debtor reminders</a>
            </div>
          </div>

          ${customerSearchStatus || dataTable(
            [{label:'Customer'}, {label:'Phone'}, {label:'Orders', className:'num'}, {label:'Spent', className:'num'}, {label:'Balance', className:'num'}, {label:'Consent'}, {label:'Action', className:'actions'}],
            state.customerSearch.map(c=>`
              <tr>
                <td><div class="dataTitle">${esc(c.name || c.phone)}</div><div class="dataMeta">${esc((c.tags_text||'').replaceAll(',',' ').trim())}</div></td>
                <td>${esc(c.phone)}</td>
                <td class="num">${esc(c.order_count)}</td>
                <td class="num">${fmtMoney(c.total_spent_cents)}</td>
                <td class="num">${Number(c.balance_cents || 0) > 0 ? `<span class="statusBadge b-prep">${fmtMoney(c.balance_cents)}</span>` : fmtMoney(0)}</td>
                <td>${c.marketing_opt_in ? '<span class="statusBadge b-ready">Yes</span>' : '<span class="statusBadge b-done">No</span>'}</td>
                <td class="actions"><button class="btn small" data-open="${c.id}">Open</button></td>
              </tr>
            `).join(''),
            emptyState('user', 'Search customers', 'Type at least two characters to find customers by phone, name, email, or tag.')
          )}
          <div id="crm_msg"></div>
        </div>

        <div class="card">
          <div class="h1">Profile</div>
          ${profileStatus || (!cust ? emptyState('user', 'No customer selected', 'Open a customer to view details, consent, order history, and timeline.') : `
            <div class="kpi">
              <div class="k"><div class="v">${fmtMoney(cust.total_spent_cents)}</div><div class="l">Total spent</div></div>
              <div class="k"><div class="v">${fmtMoney(cust.balance_cents || 0)}</div><div class="l">Balance</div></div>
              <div class="k"><div class="v">${esc(cust.order_count)}</div><div class="l">Orders</div></div>
              <div class="k"><div class="v">${fmtDate(cust.last_order_at)}</div><div class="l">Last order</div></div>
              <div class="k"><div class="v">${fmtMoney(ltvCents)}</div><div class="l">LTV estimate</div></div>
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
              Consent: store should keep proof (timestamp + source). This app stores opt-in timestamp when toggled from No->Yes.
            </div>

            <div class="item" style="margin-top:12px">
              <div class="h1">Credit ledger</div>
              <div class="muted">Running balance for on-credit sales and customer payments.</div>
              <div class="row" style="align-items:flex-end;flex-wrap:wrap">
                <div class="field"><label>Payment amount</label><input id="ledger_payment_amount" type="number" min="0" step="0.01" inputmode="decimal" placeholder="0.00"></div>
                <div class="field"><label>Note</label><input id="ledger_payment_note" placeholder="cash payment"></div>
                <button class="btn small primary" id="ledger_pay">Record payment</button>
              </div>
              <div class="list tight">
                ${((state.selectedCustomer?.ledger_entries)||[]).length===0 ? '<div class="empty">No ledger entries yet.</div>' : (state.selectedCustomer.ledger_entries||[]).map(le=>`
                  <div class="item">
                    <div class="name">${le.type === 'payment' ? 'Payment' : 'Credit'} ${fmtMoney(le.amount_cents)}</div>
                    <div class="meta">${fmtDate(le.created_at)} ${le.order_code ? ' - '+esc(le.order_code) : ''} ${le.note ? ' - '+esc(le.note) : ''}</div>
                  </div>
                `).join('')}
              </div>
            </div>

            <div style="margin-top:12px">
              <div class="h1">Recent orders</div>
              ${dataTable(
                [{label:'Order'}, {label:'Type'}, {label:'Total', className:'num'}, {label:'Created'}, {label:'Action', className:'actions'}],
                orders.map(o=>`
                  <tr>
                    <td><div class="dataTitle">${esc(o.order_code)}</div><div class="dataMeta">${badge(o.status)}</div></td>
                    <td>${esc(o.order_type)}</td>
                    <td class="num">${fmtMoney(o.total_cents)}</td>
                    <td>${fmtDate(o.created_at)}</td>
                    <td class="actions"><a class="btn small ghost" target="_blank" href="?action=receipt&code=${encodeURIComponent(o.order_code)}">Receipt</a></td>
                  </tr>
                `).join(''),
                emptyState('orders', 'No orders yet', 'This customer has not placed an order yet.')
              )}
            </div>
          `)}
          ${!profileStatus && cust ? `
            <div style="margin-top:12px">
              <div class="h1">Timeline</div>
              <div class="list">
                ${state.customerTimeline.length===0 ? emptyState('reports', 'No timeline events yet', 'Orders, campaigns, and consent changes will appear here.') : state.customerTimeline.map(ev=>`
                  <div class="item">
                    <div class="name">${esc(ev.type)}  -  ${esc(ev.label)}</div>
                    <div class="meta">${fmtDate(ev.ts)} ${ev.amount_cents ? ' -  '+fmtMoney(ev.amount_cents) : ''} ${ev.meta ? ' -  '+esc(ev.meta) : ''}</div>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ``}
          <div id="cust_msg"></div>
        </div>
      </div>
    `
  }

  function renderCampaigns(){
    const segmentsStatus = regionState('segments', skeletonList(3), 'Segments could not load', 'Retry saved segments.')
    const campaignsStatus = regionState('campaigns', skeletonList(4), 'Campaigns could not load', 'Retry campaign history.')
    return `
      ${pageHeader('Campaigns', 'Build opted-in segments, queue campaigns, and export sending lists.', `<button class="btn primary" data-focus="#seg_name">New segment</button>`)}
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
          <label class="checkRow" style="margin:8px 0 12px">
            <input type="checkbox" id="seg_has_balance">
            <span>Has outstanding balance</span>
          </label>

          <button class="btn small primary" id="seg_create">Save segment</button>
          <button class="btn small" id="seg_preview">Preview</button>

          <div id="seg_msg"></div>

          <div class="list">
            ${segmentsStatus || (state.segments.length===0 ? emptyState('crm', 'No segments yet', 'Create a saved filter for customers you want to reach later.', `<button class="btn small primary" data-focus="#seg_name">Create segment</button>`) : state.segments.map(s=>`
              <div class="item">
                <div class="row" style="align-items:flex-start;flex-wrap:wrap">
                  <div style="flex:1">
                    <div class="name">#${s.id} ${esc(s.name)} <span class="pill">${Number(s.count || 0).toLocaleString()} customers</span></div>
                    <div class="meta">${esc(s.filters_json)}</div>
                  </div>
                  <div style="flex:0 0 auto;display:flex;gap:6px;flex-wrap:wrap">
                    <button class="btn small" data-use-seg="${s.id}">Use</button>
                    <button class="btn small" data-dup-seg="${s.id}">Duplicate</button>
                  </div>
                </div>
              </div>
            `).join(''))}
          </div>
        </div>

        <div class="card">
          <div class="h1">Campaign builder</div>
          <div class="item">
            <div class="h1">Campaign presets</div>
            <div class="muted">One click creates a reusable segment and draft export campaign.</div>
            <div class="row" style="flex-wrap:wrap;margin-top:8px">
              <button class="btn small primary" data-preset="reward_top_spenders">Reward top spenders</button>
              <button class="btn small primary" data-preset="win_back_lapsed">Win back lapsed</button>
              <button class="btn small" data-preset="winback">Winback draft</button>
              <button class="btn small" data-preset="vip">VIP draft</button>
              <button class="btn small" data-preset="new_customers">New customers</button>
              <button class="btn small" data-preset="product_fans">Product fans</button>
            </div>
          </div>
          <div class="muted">Choose a segment -> write message -> export list or (optionally) send via SMS/Email provider.</div>

          <div class="field">
            <label>Segment</label>
            <select id="camp_seg">
              <option value="">Select segment</option>
              ${state.loading.segments ? `<option value="" disabled>Loading segments...</option>` : state.segments.map(s=>`<option value="${s.id}">#${s.id} ${esc(s.name)}</option>`).join('')}
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
              Est revenue: <b>${fmtMoney(state.sim.expected_revenue_cents)}</b><br>
              AOV est: <b>${fmtMoney(state.sim.avg_order_value_cents_est)}</b>
              ${(state.sim.preview_messages||[]).length ? `
                <div class="dataMeta" style="margin-top:8px">Preview messages</div>
                <div class="list tight">
                  ${(state.sim.preview_messages||[]).map(p=>`
                    <div class="item">
                      <div class="name">${esc(p.name || p.phone || 'Customer')}</div>
                      <div class="meta">${esc(p.message || '')}</div>
                    </div>
                  `).join('')}
                </div>
              ` : ``}
            </div>
          ` : ``}

          <div class="warnbox">
            SMS costs and compliance are on you. By default, campaigns target only opted-in customers unless "override" is used (audited). <a href="EXPORTS.md" target="_blank" rel="noopener">Export guide</a>
          </div>

          <div id="camp_msgbox"></div>

          <div style="margin-top:12px">
            <div class="h1">Past campaigns</div>
            <div class="list">
              ${campaignsStatus || (state.campaigns.length===0 ? emptyState('campaigns', 'No campaigns yet', 'Create a campaign from a segment, then queue recipients for export.', `<button class="btn small primary" data-focus="#camp_msg">Write campaign</button>`) : state.campaigns.map(c=>`
                <div class="item ${Number(state.focus_campaign_id || 0) === Number(c.id) ? 'focusedItem' : ''}">
                  <div class="row" style="align-items:flex-start">
                    <div style="flex:1">
                      <div class="name" style="display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap">
                        <span>#${c.id} ${esc(c.name)}</span>
                        ${Number(c.sent_count || 0) > 0 ? `<span class="pill">Ready to export</span>` : `<button class="btn small ghost" disabled>Queue first</button>`}
                      </div>
                      <div class="meta">Segment: ${esc(c.segment_name || ('#'+c.segment_id))}  -  Channel: ${esc(c.channel)}  -  Sent/queued: ${esc(c.sent_count)}</div>
                      <div class="meta">Scheduled: ${fmtDate(c.scheduled_at)}  -  Created: ${fmtDate(c.created_at)}</div>
                      ${Number(c.sent_count || 0) > 0 ? campaignExportPanel(c) : ``}
                    </div>
                  </div>
                </div>
              `).join(''))}
            </div>
          </div>
        </div>
      </div>
    `
  }

  function closePaymentRows(close){
    const methods = close?.payment_methods || {}
    const labels = [
      ['cash', 'Cash'],
      ['card', 'Card'],
      ['mobile', 'Mobile/online'],
      ['credit', 'On credit']
    ]
    return labels.map(([key,label])=>{
      const row = methods[key] || { order_count: 0, gross_cents: 0 }
      return `<div class="closeRow"><div><strong>${esc(label)}</strong><br><span>${esc(row.order_count || 0)} orders</span></div><strong>${fmtMoney(row.gross_cents || 0)}</strong></div>`
    }).join('')
  }

  function renderCloseCard(close){
    const from = close?.from || state.reportFrom || ''
    const to = close?.to || state.reportTo || ''
    const range = from === to ? from : `${from} - ${to}`
    return `
      <div class="card closeCard" id="today_close_card">
        <div class="closeHead">
          <div>
            <div class="h1">Today's close</div>
            <div class="muted">${esc(range)} / completed orders</div>
          </div>
          <button class="btn small ghost noPrint" type="button" id="close_print">Print close</button>
        </div>
        <div class="closeMetrics">
          <div class="closeMetric"><strong>${fmtMoney(close?.gross_cents || 0)}</strong><span>Gross</span></div>
          <div class="closeMetric"><strong>${esc(close?.order_count || 0)}</strong><span>Orders</span></div>
          <div class="closeMetric"><strong>${esc(close?.coupons_redeemed || 0)}</strong><span>Coupons redeemed</span></div>
          <div class="closeMetric"><strong>${esc(close?.new_customers || 0)}</strong><span>New customers</span></div>
        </div>
        <div class="closeRows">${closePaymentRows(close)}</div>
      </div>
    `
  }

  function renderReports(){
    const r = state.report || { summary:{}, top_products:[], category_mix:[] }
    const exportHref = `?action=sales_report_export&from=${encodeURIComponent(state.reportFrom || '')}&to=${encodeURIComponent(state.reportTo || '')}`
    const reportListStatus = regionState('report', skeletonList(3), 'Report could not load', 'Retry this report window.')
    return `
      ${pageHeader('Reports', 'Review completed-order revenue and export owner-friendly CSV reports.', `<a class="btn primary" href="${exportHref}">Export CSV</a>`)}
      <div class="grid">
        ${renderCloseCard(r.today_close || {})}
        <div class="card">
          <div class="h1">Sales reports</div>
          <div class="muted">Completed-order revenue by date, category, and product.</div>
          <div class="row" style="align-items:flex-end">
            <div class="field"><label>From</label><input id="rep_from" type="date" value="${esc(state.reportFrom)}"></div>
            <div class="field"><label>To</label><input id="rep_to" type="date" value="${esc(state.reportTo)}"></div>
            <button class="btn small primary" id="rep_refresh">Refresh</button>
            <a class="btn small ghost" href="${exportHref}">Export report CSV</a>
          </div>
          <div class="kpi">
            ${state.loading.report ? Array.from({length:4},()=>'<div class="skeletonKpi"></div>').join('') : (state.errors.report ? retryState('report', 'Report could not load', state.errors.report) : `
            <div class="k"><div class="v">${fmtMoney(r.summary?.revenue_cents || 0)}</div><div class="l">Revenue</div></div>
            <div class="k"><div class="v">${esc(r.summary?.order_count || 0)}</div><div class="l">Completed orders</div></div>
            <div class="k"><div class="v">${fmtMoney(r.summary?.aov_cents || 0)}</div><div class="l">AOV</div></div>
            <div class="k"><div class="v">${esc(state.reportFrom || '')} - ${esc(state.reportTo || '')}</div><div class="l">Window</div></div>
            `)}
          </div>
        </div>
        <div class="card">
          <div class="h1">Top products</div>
          <div class="list">
            ${reportListStatus || ((r.top_products || []).length===0 ? emptyState('reports', 'No completed sales', 'Completed orders in the selected window will appear here.') : r.top_products.map(p=>`
              <div class="item"><div class="name">${esc(p.product_name)}</div><div class="meta">${esc(p.category)}  -  Qty ${esc(p.qty)}  -  ${fmtMoney(p.revenue_cents)}</div></div>
            `).join(''))}
          </div>
          <div class="h1" style="margin-top:12px">Category mix</div>
          <div class="list">
            ${reportListStatus || ((r.category_mix || []).length===0 ? emptyState('reports', 'No category mix yet', 'Category totals appear after completed sales in this report window.') : (r.category_mix || []).map(c=>`<div class="item"><div class="name">${esc(c.category)}</div><div class="meta">Qty ${esc(c.qty)} - ${fmtMoney(c.revenue_cents)}</div></div>`).join(''))}
          </div>
        </div>
      </div>
    `
  }

  function renderAdmin(){
    const isAdmin = state.me?.role === 'admin'
    const auditStatus = isAdmin ? regionState('audit', skeletonList(5), 'Audit log could not load', 'Retry audit history.') : ''
    return `
      ${pageHeader('Admin', 'Change passwords, download backups, and inspect audited staff actions.', isAdmin ? `<a class="btn primary" href="?action=database_backup">Download backup</a>` : `<button class="btn primary" data-focus="#pw_current">Change password</button>`)}
      <div class="grid">
        <div class="card">
          <div class="h1">Change password</div>
          <div class="field"><label>Current password</label><input id="pw_current" type="password"></div>
          <div class="field"><label>New password</label><input id="pw_new" type="password"></div>
          <button class="btn small primary" id="pw_change">Change password</button>
          <div id="admin_msg"></div>
          ${isAdmin ? `
            <div class="item" style="margin-top:12px">
              <div class="h1">Store settings</div>
              <div class="row" style="flex-wrap:wrap">
                <div class="field"><label>Store name</label><input id="store_name" value="${esc(state.store?.name || '')}"></div>
                <div class="field"><label>Currency symbol</label><input id="store_symbol" maxlength="4" value="${esc(state.store?.currency_symbol || '')}"></div>
                <div class="field"><label>Default country code</label><input id="store_country_code" value="${esc(state.store?.default_country_code || '+1')}" placeholder="+1"></div>
              </div>
              <div class="row" style="flex-wrap:wrap">
                <div class="field"><label>Tax rate</label><input id="store_tax" type="number" min="0" step="0.001" value="${esc(state.store?.tax_rate ?? 0)}"></div>
                <div class="field"><label>Accent</label><input id="store_accent" value="${esc(state.store?.accent || '#2563eb')}"></div>
                <div class="field"><label>Delivery</label><select id="store_delivery"><option value="1" ${Number(state.store?.enable_delivery ?? 1) === 1 ? 'selected' : ''}>enabled</option><option value="0" ${Number(state.store?.enable_delivery ?? 1) === 1 ? '' : 'selected'}>disabled</option></select></div>
              </div>
              <button class="btn small primary" id="store_save">Save store settings</button>
            </div>
          ` : ``}
          ${isAdmin ? `
            <div class="item" style="margin-top:12px">
              <div class="h1">Admin reset</div>
              <div class="field"><label>User email</label><input id="reset_email" type="email"></div>
              <div class="field"><label>New password</label><input id="reset_pw" type="password"></div>
              <button class="btn small danger" id="pw_reset">Reset password</button>
            </div>
            <div class="item" style="margin-top:12px">
              <div class="h1">Download database backup</div>
              <div class="muted">Contains customer, order, campaign, and audit data. Store it carefully.</div>
              <a class="btn small ghost" href="?action=database_backup">Download database backup</a>
            </div>
          ` : `<div class="warnbox">Admin-only tools are hidden for staff accounts.</div>`}
        </div>
        <div class="card">
          <div class="h1">Audit log</div>
          ${isAdmin ? `
            <div class="field"><label>Filter</label><input id="audit_q" placeholder="action, email, payload"></div>
            <button class="btn small" id="audit_refresh">Refresh</button>
            ${auditStatus || dataTable(
              [{label:'Action'}, {label:'User'}, {label:'Time'}, {label:'Payload'}],
              state.auditLogs.map(a=>`
                <tr>
                  <td><div class="dataTitle">${esc(a.action)}</div></td>
                  <td>${esc(a.user_email || 'system')}</td>
                  <td>${fmtDate(a.ts)}</td>
                  <td><div class="dataMeta">${esc(a.payload_json || '')}</div></td>
                </tr>
              `).join(''),
              emptyState('admin', 'No audit rows loaded', 'Refresh or adjust the filter to inspect recent audited actions.')
            )}
          ` : emptyState('admin', 'Audit log is admin only', 'Sign in as an admin to review audit history.')}
        </div>
      </div>
    `
  }

  function render(){
    if (state.tab === 'dashboard') $view.innerHTML = renderDashboard()
    if (state.tab === 'pos') $view.innerHTML = renderPOS()
    if (state.tab === 'orders') $view.innerHTML = renderOrders()
    if (state.tab === 'inventory') $view.innerHTML = renderInventory()
    if (state.tab === 'crm') $view.innerHTML = renderCRM()
    if (state.tab === 'campaigns') $view.innerHTML = renderCampaigns()
    if (state.tab === 'reports') $view.innerHTML = renderReports()
    if (state.tab === 'admin') $view.innerHTML = renderAdmin()
    bind()
  }

  function msg(elId, type, text){
    const el = qs('#'+elId)
    if (!el) return
    const cls = type==='ok' ? 'okbox' : (type==='err' ? 'errbox' : 'warnbox')
    el.innerHTML = `<div class="${cls}">${esc(text)}</div>`
    toast(type, text)
  }

  async function retryRegion(key){
    if (key === 'dashboard') await loadDashboard()
    if (key === 'products') await loadProducts(state.tab === 'inventory' ? (qs('#inv_q')?.value || '') : (state.pos.q || ''), state.tab === 'inventory')
    if (key === 'lowStock') await loadLowStock()
    if (key === 'orders') await loadOrders(qs('#orders_filter')?.value || 'active')
    if (key === 'orderSearch') await loadOrderSearch()
    if (key === 'customerSearch') await loadCustomerSearch(qs('#crm_q')?.value?.trim() || '')
    if (key === 'customerProfile' && state.lastCustomerId) await loadCustomerProfile(state.lastCustomerId)
    if (key === 'segments') await loadSegments()
    if (key === 'campaigns') await loadCampaigns()
    if (key === 'report') await loadSalesReport()
    if (key === 'audit') await loadAuditLog(qs('#audit_q')?.value || '')
    clearConnectionIfHealthy([key])
    render()
  }

  function setupConnectionWatch(){
    updateConnectionBanner()
    window.addEventListener('online', updateConnectionBanner)
    window.addEventListener('offline', updateConnectionBanner)
    window.setInterval(updateConnectionBanner, 5000)
  }

  let keyboardShortcutsReady = false
  function isTypingTarget(el){
    if (!el) return false
    return ['INPUT','TEXTAREA','SELECT'].includes(el.tagName) || el.isContentEditable
  }
  function setupKeyboardShortcuts(){
    if (keyboardShortcutsReady) return
    keyboardShortcutsReady = true
    document.addEventListener('keydown', e=>{
      if (state.tab !== 'pos') return
      const typing = isTypingTarget(e.target)
      if (!typing && e.key === '/') {
        e.preventDefault()
        qs('#pos_q')?.focus()
        return
      }
      if (!typing && e.key === 'F2') {
        e.preventDefault()
        placeCurrentOrder()
        return
      }
      if (!typing && e.key === '+') {
        e.preventDefault()
        adjustLastTouchedLine(1)
        return
      }
      if (!typing && e.key === '-') {
        e.preventDefault()
        adjustLastTouchedLine(-1)
      }
    })
  }

  async function placeCurrentOrder(){
    if (!state.cart.length) return
    try{
      const walkin = state.pos.walkin ? 1 : 0
      const payload = {
        items: state.cart.map(it=>({
          product_id: it.product_id ?? null,
          name: it.name || 'Quick sale',
          price_cents: it.price_cents || 0,
          category: it.category || (it.product_id ? '' : '(quick sale)'),
          qty: it.qty,
          notes: it.notes
        })),
        order_type: state.pos.type || 'pickup',
        expected_eta_minutes: parseInt(state.pos.eta||'15',10)||15,
        tip_cents: parseInt(state.pos.tipCents||'0',10)||0,
        coupon_code: state.pos.coupon || '',
        payment_method: state.pos.payMethod || 'cash',
        payment_received: state.pos.payMethod === 'credit' ? 0 : (state.pos.paid ? 1 : 0),
        walkin,
        phone: state.pos.phone || '',
        customer_name: state.pos.name || '',
        customer_address: state.pos.address || '',
        marketing_opt_in: (state.pos.optIn || '0') === '1' ? 1 : 0
      }
      const out = await api('api_orders_create', { method:'POST', body: payload })
      state.cart = []
      state.lastTouchedProductId = null
      state.lastTouchedLineId = null
      state.pos.coupon = ''
      state.pos.tipCents = 0
      state.pos.amountTenderedCents = 0
      msg('pos_msg','ok',`Order placed: ${out.order_code}`)
      await loadOrders('active')
      await loadDashboard()
      render()
    }catch(e){
      msg('pos_msg','err', e.message || 'Failed to place order')
    }
  }

  function bind(){
    const navToggle = qs('#navToggle')
    if (navToggle) navToggle.onclick = () => setAppSidebarCollapsed(!qs('#appShell').classList.contains('navCollapsed'))
    qsa('.tab').forEach(b=>b.onclick=()=>setTab(b.dataset.tab).catch(e=>msg('pos_msg','err', e.message || 'Tab load failed')))
    qsa('[data-go]').forEach(b=>b.onclick=()=>setTab(b.dataset.go).catch(e=>msg('pos_msg','err', e.message || 'Tab load failed')))
    qsa('[data-focus]').forEach(b=>b.onclick=()=>{
      const target = qs(b.dataset.focus || '')
      if (target) target.focus()
    })
    qsa('[data-retry]').forEach(b=>b.onclick=()=>retryRegion(b.dataset.retry).catch(e=>toast('err', e.message || 'Retry failed')))

    const posQ = qs('#pos_q')
    if (posQ) posQ.oninput = async () => {
      state.pos.q = posQ.value
      state.categoryFilter = 'All'
      await loadProducts(state.pos.q, false, {renderStart:false})
      render()
    }
    if (posQ) posQ.onkeydown = async e => {
      if (e.key !== 'Enter') return
      e.preventDefault()
      state.pos.q = posQ.value
      await addExactSkuFromSearch(state.pos.q)
    }

    qsa('[data-poscat]').forEach(b=>b.onclick=()=>{
      state.categoryFilter = b.dataset.poscat || 'All'
      render()
    })

    qsa('[data-paymethod]').forEach(b=>b.onclick=()=>{
      state.pos.payMethod = b.dataset.paymethod || 'cash'
      if (state.pos.payMethod === 'credit') state.pos.paid = false
      render()
    })

    const paidToggle = qs('#pos_paid')
    if (paidToggle) paidToggle.onclick = () => {
      state.pos.paid = !state.pos.paid
      render()
    }

    const phone = qs('#pos_phone')
    if (phone) phone.oninput = () => {
      state.pos.phone = phone.value
      clearTimeout(customerLookupTimer)
      customerLookupTimer = setTimeout(()=>lookupCustomerByPhone(state.pos.phone).catch(e=>msg('pos_msg','err', e.message || 'Customer lookup failed')), 350)
    }

    const walkin = qs('#pos_walkin')
    if (walkin) walkin.onchange = () => {
      state.pos.walkin = walkin.checked
      if (state.pos.walkin) {
        state.attachedCustomer = null
        state.customerLookupStatus = 'walkin'
      }
      render()
    }

    const posName = qs('#pos_name')
    if (posName) posName.oninput = () => { state.pos.name = posName.value }
    const posOptin = qs('#pos_optin')
    if (posOptin) posOptin.onchange = () => { state.pos.optIn = posOptin.value }
    const posAddr = qs('#pos_addr')
    if (posAddr) posAddr.oninput = () => { state.pos.address = posAddr.value }
    const posCoupon = qs('#pos_coupon')
    if (posCoupon) posCoupon.oninput = () => { state.pos.coupon = posCoupon.value }
    const posTip = qs('#pos_tip')
    if (posTip) posTip.oninput = () => {
      state.pos.tipCents = Math.max(0, parseInt(posTip.value || '0', 10) || 0)
      render()
    }
    const posReceived = qs('#pos_amount_received')
    if (posReceived) posReceived.oninput = () => {
      state.pos.amountTenderedCents = centsFromAmount(posReceived.value)
      const due = qs('#change_due')
      if (due) due.textContent = fmtMoney(Math.max(0, state.pos.amountTenderedCents - cartTotals().total))
    }
    const posType = qs('#pos_type')
    if (posType) posType.onchange = () => { state.pos.type = posType.value }
    const posEta = qs('#pos_eta')
    if (posEta) posEta.oninput = () => { state.pos.eta = Math.max(5, parseInt(posEta.value || '15', 10) || 15) }

    qsa('[data-add]').forEach(b=>b.onclick=()=>{
      const id = Number(b.dataset.add)
      const p = state.products.find(x=>Number(x.id)===id)
      if (p) cartAdd(p)
    })
    qsa('[data-quick-amount]').forEach(b=>b.onclick=addQuickSaleLine)

    qsa('[data-qtyminus]').forEach(b=>b.onclick=()=>cartQty(b.dataset.qtyminus, -1))
    qsa('[data-qtyplus]').forEach(b=>b.onclick=()=>cartQty(b.dataset.qtyplus, +1))
    qsa('[data-remove]').forEach(b=>b.onclick=()=>cartRemove(b.dataset.remove))
    qsa('[data-notes]').forEach(inp=>inp.oninput=()=>{
      const it = cartLineById(inp.dataset.notes)
      if (it) it.notes = inp.value
    })
    qsa('[data-note-prompt]').forEach(b=>b.onclick=async ()=>{
      const it = cartLineById(b.dataset.notePrompt)
      if (!it) return
      const next = await uiPrompt('Item note', `Add a note for ${it.name}.`, it.notes || '')
      if (next !== null) {
        it.notes = next.trim()
        render()
      }
    })

    const place = qs('#pos_place')
    if (place) place.onclick = placeCurrentOrder

    const ordRef = qs('#orders_refresh')
    if (ordRef) ordRef.onclick = async ()=>{ await loadOrders(qs('#orders_filter')?.value || 'active'); render() }
    const ordFil = qs('#orders_filter')
    if (ordFil) ordFil.onchange = async ()=>{ await loadOrders(ordFil.value); render() }

    const orderSearch = qs('#order_search_btn')
    if (orderSearch) orderSearch.onclick = async ()=>{
      try{
        await loadOrderSearch()
        render()
      }catch(e){
        msg('orders_msg','err', e.message || 'Order search failed')
      }
    }

    qsa('[data-open-order]').forEach(b=>b.onclick=async ()=>{
      try{
        state.selectedOrder = await api('api_order_get', { params: { id: Number(b.dataset.openOrder) }})
        render()
      }catch(e){
        msg('orders_msg','err', e.message || 'Order open failed')
      }
    })

    qsa('[data-st]').forEach(b=>b.onclick=async ()=>{
      try{
        await api('api_order_status_update', { method:'POST', body:{ id:Number(b.dataset.st), status:b.dataset.next } })
        msg('orders_msg','ok','Order updated')
        await loadOrders(qs('#orders_filter')?.value || 'active')
        await loadDashboard()
        render()
      }catch(e){
        msg('orders_msg','err', e.message || 'Failed to update')
      }
    })

    const invQ = qs('#inv_q')
    if (invQ) invQ.oninput = async ()=>{ await loadProducts(invQ.value, true, {renderStart:false}); render() }

    const clearProd = () => {
      if (qs('#prod_id')) qs('#prod_id').value = ''
      if (qs('#prod_sku')) qs('#prod_sku').value = ''
      if (qs('#prod_name')) qs('#prod_name').value = ''
      if (qs('#prod_price')) qs('#prod_price').value = '0'
      if (qs('#prod_stock')) qs('#prod_stock').value = '0'
      if (qs('#prod_cat')) qs('#prod_cat').value = ''
      if (qs('#prod_active')) qs('#prod_active').value = '1'
    }
    const prodClear = qs('#prod_clear')
    if (prodClear) prodClear.onclick = clearProd

    const importFile = qs('#prod_import_file')
    const importFilename = qs('#prod_import_filename')
    const importCsv = qs('#prod_import_csv')
    if (importFilename) importFilename.oninput = () => { state.productImport.filename = importFilename.value || 'products.csv' }
    if (importCsv) importCsv.oninput = () => {
      state.productImport.csv = importCsv.value
      state.productImport.preview = null
    }
    if (importFile) importFile.onchange = async () => {
      const file = importFile.files && importFile.files[0]
      if (!file) return
      state.productImport.filename = file.name || 'products.csv'
      state.productImport.csv = await file.text()
      state.productImport.preview = null
      render()
    }
    const importPreview = qs('#prod_import_preview')
    if (importPreview) importPreview.onclick = async ()=>{
      try{
        state.productImport.busy = true
        const payload = { filename: state.productImport.filename || 'products.csv', csv: state.productImport.csv || '' }
        state.productImport.preview = await api('api_product_import_preview', { method:'POST', body: payload })
        msg('inv_msg','ok',`Preview ready: ${state.productImport.preview.valid_count} rows can import`)
      }catch(e){
        msg('inv_msg','err', e.message || 'Import preview failed')
      }finally{
        state.productImport.busy = false
        render()
      }
    }
    const importCommit = qs('#prod_import_commit')
    if (importCommit) importCommit.onclick = async ()=>{
      try{
        state.productImport.busy = true
        const payload = { filename: state.productImport.filename || 'products.csv', csv: state.productImport.csv || '' }
        const out = await api('api_product_import_commit', { method:'POST', body: payload })
        state.productImport.preview = { rows_total: out.rows_total, valid_count: out.rows_imported, rows: [], errors: out.errors || [] }
        msg('inv_msg','ok',`Imported ${out.rows_imported} products`)
        await Promise.all([loadProducts(qs('#inv_q')?.value || '', true, {renderStart:false}), loadLowStock({renderStart:false}), loadProductImports({renderStart:false}), loadDashboard({renderStart:false})])
      }catch(e){
        msg('inv_msg','err', e.message || 'Import failed')
      }finally{
        state.productImport.busy = false
        render()
      }
    }

    const prodSave = qs('#prod_save')
    if (prodSave) prodSave.onclick = async ()=>{
      try{
        const payload = {
          id: parseInt(qs('#prod_id')?.value || '0',10) || 0,
          sku: qs('#prod_sku')?.value || '',
          name: qs('#prod_name')?.value || '',
          price_cents: parseInt(qs('#prod_price')?.value || '0',10) || 0,
          stock_qty: parseInt(qs('#prod_stock')?.value || '0',10) || 0,
          category: qs('#prod_cat')?.value || '',
          active: (qs('#prod_active')?.value || '1') === '1' ? 1 : 0
        }
        await api('api_product_save', { method:'POST', body: payload })
        msg('inv_msg','ok','Product saved')
        clearProd()
        await loadProducts(qs('#inv_q')?.value || '', true)
        await loadLowStock()
        await loadDashboard()
        render()
      }catch(e){
        msg('inv_msg','err', e.message || 'Product save failed')
      }
    }

    qsa('[data-editprod]').forEach(b=>b.onclick=()=>{
      const p = state.products.find(x=>Number(x.id)===Number(b.dataset.editprod))
      if (!p) return
      qs('#prod_id').value = p.id
      qs('#prod_sku').value = p.sku || ''
      qs('#prod_name').value = p.name || ''
      qs('#prod_price').value = p.price_cents || 0
      qs('#prod_stock').value = p.stock_qty || 0
      qs('#prod_cat').value = p.category || ''
      qs('#prod_active').value = Number(p.active)===1 ? '1' : '0'
    })

    qsa('[data-saveprod]').forEach(b=>b.onclick=async ()=>{
      try{
        const id = Number(b.dataset.saveprod)
        const stock = parseInt(qs(`[data-stock="${id}"]`)?.value || '0',10) || 0
        await api('api_product_update', { method:'POST', body:{ id, stock_qty: stock, active: 1 } })
        msg('inv_msg','ok','Saved')
        await loadLowStock()
        await loadProducts(qs('#inv_q')?.value || '', true)
        await loadDashboard()
        render()
      }catch(e){
        msg('inv_msg','err', e.message || 'Save failed')
      }
    })

    const lowRef = qs('#low_refresh')
    if (lowRef) lowRef.onclick = async ()=>{ await loadLowStock(); await loadDashboard(); render() }

    const crmQ = qs('#crm_q')
    if (crmQ) crmQ.oninput = async ()=>{
      const q = crmQ.value.trim()
      state.customerExport.q = q
      if (q.length < 2 && !state.customerOwesOnly) { state.customerSearch = []; render(); return }
      await loadCustomerSearch(q, {renderStart:false})
      render()
    }
    const crmOwes = qs('#crm_owes')
    if (crmOwes) crmOwes.onchange = async ()=>{
      state.customerOwesOnly = !!crmOwes.checked
      const q = qs('#crm_q')?.value?.trim() || ''
      if (q.length < 2 && !state.customerOwesOnly) {
        state.customerSearch = []
      } else {
        await loadCustomerSearch(q, {renderStart:false})
      }
      render()
    }

    const crmExportSegment = qs('#crm_export_segment')
    if (crmExportSegment) crmExportSegment.onchange = ()=>{ state.customerExport.segmentId = crmExportSegment.value; render() }
    const crmExportFormat = qs('#crm_export_format')
    if (crmExportFormat) crmExportFormat.onchange = ()=>{ state.customerExport.format = crmExportFormat.value || 'sms'; render() }
    const crmExportBom = qs('#crm_export_bom')
    if (crmExportBom) crmExportBom.onchange = ()=>{ state.customerExport.bom = !!crmExportBom.checked; render() }
    const crmExportOverride = qs('#crm_export_override')
    if (crmExportOverride) crmExportOverride.onchange = ()=>{ state.customerExport.override = !!crmExportOverride.checked; render() }

    qsa('[data-open]').forEach(b=>b.onclick=async ()=>{
      const id = Number(b.dataset.open)
      state.selectedCustomer = null
      state.customerTimeline = []
      await loadCustomerProfile(id)
      render()
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
        if (state.selectedCustomer?.customer?.id) {
          state.customerTimeline = await api('api_customer_timeline', { params: { id: state.selectedCustomer.customer.id }})
        }
        render()
      }catch(e){
        msg('cust_msg','err', e.message || 'Save failed')
      }
    }

    const ledgerPay = qs('#ledger_pay')
    if (ledgerPay) ledgerPay.onclick = async ()=>{
      try{
        const customerId = Number(state.selectedCustomer?.customer?.id || 0)
        const amount = centsFromAmount(qs('#ledger_payment_amount')?.value || '')
        await api('api_ledger_payment', { method:'POST', body: {
          customer_id: customerId,
          amount_cents: amount,
          note: qs('#ledger_payment_note')?.value || ''
        }})
        msg('cust_msg','ok','Payment recorded')
        await loadCustomerProfile(customerId)
        await loadCustomerSearch(qs('#crm_q')?.value?.trim() || '', {renderStart:false})
        await loadDashboard()
        render()
      }catch(e){
        msg('cust_msg','err', e.message || 'Payment failed')
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

    qsa('[data-dup-seg]').forEach(b=>b.onclick=async ()=>{
      try{
        const out = await api('api_segment_duplicate', { method:'POST', body: { id: Number(b.dataset.dupSeg || '0') }})
        msg('seg_msg','ok',`Duplicated segment #${out.id}`)
        await loadSegments()
        render()
      }catch(e){
        msg('seg_msg','err', e.message || 'Duplicate failed')
      }
    })

    qsa('[data-preset]').forEach(b=>b.onclick=async ()=>{
      try{
        const out = await api('api_campaign_preset_create', { method:'POST', body: { preset: b.dataset.preset }})
        const focusId = Number(out.focus_campaign_id || out.campaign_id || 0)
        state.focus_campaign_id = focusId || null
        if (focusId && out.export_format) campaignExportState(focusId).format = out.export_format
        await loadSegments()
        await loadCampaigns()
        await loadDashboard()
        if (focusId && Number(out.queued || 0) > 0) {
          const ex = campaignExportState(focusId)
          ex.loading = true
          ex.error = ''
          try {
            ex.preview = await api('api_campaign_export_preview', { method:'POST', body: { id: focusId, format: ex.format || out.export_format || 'sms' }})
          } catch (previewError) {
            ex.error = previewError.message || 'Preview failed'
          } finally {
            ex.loading = false
          }
        }
        render()
        msg('camp_msgbox','ok', Number(out.queued || 0) > 0 ? `Created and queued ${out.queued} recipients. Download the CSV from the highlighted campaign.` : `Created preset segment #${out.segment_id} and campaign #${out.campaign_id}`)
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Preset failed')
      }
    })

    const campSim = qs('#camp_sim')
    if (campSim) campSim.onclick = async ()=>{
      try{
        const segment_id = Number(qs('#camp_seg')?.value || '0')
        const override_opt_in = (qs('#camp_override')?.value || '0') === '1' ? 1 : 0
        const message_template = qs('#camp_msg')?.value || ''
        state.sim = await api('api_campaign_simulate', { method:'POST', body: { segment_id, override_opt_in, message_template, sample_coupon_code: 'NP-PREVIEW' }})
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
        await loadDashboard()
        render()
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Create failed')
      }
    }

    const campSend = qs('#camp_send')
    if (campSend) campSend.onclick = async ()=>{
      try{
        const entered = await uiPrompt('Queue campaign', 'Enter the campaign ID to send or queue now.', '')
        const id = Number(entered || '0')
        if (!id) return
        const override_opt_in = (qs('#camp_override')?.value || '0') === '1' ? 1 : 0
        const with_coupons = (qs('#camp_coupon')?.value || '0') === '1' ? 1 : 0
        const out = await api('api_campaign_send', { method:'POST', body: { id, override_opt_in, with_coupons } })
        await loadCampaigns()
        await loadDashboard()
        render()
        msg('camp_msgbox','ok',`Queued ${out.queued} recipients. Use the export panel on this campaign row.`)
      }catch(e){
        msg('camp_msgbox','err', e.message || 'Send failed')
      }
    }

    qsa('[data-export-format]').forEach(sel=>sel.onchange=()=>{
      const ex = campaignExportState(sel.dataset.exportFormat)
      ex.format = sel.value || 'mailchimp'
      ex.preview = null
      ex.error = ''
      render()
    })

    qsa('[data-export-bom]').forEach(inp=>inp.onchange=()=>{
      const ex = campaignExportState(inp.dataset.exportBom)
      ex.bom = !!inp.checked
      render()
    })

    qsa('[data-export-preview]').forEach(btn=>btn.onclick=async ()=>{
      const id = Number(btn.dataset.exportPreview || '0')
      const ex = campaignExportState(id)
      ex.loading = true
      ex.error = ''
      render()
      try{
        ex.preview = await api('api_campaign_export_preview', { method:'POST', body: { id, format: ex.format || 'mailchimp' }})
      }catch(e){
        ex.error = e.message || 'Preview failed'
      }finally{
        ex.loading = false
        render()
      }
    })

    const repRefresh = qs('#rep_refresh')
    if (repRefresh) repRefresh.onclick = async ()=>{
      try{
        state.reportFrom = qs('#rep_from')?.value || state.reportFrom
        state.reportTo = qs('#rep_to')?.value || state.reportTo
        await loadSalesReport()
        render()
      }catch(e){
        $view.insertAdjacentHTML('afterbegin', `<div class="errbox">${esc(e.message || 'Report failed')}</div>`)
      }
    }
    const closePrint = qs('#close_print')
    if (closePrint) closePrint.onclick = () => window.print()

    const auditRefresh = qs('#audit_refresh')
    if (auditRefresh) auditRefresh.onclick = async ()=>{
      try{
        await loadAuditLog(qs('#audit_q')?.value || '')
        render()
      }catch(e){
        msg('admin_msg','err', e.message || 'Audit load failed')
      }
    }

    const storeSave = qs('#store_save')
    if (storeSave) storeSave.onclick = async ()=>{
      try{
        await api('api_settings_update', { method:'POST', body: {
          name: qs('#store_name')?.value || state.store?.name || '',
          currency_symbol: qs('#store_symbol')?.value || state.store?.currency_symbol || '',
          default_country_code: qs('#store_country_code')?.value || state.store?.default_country_code || '+1',
          tax_rate: Number(qs('#store_tax')?.value || state.store?.tax_rate || 0),
          accent: qs('#store_accent')?.value || state.store?.accent || '#2563eb',
          enable_delivery: (qs('#store_delivery')?.value || '1') === '1' ? 1 : 0
        }})
        await loadMe()
        toast('ok', 'Store settings saved')
        render()
      }catch(e){
        msg('admin_msg','err', e.message || 'Store settings failed')
      }
    }

    const pwChange = qs('#pw_change')
    if (pwChange) pwChange.onclick = async ()=>{
      try{
        await api('api_password_change', { method:'POST', body: {
          current_password: qs('#pw_current')?.value || '',
          new_password: qs('#pw_new')?.value || ''
        }})
        msg('admin_msg','ok','Password changed')
      }catch(e){
        msg('admin_msg','err', e.message || 'Password change failed')
      }
    }

    const pwReset = qs('#pw_reset')
    if (pwReset) pwReset.onclick = async ()=>{
      try{
        await api('api_admin_password_reset', { method:'POST', body: {
          email: qs('#reset_email')?.value || '',
          new_password: qs('#reset_pw')?.value || ''
        }})
        msg('admin_msg','ok','Password reset')
      }catch(e){
        msg('admin_msg','err', e.message || 'Password reset failed')
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
    if (qs('#seg_has_balance')?.checked) f.has_balance = true
    return f
  }

  async function boot(){
    setAppSidebarCollapsed(localStorage.getItem('neighbourposSidebarCollapsed') === '1')
    setupConnectionWatch()
    setupKeyboardShortcuts()
    await loadMe()
    const initial = (window.location.hash || '#pos').slice(1)
    await setTab(['dashboard','pos','orders','inventory','crm','campaigns','reports','admin'].includes(initial) ? initial : 'pos')
  }

  boot().catch(e=>{
    $view.innerHTML = `<div class="card"><div class="h1">Error</div><div class="errbox">${esc(e.message || e)}</div>
      <div class="muted">If you just deployed: ensure PHP can write next to this file to create <b>neighbourpos.db</b>.</div>
      <div class="muted" style="margin-top:10px">Admin-only demo: open DevTools Console and run <b>loadSample()</b> after login.</div>
      <button class="btn small" type="button" onclick="window.location.reload()">Retry</button>
      </div>`
  })

  async function loadSample(){
    try{
      await api('api_load_sample_data', { method:'POST', body:{} })
      toast('ok', 'Sample data loaded. Refreshing...')
      await loadProducts('')
      await loadLowStock()
      await loadOrders('active')
      await loadSegments()
      await loadCampaigns()
      render()
    }catch(e){ toast('err', e.message || String(e)) }
  }
  window.loadSample = loadSample
</script>

<div style="max-width:1100px;margin:0 auto;padding:0 14px 18px;color:var(--muted);font-size:12px;line-height:1.45">
  <div class="card" style="margin:14px 0">
    <div class="h1">Security & docs</div>
    <div class="muted" style="margin-top:6px">
      <a href="SETUP.md">Docs</a>  -  <a href="SECURITY.md">Security</a>  -  <a href="README.md">README</a>  -  <span class="pill versionPill mono">v<?=h(APP_VERSION)?></span>
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
