<?php
declare(strict_types=1);

/* ---------- Session hardening ---------- */
$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
  'lifetime' => 0,
  'path'     => '/',
  'domain'   => '',
  'secure'   => $secure,
  'httponly' => true,
  'samesite' => 'Strict',
]);
session_start();

/* ---------- Config via env ---------- */
$ADMIN_USER   = getenv('ADMIN_USER')  ?: 'admin';
$ADMIN_PASS   = getenv('ADMIN_PASS')  ?: null;             // plain (небезопасно — лучше HASH)
$ADMIN_HASH   = getenv('ADMIN_PASS_HASH') ?: null;         // предпочтительно (password_hash)
$ADMIN_OTP    = getenv('ADMIN_OTP')   ?: null;             // опциональный статический код (например 6 цифр)

$allowed_ips_raw = getenv('ALLOWED_IPS') ?: '';            // пример: "1.2.3.4, 5.6.7.0/24, 2001:db8::/32"
$allowed_list = array_values(array_filter(array_map('trim', explode(',', $allowed_ips_raw))));

$client_ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$lock_file   = __DIR__ . '/lock.json';
$auth_log    = __DIR__ . '/auth.log';
$max_attempts= 5;           // до времблока
$lock_time   = 15*60;       // 15 минут
$backoff_base= 300000;      // 0.3s base backoff (микросекунды)

/* ---------- Small helpers ---------- */
function ip_in_cidr(string $ip, string $cidr): bool {
  if (strpos($cidr, '/') === false) return false;
  [$net, $mask] = explode('/', $cidr, 2);
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    $mask = (int)$mask;
    $ip_long  = ip2long($ip);
    $net_long = ip2long($net);
    $mask_long = -1 << (32 - $mask);
    return ($ip_long & $mask_long) === ($net_long & $mask_long);
  }
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    $mask = (int)$mask;
    $ip_bin  = inet_pton($ip);
    $net_bin = inet_pton($net);
    $bytes = intdiv($mask, 8);
    $bits  = $mask % 8;
    if ($bytes && substr($ip_bin, 0, $bytes) !== substr($net_bin, 0, $bytes)) return false;
    if ($bits) {
      $maskByte = chr((0xFF << (8 - $bits)) & 0xFF);
      return (ord($ip_bin[$bytes]) & ord($maskByte)) === (ord($net_bin[$bytes]) & ord($maskByte));
    }
    return true;
  }
  return false;
}
function ip_allowed(string $ip, array $list): bool {
  if (!$list) return true; // пусто — пускать всех
  foreach ($list as $entry) {
    if (strpos($entry, '/') !== false) { if (ip_in_cidr($ip, $entry)) return true; }
    else if (hash_equals($entry, $ip)) { return true; }
  }
  return false;
}
function read_lock(string $path): array {
  if (!file_exists($path)) return [];
  $fh = fopen($path, 'c+');
  if (!$fh) return [];
  try {
    flock($fh, LOCK_SH);
    $raw = stream_get_contents($fh);
    flock($fh, LOCK_UN);
  } finally { fclose($fh); }
  $j = @json_decode($raw ?: '[]', true);
  return is_array($j) ? $j : [];
}
function write_lock(string $path, array $data): void {
  $tmp = $path . '.tmp';
  $fh = fopen($tmp, 'wb');
  if (!$fh) return;
  try {
    flock($fh, LOCK_EX);
    fwrite($fh, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT));
    fflush($fh);
    flock($fh, LOCK_UN);
  } finally { fclose($fh); }
  rename($tmp, $path);
}
function log_auth(string $path, string $ip, string $status, string $user = ''): void {
  $line = sprintf("%s | %s | %s%s\n", date('c'), $ip, $status, $user !== '' ? " ($user)" : '');
  $fh = fopen($path, 'ab');
  if ($fh) { flock($fh, LOCK_EX); fwrite($fh, $line); flock($fh, LOCK_UN); fclose($fh); }
}

/* ---------- IP allowlist ---------- */
if (!ip_allowed($client_ip, $allowed_list)) {
  http_response_code(403);
  exit('403 Forbidden');
}

/* ---------- CSRF ---------- */
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf'];

/* ---------- Locks / throttle ---------- */
$locks = read_lock($lock_file);
$ip_key = $client_ip;
$cnt_key = $client_ip . '_count';
$now = time();
if (isset($locks[$ip_key]) && $now < (int)$locks[$ip_key]) {
  exit('⛔ IP временно заблокирован, попробуйте позже.');
}

/* ---------- Already logged-in ---------- */
if (!empty($_SESSION['admin']) && $_SESSION['admin'] === true) {
  header('Location: panel.php');
  exit;
}

/* ---------- Handle POST ---------- */
$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // simple backoff vs brute (based on previous count)
  $prev = (int)($locks[$cnt_key] ?? 0);
  if ($prev > 0) {
    $delay = min(2000000, $prev * $backoff_base); // max 2s
    usleep($delay);
  }

  $token = $_POST['_csrf'] ?? '';
  if (!hash_equals($CSRF, $token)) {
    http_response_code(400); $error = 'Плохой CSRF';
  } else {
    $user = (string)($_POST['user'] ?? '');
    $pass = (string)($_POST['pass'] ?? '');
    $otp  = (string)($_POST['otp']  ?? '');

    // username check
    $ok_user = hash_equals($ADMIN_USER, $user);

    // password check (prefer hash)
    $ok_pass = false;
    if ($ADMIN_HASH)       $ok_pass = password_verify($pass, $ADMIN_HASH);
    elseif ($ADMIN_PASS)   $ok_pass = hash_equals($ADMIN_PASS, $pass);

    // optional OTP
    $ok_otp = true;
    if ($ADMIN_OTP !== null && $ADMIN_OTP !== '') {
      $ok_otp = hash_equals($ADMIN_OTP, $otp);
    }

    if ($ok_user && $ok_pass && $ok_otp) {
      // success: reset counters, fixate session
      unset($locks[$cnt_key], $locks[$ip_key]);
      write_lock($lock_file, $locks);

      session_regenerate_id(true);
      $_SESSION['admin'] = true;
      $_SESSION['login_time'] = time();
      $_SESSION['ip'] = $client_ip;
      $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

      log_auth($auth_log, $client_ip, 'SUCCESS', $user);
      header('Location: panel.php');
      exit;
    } else {
      // fail
      $locks[$cnt_key] = (int)($locks[$cnt_key] ?? 0) + 1;
      if ($locks[$cnt_key] >= $max_attempts) {
        $locks[$ip_key] = $now + $lock_time;
        unset($locks[$cnt_key]); // сброс счётчика — начинаем заново после окна бана
      }
      write_lock($lock_file, $locks);
      log_auth($auth_log, $client_ip, 'FAIL', $user);
      $error = 'Неверные данные';
    }
  }
}

/* ---------- HTML (purple) ---------- */
?>
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Вход — Purple Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg1:#12091f; --bg2:#3a0f6e; --glass:rgba(255,255,255,.08);
  --stroke:rgba(255,255,255,.18); --text:#f4eaff; --muted:#bda7ff;
  --accent1:#8a2be2; --accent2:#b06ab3; --danger:#ff4b2b; --ok:#3ddc97;
}
*{box-sizing:border-box} body{
  margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  background: radial-gradient(900px 600px at 15% 10%, #2b0a52 0%, transparent 60%),
              radial-gradient(900px 600px at 85% 90%, #4d1d7d 0%, transparent 60%),
              linear-gradient(135deg,var(--bg1),var(--bg2));
  font-family:Montserrat,system-ui,sans-serif; color:var(--text);
}
.box{
  width:min(420px,94vw); padding:22px 22px 18px; border-radius:18px;
  background:var(--glass); border:1px solid var(--stroke); backdrop-filter:blur(16px);
  box-shadow:0 40px 90px rgba(0,0,0,.4);
}
.h{margin:0 0 10px; font-size:22px; background:linear-gradient(90deg,var(--accent2),#a8c0ff);
   -webkit-background-clip:text; -webkit-text-fill-color:transparent}
.sub{color:var(--muted); font-size:12px; margin-bottom:12px}
.row{display:flex; flex-direction:column; gap:10px}
.input{
  width:100%; padding:12px 14px; border-radius:12px; border:1px solid var(--stroke);
  background:rgba(255,255,255,.06); color:var(--text); outline:none;
}
.btn{
  width:100%; padding:12px 14px; border-radius:12px; border:1px solid transparent; cursor:pointer;
  background:linear-gradient(90deg,var(--accent1),#9932cc); color:#fff; font-weight:700; margin-top:8px;
}
.btn:hover{ filter:brightness(1.08) }
.note{ color:var(--muted); font-size:12px; margin-top:8px }
.err{ background:rgba(255,75,43,.12); border:1px solid rgba(255,75,43,.35); color:#ffd7cf;
      padding:10px 12px; border-radius:10px; margin-bottom:10px; font-size:13px }
.meta{ color:#bda7ff; font-size:12px; margin-top:6px }
.ip{ font-family:ui-monospace,Menlo,Consolas,monospace }
</style>
</head>
<body>
  <div class="box">
    <h1 class="h">Вход в админ-панель</h1>
    <div class="sub">Доступ ограничен. Ваш IP: <span class="ip"><?=htmlspecialchars($client_ip)?></span></div>

    <?php if ($error): ?>
      <div class="err">❌ <?=htmlspecialchars($error)?></div>
    <?php endif; ?>

    <form method="post" class="row" autocomplete="off">
      <input type="hidden" name="_csrf" value="<?=$CSRF?>">
      <input class="input" type="text"     name="user" placeholder="Логин"    required autofocus>
      <input class="input" type="password" name="pass" placeholder="Пароль"   required>
      <?php if ($ADMIN_OTP !== null && $ADMIN_OTP !== ''): ?>
        <input class="input" type="text"   name="otp"  placeholder="Код (2FA)" inputmode="numeric" pattern="[0-9A-Za-z\-]{4,10}">
      <?php endif; ?>
      <button class="btn" type="submit">Войти</button>
    </form>

    <div class="note">
      Советы безопасности:
      <ul style="margin:8px 0 0 18px; padding:0">
        <li>Задайте <code>ADMIN_PASS_HASH</code> (bcrypt/argon2) вместо <code>ADMIN_PASS</code>.</li>
        <li>Ограничьте доступ через <code>ALLOWED_IPS</code> (IP или CIDR).</li>
      </ul>
    </div>
    <div class="meta">После входа сессия фиксируется под ваш IP/UA и cookie с SameSite=Strict.</div>
  </div>
</body>
</html>
