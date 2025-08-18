<?php
session_start();

$ADMIN_USER  = getenv("ADMIN_USER") ?: "admin";
$ADMIN_PASS  = getenv("ADMIN_PASS") ?: "password";
$allowed_ips_raw = getenv("ALLOWED_IPS") ?: "";
$allowed_ips = array_filter(array_map('trim', explode(",", $allowed_ips_raw)));

$client_ip = $_SERVER['REMOTE_ADDR'] ?? "0.0.0.0";
$lock_file    = __DIR__ . "/lock.json";
$max_attempts = 3;
$lock_time    = 600; // 10 минут

// Если список не пустой → проверяем, иначе пускаем всех
if (!empty($allowed_ips) && !in_array($client_ip, $allowed_ips)) {
    http_response_code(403);
    die("403 Forbidden");
}

// Загружаем блокировки
$lock_data = file_exists($lock_file) ? json_decode(file_get_contents($lock_file), true) : [];
if (isset($lock_data[$client_ip]) && time() < $lock_data[$client_ip]) {
    die("⛔ IP временно заблокирован, попробуйте позже.");
}

// Авторизация
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['user'] ?? "";
    $pass = $_POST['pass'] ?? "";

    if ($user === $ADMIN_USER && $pass === $ADMIN_PASS) {
        $_SESSION['admin'] = true;
        file_put_contents(__DIR__."/auth.log", date("c")." | $client_ip | SUCCESS\n", FILE_APPEND);
        header("Location: panel.php");
        exit;
    } else {
        $lock_data[$client_ip.'_count'] = ($lock_data[$client_ip.'_count'] ?? 0) + 1;
        file_put_contents(__DIR__."/auth.log", date("c")." | $client_ip | FAIL ($user)\n", FILE_APPEND);

        if ($lock_data[$client_ip.'_count'] >= $max_attempts) {
            $lock_data[$client_ip] = time() + $lock_time;
            unset($lock_data[$client_ip.'_count']);
        }
        file_put_contents($lock_file, json_encode($lock_data));
        die("❌ Неверные данные!");
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Вход в админку</title>
  <style>
    body { font-family: sans-serif; background: #f0f4ff; }
    .login-box {
        width: 300px; margin: 100px auto; padding: 20px;
        border: 1px solid #ccc; border-radius: 10px;
        background: #fff; box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    input { width: 100%; margin: 8px 0; padding: 10px; }
    button { width: 100%; padding: 10px; background: #2a6df4; color: #fff; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #1d4fc9; }
  </style>
</head>
<body>
  <div class="login-box">
    <h2>Админ-панель</h2>
    <form method="post">
      <input type="text" name="user" placeholder="Логин" required>
      <input type="password" name="pass" placeholder="Пароль" required>
      <button type="submit">Войти</button>
    </form>
  </div>
</body>
</html>
