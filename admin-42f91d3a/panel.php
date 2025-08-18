<?php
session_start();
if (!($_SESSION['admin'] ?? false)) {
    http_response_code(403);
    die("403 Forbidden");
}

// Файлы
$banFile    = __DIR__."/banned.txt";
$visitFile  = __DIR__."/visits.log";
$debugFile  = __DIR__."/debug.log";
$configFile = __DIR__."/config.json";

// --- Действия админа ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Разбанить IP
    if (isset($_POST['unban'])) {
        $ip = trim($_POST['unban']);
        $bans = file_exists($banFile) ? file($banFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) : [];
        $bans = array_filter($bans, fn($b)=>$b !== $ip);
        file_put_contents($banFile, implode("\n",$bans)."\n");
    }

    // Забанить IP вручную
    if (isset($_POST['ban_ip'])) {
        $ip = trim($_POST['ban_ip']);
        if ($ip) file_put_contents($banFile, $ip."\n", FILE_APPEND);
    }

    // Очистить логи
    if (isset($_POST['clear_visits'])) file_put_contents($visitFile,"");
    if (isset($_POST['clear_debug']))  file_put_contents($debugFile,"");

    // Установить режим защиты
    if (isset($_POST['mode'])) {
        $config = ['mode'=>$_POST['mode']];
        file_put_contents($configFile, json_encode($config));
    }
    header("Location: panel.php");
    exit;
}

// Данные для отображения
$bans   = file_exists($banFile) ? file($banFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) : [];
$visits = file_exists($visitFile) ? array_slice(file($visitFile), -50) : [];
$debugs = file_exists($debugFile) ? array_slice(file($debugFile), -50) : [];
$config = file_exists($configFile) ? json_decode(file_get_contents($configFile),true) : ['mode'=>'medium'];
$mode   = $config['mode'] ?? 'medium';
?>
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Админ-панель</title>
  <style>
    body { font-family: sans-serif; background: #eef3ff; padding: 20px; }
    h1 { color: #2a6df4; }
    .section { background:#fff; padding:15px; margin:20px 0; border-radius:8px;
               box-shadow:0 4px 12px rgba(0,0,0,0.1); }
    .logs { max-height:250px; overflow:auto; font-family:monospace; background:#111; color:#0f0; padding:10px; }
    input,select,button { margin:5px; padding:5px 10px; }
  </style>
</head>
<body>
  <h1>Админ-панель сайта</h1>

  <div class="section">
    <h2>⚡ Защита от DDoS</h2>
    <form method="post">
      <select name="mode">
        <option value="easy"   <?= $mode==="easy"?"selected":"" ?>>Мягкая (10 req/s)</option>
        <option value="medium" <?= $mode==="medium"?"selected":"" ?>>Средняя (5 req/s)</option>
        <option value="hard"   <?= $mode==="hard"?"selected":"" ?>>Жёсткая (2 req/s)</option>
      </select>
      <button type="submit">Применить</button>
    </form>
  </div>

  <div class="section">
    <h2>🚫 Бан-лист</h2>
    <form method="post">
      <input type="text" name="ban_ip" placeholder="IP для бана">
      <button type="submit">Забанить</button>
    </form>
    <ul>
      <?php foreach($bans as $ip): ?>
        <li><?=htmlspecialchars($ip)?> 
            <form method="post" style="display:inline">
              <button name="unban" value="<?=$ip?>">Разбанить</button>
            </form>
        </li>
      <?php endforeach; ?>
    </ul>
  </div>

  <div class="section">
    <h2>📜 Логи посещений</h2>
    <form method="post"><button name="clear_visits">Очистить</button></form>
    <div class="logs"><?=implode("<br>",array_map("htmlspecialchars",$visits))?></div>
  </div>

  <div class="section">
    <h2>🐞 Debug (Telegram)</h2>
    <form method="post"><button name="clear_debug">Очистить</button></form>
    <div class="logs"><?=implode("<br>",array_map("htmlspecialchars",$debugs))?></div>
  </div>

  <p><a href="logout.php">Выйти</a></p>
</body>
</html>
