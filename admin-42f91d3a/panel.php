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
// Данные для отображения
$bans   = file_exists($banFile) ? file($banFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) : [];
$visits = file_exists($visitFile) ? array_slice(file($visitFile), -50) : [];
$debugs = file_exists($debugFile) ? array_slice(file($debugFile), -50) : [];
?>
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Админ-панель</title>
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: 'Montserrat', sans-serif;
    }
    
    body {
        background: linear-gradient(135deg, #1a0b2e, #4d1d7d);
        min-height: 100vh;
        padding: 20px;
        color: white;
        display: flex;
        flex-direction: column;
        align-items: center;
    }
    
    .container {
        width: 100%;
        max-width: 1200px;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(15px);
        border-radius: 20px;
        overflow: hidden;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.2);
        animation: fadeIn 1s ease-out;
    }
    
    .header {
        text-align: center;
        padding: 30px;
        background: rgba(0, 0, 0, 0.2);
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .header h1 {
        font-size: 2.5rem;
        background: linear-gradient(to right, #b06ab3, #a8c0ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 10px;
    }
    
    .header p {
        color: #d0b3ff;
        font-size: 1.1rem;
    }
    
    .section {
        padding: 25px;
        margin: 20px;
        background: rgba(0, 0, 0, 0.2);
        border-radius: 15px;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        animation: slideIn 0.5s ease-out;
    }
    
    .section h2 {
        color: #c7a0ff;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .section h2 i {
        font-size: 1.5rem;
    }
    
    .ban-form {
        display: flex;
        gap: 10px;
        margin-bottom: 20px;
    }
    
    .ban-form input {
        flex: 1;
        padding: 12px;
        border-radius: 8px;
        border: none;
        background: rgba(255, 255, 255, 0.1);
        color: white;
        font-size: 1rem;
    }
    
    .ban-form button {
        padding: 12px 20px;
        background: linear-gradient(to right, #8a2be2, #9932cc);
        border: none;
        border-radius: 8px;
        color: white;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .ban-form button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    .ban-list {
        list-style: none;
        max-height: 300px;
        overflow-y: auto;
        background: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
        padding: 15px;
    }
    
    .ban-list li {
        padding: 12px;
        margin-bottom: 10px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        animation: fadeInItem 0.5s ease-out;
    }
    
    .ban-list li:last-child {
        margin-bottom: 0;
    }
    
    .ban-ip {
        font-family: monospace;
        font-size: 1.1rem;
    }
    
    .unban-btn {
        padding: 8px 15px;
        background: linear-gradient(to right, #ff416c, #ff4b2b);
        border: none;
        border-radius: 6px;
        color: white;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .unban-btn:hover {
        transform: scale(1.05);
    }
    
    .logs {
        max-height: 250px;
        overflow: auto;
        font-family: monospace;
        background: rgba(0, 0, 0, 0.5);
        color: #0f0;
        padding: 15px;
        border-radius: 10px;
        font-size: 0.9rem;
        line-height: 1.5;
        white-space: pre-wrap;
    }
    
    .clear-btn {
        padding: 10px 20px;
        background: linear-gradient(to right, #ff416c, #ff4b2b);
        border: none;
        border-radius: 8px;
        color: white;
        cursor: pointer;
        margin-bottom: 15px;
        transition: all 0.3s ease;
    }
    
    .clear-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    .footer {
        text-align: center;
        padding: 20px;
        color: #b19cd9;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .footer a {
        color: #c7a0ff;
        text-decoration: none;
    }
    
    .footer a:hover {
        text-decoration: underline;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    @keyframes slideIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes fadeInItem {
        from { opacity: 0; transform: translateX(-10px); }
        to { opacity: 1; transform: translateX(0); }
    }
    
    /* Поиск */
    .search-box {
        margin-bottom: 15px;
    }
    
    .search-box input {
        width: 100%;
        padding: 10px;
        border-radius: 8px;
        border: none;
        background: rgba(255, 255, 255, 0.1);
        color: white;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1><i class="fas fa-crown"></i> Админ-панель сайта</h1>
      <p>Управление сайтом</p>
    </div>
    
    <div class="section">
      <h2><i class="fas fa-ban"></i> Бан-лист</h2>
      <form class="ban-form" method="post">
        <input type="text" name="ban_ip" placeholder="Введите IP для бана" required>
        <button type="submit"><i class="fas fa-ban"></i> Забанить</button>
      </form>
      
      <div class="search-box">
        <input type="text" id="search-ban" placeholder="Поиск по IP...">
      </div>
      
      <ul class="ban-list" id="ban-list">
        <?php foreach($bans as $ip): ?>
          <li>
            <span class="ban-ip"><?=htmlspecialchars($ip)?></span>
            <form method="post" style="display:inline">
              <button class="unban-btn" name="unban" value="<?=$ip?>">
                <i class="fas fa-unlock"></i> Разбанить
              </button>
            </form>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>
    
    <div class="section">
      <h2><i class="fas fa-file-alt"></i> Логи посещений</h2>
      <form method="post">
        <button class="clear-btn" name="clear_visits">
          <i class="fas fa-trash"></i> Очистить логи
        </button>
      </form>
      <div class="logs"><?=implode("",array_map("htmlspecialchars",$visits))?></div>
    </div>
    
    <div class="section">
      <h2><i class="fas fa-bug"></i> Debug (Telegram)</h2>
      <form method="post">
        <button class="clear-btn" name="clear_debug">
          <i class="fas fa-trash"></i> Очистить debug
        </button>
      </form>
      <div class="logs"><?=implode("",array_map("htmlspecialchars",$debugs))?></div>
    </div>
    
    <div class="footer">
      <p><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Выйти из панели</a></p>
    </div>
  </div>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Поиск по списку банов
        const searchInput = document.getElementById('search-ban');
        const banList = document.getElementById('ban-list');
        const banItems = banList.getElementsByTagName('li');
        
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            
            Array.from(banItems).forEach(item => {
                const ip = item.querySelector('.ban-ip').textContent.toLowerCase();
                if (ip.includes(searchTerm)) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
  </script>
</body>
</html>
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
