<?php
// === НАСТРОЙКИ ===
$token   = getenv("BOT_TOKEN");
$chat_id = getenv("CHAT_ID");

// --- Утилиты токен-бакета (APCu -> файлы) ---
function tb_now() { return microtime(true); }

function tb_store_get($k, $default) {
    if (function_exists('apcu_fetch')) {
        $ok = false;
        $v = apcu_fetch($k, $ok);
        return $ok ? $v : $default;
    }
    $f = sys_get_temp_dir()."/tb_".sha1($k).".json";
    if (!is_file($f)) return $default;
    $raw = @file_get_contents($f);
    if ($raw === false) return $default;
    $d = @json_decode($raw, true);
    return is_array($d) ? $d : $default;
}
function tb_store_set($k, $v) {
    if (function_exists('apcu_store')) {
        apcu_store($k, $v, 3600);
        return;
    }
    $f = sys_get_temp_dir()."/tb_".sha1($k).".json";
    @file_put_contents($f, json_encode($v), LOCK_EX);
}

// $capacity — макс. токенов (бурст), $rate — токенов в секунду
function tb_allow($key, $capacity, $rate) {
    $now = tb_now();
    $st = tb_store_get($key, ['tokens'=>$capacity, 'ts'=>$now]);
    $elapsed = max(0.0, $now - ($st['ts'] ?? $now));
    $st['tokens'] = min($capacity, ($st['tokens'] ?? $capacity) + $elapsed * $rate);
    $st['ts'] = $now;
    $allowed = false;
    if ($st['tokens'] >= 1.0) {
        $st['tokens'] -= 1.0;
        $allowed = true;
    }
    tb_store_set($key, $st);
    $wait = $allowed ? 0 : (1.0 - $st['tokens']) / max(1e-6, $rate);
    return [$allowed, $wait];
}

// --- Helpers для IP и GEO ---
function is_public_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}
function first_public_from_xff($xff) {
    foreach (explode(',', $xff) as $p) {
        $cand = trim($p);
        if ($cand && is_public_ip($cand)) return $cand;
    }
    return null;
}
function client_ip() {
    $candidates = [];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) $candidates[] = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
    if (!empty($_SERVER['HTTP_TRUE_CLIENT_IP']))   $candidates[] = trim($_SERVER['HTTP_TRUE_CLIENT_IP']);
    if (!empty($_SERVER['HTTP_X_REAL_IP']))        $candidates[] = trim($_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ipFromXff = first_public_from_xff($_SERVER['HTTP_X_FORWARDED_FOR']);
        if ($ipFromXff) $candidates[] = $ipFromXff;
    }
    if (!empty($_SERVER['REMOTE_ADDR']))           $candidates[] = trim($_SERVER['REMOTE_ADDR']);

    foreach ($candidates as $ip) {
        if (is_public_ip($ip)) return $ip;
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
function geo_country($ip) {
    $cacheFile = sys_get_temp_dir() . '/geo_' . sha1($ip) . '.json';
    if (is_file($cacheFile) && (time() - filemtime($cacheFile) < 86400)) {
        $c = @json_decode(@file_get_contents($cacheFile), true);
        if (!empty($c['country'])) return $c['country'];
    }
    $ctx = stream_context_create(['http'=>['timeout'=>0.6, 'header'=>"User-Agent: geo-lookup/1.0\r\n"]]);

    $r = @file_get_contents("https://ipinfo.io/{$ip}/json", false, $ctx);
    if ($r) {
        $j = @json_decode($r, true);
        if (!empty($j['country'])) {
            @file_put_contents($cacheFile, json_encode(['country'=>$j['country']]));
            return $j['country'];
        }
    }
    $r = @file_get_contents("https://ip-api.com/json/{$ip}?fields=status,countryCode", false, $ctx);
    if ($r) {
        $j = @json_decode($r, true);
        if (!empty($j['status']) && $j['status']==='success' && !empty($j['countryCode'])) {
            @file_put_contents($cacheFile, json_encode(['country'=>$j['countryCode']]));
            return $j['countryCode'];
        }
    }
    $r = @file_get_contents("https://ipwho.is/{$ip}", false, $ctx);
    if ($r) {
        $j = @json_decode($r, true);
        if (!empty($j['success']) && !empty($j['country_code'])) {
            @file_put_contents($cacheFile, json_encode(['country'=>$j['country_code']]));
            return $j['country_code'];
        }
    }
    return "неизвестно";
}

// === Данные клиента ===
$ip   = client_ip();
$ua   = $_SERVER['HTTP_USER_AGENT'] ?? 'неизвестно';
$page = $_SERVER['REQUEST_URI'];
$time = date("Y-m-d H:i:s");
$host = $_SERVER['HTTP_HOST'] ?? 'неизвестно';
$fullurl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']==='on' ? "https://" : "http://") . $host . $page;
$referer = $_SERVER['HTTP_REFERER'] ?? 'нет';
$lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'нет';
$xff  = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($ip ?? '');
$country = geo_country($ip);

$host_or_ua = strtolower($ua . " " . $referer);

// --- Фильтр строк ---
$filter = function($str) {
    return substr(preg_replace('/[^a-zA-Z0-9 :;,\.\-_\/\?\=\&]/','',$str),0,200);
};
$ua = $filter($ua);
$referer = $filter($referer);
$lang = $filter($lang);
$xff = $filter($xff);

// === Бан-лист ===
if (!file_exists("banned.txt")) file_put_contents("banned.txt","");
$banned = file("banned.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (in_array($ip, $banned, true)) {
    http_response_code(403);
    echo "сын шлюхи, съебался с сайта";
    exit;
}

// === Rate-limiting (щадящий) ===
list($ok_ip, $wait_ip)   = tb_allow("ip:$ip", 7, 0.3); 
list($ok_path, $wait_path) = tb_allow("path:$page", 15, 0.7);

if (!$ok_ip || !$ok_path) {
    http_response_code(429);
    header('Retry-After: '.(int)ceil(max($wait_ip, $wait_path)));
    echo "сын шлюхи, съебался с сайта";
    $log = "$time | RLIMIT | $ip | $country | $fullurl | UA:$ua\n";
    @file_put_contents("visits.log",$log,FILE_APPEND);
    @file_put_contents("banned.txt", "$ip\n", FILE_APPEND);
    $msg = "🚨 Забанен за DDoS!\nIP: $ip ($country)\n⏰ $time\nURL: $fullurl\nUA: $ua";
    goto send;
}

// === Honeypot ===
if ($page === "/admin.php") {
    http_response_code(403);
    echo "сын шлюхи, съебался с сайта";
    $msg = "🚨 Попытка зайти в honeypot (/admin.php)\nIP: $ip ($country)\n⏰ $time";
    @file_put_contents("banned.txt", "$ip\n", FILE_APPEND);
    goto send;
}

// --- Блокировка по рефереру (CheckHost) ---
if (stripos($referer, 'check-host') !== false) {
    http_response_code(403);
    echo "неа)))";
    @file_put_contents("banned.txt", "$ip\n", FILE_APPEND);
    $msg = "🚫 Заблокировано (CheckHost по рефереру)\nIP: $ip ($country)\n⏰ $time\nReferer: $referer";
    goto send;
}

// --- Блокировка по GEO (Нидерланды) ---
if ($country === 'NL') {
    http_response_code(403);
    echo "неа)))";
    @file_put_contents("banned.txt", "$ip\n", FILE_APPEND);
    $msg = "🚫 Заблокировано (страна NL)\nIP: $ip ($country)\n⏰ $time\nUA: $ua\nURL: $fullurl";
    goto send;
}

// === Определение ОС и браузера ===
$os="неизвестно"; $browser="неизвестно";
if (preg_match('/Windows/i',$ua)) $os="Windows";
elseif (preg_match('/Linux/i',$ua)) $os="Linux";
elseif (preg_match('/Android/i',$ua)) $os="Android";
elseif (preg_match('/iPhone|iPad/i',$ua)) $os="iOS";
elseif (preg_match('/Mac OS/i',$ua)) $os="MacOS";

if (preg_match('/Chrome/i',$ua)) $browser="Chrome";
elseif (preg_match('/Firefox/i',$ua)) $browser="Firefox";
elseif (preg_match('/Safari/i',$ua)) $browser="Safari";
elseif (preg_match('/Edge/i',$ua)) $browser="Edge";
elseif (preg_match('/MSIE|Trident/i',$ua)) $browser="IE";

// === Сообщение ===
$msg = "🔔 Новое подключение\n".
       "⏰ $time\n".
       "🌐 IP: $ip ($country)\n".
       "💻 ОС: $os\n".
       "🌍 Браузер: $browser\n".
       "📄 Страница: $page\n".
       "🔗 URL: $fullurl\n".
       "↩️ Referer: $referer\n".
       "🗣 Язык: $lang\n".
       "📶 XFF: $xff";

// === Лог ===
$log = "$time | $ip | $country | $os | $browser | $fullurl | Ref:$referer | UA:$ua | Lang:$lang | XFF:$xff\n";
@file_put_contents("visits.log",$log,FILE_APPEND);

// === Телега (с антиспамом уведомлений) ===
send:
list($ok_tg, $wait_tg) = tb_allow("tg:send", 20, 0.5);
if ($ok_tg && $token && $chat_id) {
    $url="https://api.telegram.org/bot$token/sendMessage";
    $data=['chat_id'=>$chat_id,'text'=>$msg];
    $options=["http"=>[
      "header"=>"Content-type: application/x-www-form-urlencoded\r\n",
      "method"=>"POST",
      //"timeout"=>0.7,
      "content"=>http_build_query($data)
    ]];
	file_put_contents("debug.log", date("c")." | msg=".json_encode($msg).PHP_EOL, FILE_APPEND);
	$response = file_get_contents($url,false,stream_context_create($options));
	file_put_contents("debug.log", date("c")." | ".$response.PHP_EOL, FILE_APPEND);
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EveryDay the best</title>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin>
    <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
    <link rel="preload" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap">
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Montserrat', sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #1a2980, #26d0ce);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            color: white;
            overflow-x: hidden;
            -webkit-tap-highlight-color: transparent;
        }
        
        .container {
            width: 100%;
            max-width: 900px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: fadeIn 1s ease-out;
            position: relative;
        }
        
        /* Принудительная аппаратная акселерация */
        .header, .tabs, .footer, .disclaimer-box {
            transform: translateZ(0);
            backface-visibility: hidden;
            perspective: 1000px;
        }
        
        /* Оптимизация пузырей */
        .bubble {
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.05);
            z-index: -1;
            transform: translateZ(0);
            will-change: transform, opacity;
            contain: strict;
        }
        
        .bubble:nth-child(1) {
            width: 120px;
            height: 120px;
            top: -30px;
            left: -30px;
            animation: float1 8s infinite ease-in-out;
        }
        
        .bubble:nth-child(2) {
            width: 80px;
            height: 80px;
            bottom: 20px;
            right: 50px;
            animation: float2 15s infinite ease-in-out;
        }

        /* Упрощенные анимации */
        @keyframes float1 {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(10px, -20px); }
        }

        @keyframes float2 {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(-10px, -15px); }
        }
        
        .header {
            text-align: center;
            padding: 40px 30px 30px;
            background: rgba(0, 0, 0, 0.2);
            position: relative;
        }
        
        .logo {
            font-size: 4rem;
            margin-bottom: 15px;
            text-shadow: 0 0 15px rgba(0, 195, 255, 0.8);
            animation: pulse 4s infinite;
            display: inline-block;
            transform: translateY(0);
            transition: transform 0.3s ease;
            will-change: transform, text-shadow;
        }
        
        .logo:hover {
            transform: translateY(-5px);
        }
        
        h1 {
            font-size: 2.8rem;
            background: linear-gradient(to right, #4df1ff, #a6f6ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            letter-spacing: 1px;
            font-weight: 700;
        }
        
        .tabs {
            display: flex;
            background: rgba(0, 0, 0, 0.25);
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
        }
        
        .tab {
            flex: 1;
            text-align: center;
            padding: 20px 0;
            font-size: 1.2rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
            z-index: 1;
            will-change: background;
        }
        
        .tab i {
            margin-right: 8px;
            transition: transform 0.3s ease;
        }
        
        .tab:hover {
            background: rgba(0, 195, 255, 0.2);
        }
        
        .tab:hover i {
            transform: scale(1.2);
        }
        
        .tab.active {
            background: rgba(0, 195, 255, 0.3);
            color: #a6f6ff;
        }
        
        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, #00c3ff, #4df1ff);
            animation: tabIndicator 0.5s ease;
        }
        
        .content {
            padding: 30px;
            min-height: 400px;
            will-change: transform, opacity;
        }
        
        .tab-content {
            display: none;
            animation: slideIn 0.5s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .link-list {
            list-style: none;
            padding: 0;
        }
        
        .link-item {
            background: rgba(255, 255, 255, 0.1);
            margin: 15px 0;
            padding: 20px 25px;
            border-radius: 15px;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            cursor: pointer;
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
            will-change: transform, background, box-shadow;
        }
        
        .link-item:hover {
            background: rgba(255, 255, 255, 0.15);
            transform: translateY(-4px);
            box-shadow: 0 7px 15px rgba(0, 0, 0, 0.15);
        }
        
        .link-item i {
            font-size: 2rem;
            margin-right: 20px;
            width: 50px;
            text-align: center;
            color: #4df1ff;
            transition: transform 0.3s ease;
            will-change: transform;
        }
        
        .link-item:hover i {
            transform: scale(1.15);
        }
        
        .link-item .text {
            flex: 1;
        }
        
        .link-item .title {
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 5px;
            color: #a6f6ff;
        }
        
        .link-item .url {
            display: none;
        }
        
        .link-item::after {
            content: '↗';
            position: absolute;
            right: 25px;
            font-size: 1.8rem;
            opacity: 0.7;
            transition: all 0.3s ease;
        }
        
        .link-item:hover::after {
            transform: translate(3px, -3px);
            opacity: 1;
            color: #4df1ff;
        }
        
        .footer {
            text-align: center;
            padding: 25px;
            background: rgba(0, 0, 0, 0.2);
            font-size: 1rem;
            color: rgba(255, 255, 255, 0.8);
            position: relative;
        }
        
        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 80%;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(0, 195, 255, 0.5), transparent);
        }
        
        .disclaimer-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.4s ease;
            will-change: opacity;
        }
        
        .disclaimer-overlay.active {
            opacity: 1;
            visibility: visible;
        }
        
        .disclaimer-box {
            background: linear-gradient(135deg, #7b1fa2, #4527a0);
            border-radius: 20px;
            width: 90%;
            max-width: 500px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            position: relative;
            overflow: hidden;
            transform: translateZ(0);
            backface-visibility: hidden;
        }
        
        .disclaimer-box::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            z-index: -1;
        }
        
        .disclaimer-icon {
            font-size: 3.5rem;
            margin-bottom: 20px;
            color: #e1bee7;
            animation: pulse 3s infinite;
        }
        
        .disclaimer-title {
            font-size: 1.8rem;
            margin-bottom: 20px;
            color: #ffffff;
        }
        
        .disclaimer-text {
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 30px;
            color: #f3e5f5;
        }
        
        .disclaimer-button {
            background: linear-gradient(to right, #e040fb, #7c4dff);
            border: none;
            border-radius: 50px;
            padding: 15px 40px;
            font-size: 1.2rem;
            font-weight: 600;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(124, 77, 255, 0.3);
            position: relative;
            overflow: hidden;
            transform: translateZ(0);
            will-change: transform;
        }
        
        .disclaimer-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 18px rgba(124, 77, 255, 0.4);
        }
        
        /* Стили для баннера "Soon..." */
        .soon-banner {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 300px;
            background: linear-gradient(135deg, rgba(38, 208, 206, 0.15), rgba(26, 41, 128, 0.25));
            border-radius: 20px;
            border: 2px solid rgba(255, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            margin: 20px 0;
        }
        
        .soon-banner::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(
                45deg, 
                transparent 0%, 
                transparent 46%, 
                rgba(255, 255, 255, 0.1) 49%, 
                rgba(255, 255, 255, 0.1) 51%, 
                transparent 53%, 
                transparent 100%
            );
            animation: shine 3s infinite linear;
            z-index: 0;
        }
        
        .soon-text {
            font-size: 5rem;
            font-weight: 800;
            background: linear-gradient(45deg, #ff00cc, #00ccff, #00ffcc, #ffcc00);
            background-size: 400% 400%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 15px rgba(255, 255, 255, 0.3);
            animation: gradient 4s ease infinite, pulse-glow 2s infinite alternate;
            position: relative;
            z-index: 1;
            letter-spacing: 2px;
        }
        
        /* Анимации для баннера */
        @keyframes gradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        @keyframes pulse-glow {
            0% { text-shadow: 0 0 10px rgba(255, 255, 255, 0.3); }
            100% { text-shadow: 0 0 25px rgba(255, 255, 255, 0.7), 0 0 40px rgba(100, 255, 255, 0.5); }
        }
        
        @keyframes shine {
            0% { transform: translate(-25%, -25%) rotate(0deg); }
            100% { transform: translate(-25%, -25%) rotate(360deg); }
        }
        
        /* Упрощенные анимации */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }
        
        @keyframes tabIndicator {
            from { width: 0; }
            to { width: 100%; }
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(15px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Адаптивность */
        @media (max-width: 768px) {
            .tabs {
                flex-direction: column;
            }
            
            .header {
                padding: 25px 15px;
            }
            
            h1 {
                font-size: 2.2rem;
            }
            
            .logo {
                font-size: 3.2rem;
            }
            
            .content {
                padding: 20px 15px;
                min-height: 350px;
            }
            
            .link-item {
                padding: 15px;
            }
            
            .link-item .title {
                font-size: 1.2rem;
            }
            
            .disclaimer-box {
                padding: 25px 15px;
            }
            
            .disclaimer-title {
                font-size: 1.5rem;
            }
            
            .disclaimer-text {
                font-size: 1rem;
            }
            
            /* Адаптивность баннера */
            .soon-banner {
                height: 200px;
            }
            
            .soon-text {
                font-size: 3.5rem;
            }
        }
        
        @media (max-width: 480px) {
            .soon-banner {
                height: 150px;
            }
            
            .soon-text {
                font-size: 2.5rem;
            }
        }
        
        /* Отключение анимаций для пользователей, предпочитающих уменьшенное движение */
        @media (prefers-reduced-motion) {
            * {
                animation: none !important;
                transition: none !important;
            }
            
            .soon-text {
                animation: none !important;
                background: linear-gradient(45deg, #ff00cc, #00ccff);
                text-shadow: none;
            }
            
            .soon-banner::before {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="disclaimer-overlay active">
        <div class="disclaimer-box">
            <div class="disclaimer-icon">🍪🤖</div>
            <h2 class="disclaimer-title">Важное уведомление!</h2>
            <p class="disclaimer-text">
                🍪 <strong>Внимание!</strong> Вы соглашаетесь с тем, что мы ведём сбор Куки. 
                Этот сайт сгенерирован нейронкой DeepSeek 🤖 и не имеет реального замысла! 
                ⚠️ Сайт не нарушает законы РФ.
            </p>
            <button class="disclaimer-button">Я согласен! ✅</button>
        </div>
    </div>
    
    <div class="bubble"></div>
    <div class="bubble"></div>
    
    <div class="container">
        <div class="header">
            <div class="logo">✨</div>
            <h1>EveryDay the best</h1>
            <p>EveryDay bio</p>
            <p>Заместитель создателя канала PrankVZ</p>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="general">
                <i class="fas fa-home"></i> General
            </div>
            <div class="tab" data-tab="nft">
                <i class="fas fa-coins"></i> NFT
            </div>
            <div class="tab" data-tab="softs">
                <i class="fas fa-download"></i> Softs
            </div>
        </div>
        
        <div class="content">
            <div class="tab-content active" id="general">
                <ul class="link-list">
                    <li class="link-item" data-url="https://t.me/prankvz">
                        <i class="fab fa-telegram"></i>
                        <div class="text">
                            <div class="title">Канал Telegram 📢</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://t.me/mobile_everyday">
                        <i class="fab fa-telegram"></i>
                        <div class="text">
                            <div class="title">Telegram Everyday 💬</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://t.me/prankvzbot">
                        <i class="fas fa-robot"></i>
                        <div class="text">
                            <div class="title">Бот PrankVZ 🤖</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://t.me/+gUAplPwH9GhiMDg1">
                        <i class="fas fa-comments"></i>
                        <div class="text">
                            <div class="title">Чат сообщества 👥</div>
                        </div>
                    </li>
                </ul>
            </div>
            
            <div class="tab-content" id="nft">
                <!-- Удалены старые кнопки и добавлен новый баннер -->
                <div class="soon-banner">
                    <div class="soon-text">Soon...</div>
                </div>
            </div>
            
            <div class="tab-content" id="softs">
                <ul class="link-list">
                    <li class="link-item" data-url="https://drive.google.com/uc?export=download&id=1a4uqsLWD_5vCMNMDmr8Mr0mzh0OmtF6r">
                        <i class="fas fa-download"></i>
                        <div class="text">
                            <div class="title">Blue Hikvision 📥</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://drive.google.com/uc?export=download&id=1tVPe7sceTvmZJKL5Y0L1IrsgIwWIkUtk">
                        <i class="fas fa-server"></i>
                        <div class="text">
                            <div class="title">Ingram📥</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://drive.google.com/uc?export=download&id=1Kl9CvZn2qqTtJUi1toUZKnBKyrOG17Cx">
                        <i class="fas fa-key"></i>
                        <div class="text">
                            <div class="title">Generate Pass and User🔑</div>
                        </div>
                    </li>
                    <li class="link-item" data-url="https://drive.google.com/uc?export=download&id=1PrWY16XUyADSi6K5aT9YmN7xPsHI9Uhk">
                        <i class="fas fa-sun"></i>
                        <div class="text">
                            <div class="title">Noon🌞</div>
                        </div>
                    </li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>® 2025 EveryDay the best | Все права защищены</p>
            <p>by @mobile_everyday</p>
            <p>@jiarbuz gay</p>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // === Оптимизированные элементы DOM ===
            const disclaimerOverlay = document.querySelector('.disclaimer-overlay');
            const disclaimerButton = document.querySelector('.disclaimer-button');
            
            // === Проверка поддержки localStorage ===
            const supportsLocalStorage = (function() {
                try {
                    const test = '__localStorageTest__';
                    localStorage.setItem(test, test);
                    localStorage.removeItem(test);
                    return true;
                } catch(e) {
                    return false;
                }
            })();
            
            // === Управление дисклеймером ===
            if (supportsLocalStorage && localStorage.getItem('disclaimerAccepted')) {
                disclaimerOverlay.classList.remove('active');
            } else {
                disclaimerOverlay.classList.add('active');
            }
            
            disclaimerButton.addEventListener('click', function() {
                if (supportsLocalStorage) {
                    localStorage.setItem('disclaimerAccepted', 'true');
                }
                // Плавное скрытие с requestAnimationFrame
                const startTime = performance.now();
                const duration = 400;
                
                function animate(time) {
                    const elapsed = time - startTime;
                    const progress = Math.min(elapsed / duration, 1);
                    const opacity = 1 - progress;
                    disclaimerOverlay.style.opacity = opacity;
                    
                    if (progress < 1) {
                        requestAnimationFrame(animate);
                    } else {
                        disclaimerOverlay.style.visibility = 'hidden';
                        // Удаление из DOM для улучшения производительности
                        setTimeout(() => {
                            if (disclaimerOverlay.parentNode) {
                                disclaimerOverlay.parentNode.removeChild(disclaimerOverlay);
                            }
                        }, 100);
                    }
                }
                
                requestAnimationFrame(animate);
            });
            
            // === Переключение вкладок ===
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    if (this.classList.contains('active')) return;
                    
                    // Удаляем активный класс у всех вкладок
                    tabs.forEach(t => t.classList.remove('active'));
                    
                    // Добавляем активный класс к текущей вкладке
                    this.classList.add('active');
                    
                    // Прячем все контенты
                    document.querySelectorAll('.tab-content').forEach(c => {
                        c.classList.remove('active');
                    });
                    
                    // Показываем выбранный контент
                    const tabId = this.getAttribute('data-tab');
                    const content = document.getElementById(tabId);
                    if (content) {
                        // Задержка для анимации
                        setTimeout(() => {
                            content.classList.add('active');
                        }, 10);
                    }
                });
            });
            
            // === Обработка кликов по ссылкам ===
            const linkItems = document.querySelectorAll('.link-item[data-url]');
            linkItems.forEach(item => {
                item.addEventListener('click', function() {
                    const url = this.getAttribute('data-url');
                    if (!url) return;
                    
                    // Оптимизированная анимация клика с RAF
                    const startTime = performance.now();
                    const transformValues = [];
                    
                    function animateClick(time) {
                        const elapsed = time - startTime;
                        const progress = Math.min(elapsed / 300, 1);
                        const scale = 1 - (0.05 * Math.sin(progress * Math.PI));
                        
                        transformValues[0] = `scale(${scale})`;
                        transformValues[1] = progress > 0.5 ? 
                            `translateY(${-4 * (1 - progress) * 2}px)` : 
                            `translateY(${-4 * progress * 2}px)`;
                            
                        item.style.transform = transformValues.join(' ');
                        
                        if (progress < 1) {
                            requestAnimationFrame(animateClick);
                        } else {
                            item.style.transform = '';
                            window.open(url, '_blank');
                        }
                    }
                    
                    requestAnimationFrame(animateClick);
                });
            });
        });
    </script>
</body>
</html>














