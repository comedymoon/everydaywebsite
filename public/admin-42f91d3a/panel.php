<?php
/**
 * Purple Admin Panel — PRO
 * Все в одном файле: временные/массовые/сети баны, белый список, импорт/экспорт, пагинация, бан из логов.
 */
declare(strict_types=1);
session_start();
if (!($_SESSION['admin'] ?? false)) {
    header('Location: login.php');
    exit;

$rootDir = dirname(__DIR__);
$configFile = $rootDir . '/storage/config.json';
function cfg_defaults() {
  return [
    'shield' => ['mode'=>'medium','ttl'=>3600,'window'=>120,'bind_ua'=>'loose','bind_ip'=>false],
    'ddos'   => ['limit_per_minute'=>60,'ban_minutes'=>30,'honeypot'=>true],
    'logger' => ['bot_token'=>'', 'chat_id'=>''],
  ];
}
function cfg_load($path) {
  if (!is_file($path)) return cfg_defaults();
  $raw = @file_get_contents($path);
  $j = $raw ? json_decode($raw, true) : null;
  if (!is_array($j)) $j = cfg_defaults();
  return array_replace_recursive(cfg_defaults(), $j);
}
function cfg_save($path, $data) {
  @file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}
$CFG = cfg_load($configFile);
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['_action'] ?? '') === 'save_settings') {
  if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['_csrf'] ?? '')) { http_response_code(403); exit('CSRF token mismatch'); }
  $shield = $CFG['shield'];
  $shield['mode']   = in_array($_POST['shield_mode'] ?? 'medium', ['low','medium','high'], true) ? $_POST['shield_mode'] : 'medium';
  $shield['ttl']    = max(60, (int)($_POST['shield_ttl'] ?? 3600));
  $shield['window'] = max(10, (int)($_POST['shield_window'] ?? 120));
  $shield['bind_ua'] = in_array($_POST['shield_bind_ua'] ?? 'loose', ['off','loose','strict'], true) ? $_POST['shield_bind_ua'] : 'loose';
  $shield['bind_ip'] = !!($_POST['shield_bind_ip'] ?? '');
  $ddos = $CFG['ddos'];
  $ddos['limit_per_minute'] = max(10, (int)($_POST['ddos_lpm'] ?? 60));
  $ddos['ban_minutes']      = max(1, (int)($_POST['ddos_ban'] ?? 30));
  $ddos['honeypot']         = !!($_POST['ddos_honeypot'] ?? '');
  $logger = $CFG['logger'];
  $logger['bot_token'] = trim((string)($_POST['logger_bot'] ?? ''));
  $logger['chat_id']   = trim((string)($_POST['logger_chat'] ?? ''));
  $CFG['shield'] = $shield; $CFG['ddos'] = $ddos; $CFG['logger'] = $logger;
  cfg_save($configFile, $CFG);
  $settings_saved = true;
}


}

$rootDir = dirname(__DIR__);
$banFile   = $rootDir.'/storage/banned.txt';
$whiteFile = $rootDir.'/storage/whitelist.txt';
$visitFile = $rootDir.'/storage/visits.log';
$debugFile = $rootDir.'/storage/debug.log';
$configFile  = __DIR__.'/config.json';

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf'];
function csrf_check($t){ if(!hash_equals($_SESSION['csrf']??'', (string)$t)){ http_response_code(400); exit('Bad CSRF'); } }

function safe_read_lines(string $p): array {
  if(!file_exists($p)) return [];
  $fh=fopen($p,'rb'); if(!$fh) return [];
  try{ flock($fh,LOCK_SH); $d=stream_get_contents($fh); flock($fh,LOCK_UN);} finally{ fclose($fh); }
  $l=preg_split('/\R/u',(string)$d,-1,PREG_SPLIT_NO_EMPTY); return array_values(array_map('trim',$l));
}
function safe_write_lines(string $p, array $lines): void {
  $tmp=$p.'.tmp'; $fh=fopen($tmp,'wb'); if(!$fh) throw new RuntimeException('write fail');
  try{ flock($fh,LOCK_EX); fwrite($fh,implode("\n",$lines).(count($lines)?"\n":"")); fflush($fh); flock($fh,LOCK_UN);} finally{ fclose($fh); }
  rename($tmp,$p);
}
function safe_truncate(string $p): void { $fh=fopen($p,'c+'); if(!$fh) return; try{ flock($fh,LOCK_EX); ftruncate($fh,0); fflush($fh); flock($fh,LOCK_UN);} finally{ fclose($fh);} }

function is_ip(string $v): bool { return (bool)filter_var($v, FILTER_VALIDATE_IP); }
function is_cidr(string $v): bool {
  if(!str_contains($v,'/')) return false;
  [$ip,$mask]=explode('/',$v,2); if(!is_ip($ip)) return false;
  return ctype_digit($mask) && (int)$mask>=0 && (int)$mask<= (str_contains($ip,':')?128:32);
}
function target_type(string $t): string { return is_ip($t)?'IP':(is_cidr($t)?'CIDR':'?'); }

/** Parse line: IP|REASON|COUNTRY|TS|EXP=...|NOTE=... */
function parse_line(string $line): array {
  $parts = array_map('trim', explode('|', $line));
  $out = ['raw'=>$line,'target'=>$parts[0]??'','reason'=>'','country'=>'','ts'=>'','exp'=>'','note'=>''];
  for($i=1;$i<count($parts);$i++){
    $v=$parts[$i];
    if (str_starts_with($v,'EXP=')) { $out['exp']=substr($v,4); continue; }
    if (str_starts_with($v,'NOTE=')){ $out['note']=substr($v,5); continue; }
    if ($out['reason']==='') { $out['reason']=$v; continue; }
    if ($out['country']==='') { $out['country']=$v; continue; }
    if ($out['ts']==='') { $out['ts']=$v; continue; }
  }
  if($out['ts']==='') $out['ts']='';
  return $out;
}
function render_line(array $e): string {
  $chunks = [$e['target']];
  if($e['reason']!=='')  $chunks[]=$e['reason'];
  if($e['country']!=='') $chunks[]=$e['country'];
  if($e['ts']!=='')      $chunks[]=$e['ts'];
  if($e['exp']!=='')     $chunks[]='EXP='.$e['exp'];
  if($e['note']!=='')    $chunks[]='NOTE='.$e['note'];
  return implode('|',$chunks);
}
function now_str(): string { return date('Y-m-d H:i:s'); }
function add_minutes(string $ts, int $m): string { return date('Y-m-d H:i:s', strtotime($ts." +{$m} minutes")); }

/** Purge expired entries (ban list) */
function purge_expired(array $rows): array {
  $now = strtotime(now_str());
  $out=[];
  foreach($rows as $e){
    if($e['exp']!==''){
      $expts = strtotime($e['exp']); if($expts!==false && $expts<$now) continue;
    }
    $out[]=$e;
  }
  return $out;
}

/** Unique by target (IP/CIDR) */
function unique_by_target(array $rows): array {
  $seen=[]; $out=[];
  foreach($rows as $e){ $t=$e['target']; if(!$t) continue; if(isset($seen[$t])) continue; $seen[$t]=1; $out[]=$e; }
  return $out;
}

function load_config(string $p): array {
  $cfg=['mode'=>'medium'];
  if(file_exists($p)){
    $raw=@file_get_contents($p); $j=@json_decode($raw,true);
    if(is_array($j)) $cfg=array_merge($cfg,$j);
  }
  return $cfg;
}
function save_config(string $p, array $cfg): void {
  $tmp=$p.'.tmp'; file_put_contents($tmp, json_encode($cfg, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)); rename($tmp,$p);
}

/* ===== Handle POST ===== */
if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_check($_POST['_csrf']??'');
  $act=$_POST['_action']??'';

  if($act==='set_mode'){
    $mode = in_array($_POST['mode']??'medium',['low','medium','high'],true)? $_POST['mode']:'medium';
    $cfg = load_config($configFile); $cfg['mode']=$mode; save_config($configFile,$cfg);
    header('Location: panel.php?ok=mode'); exit;
  }

  if($act==='ban_add'){
    $target=trim((string)($_POST['target']??'')); $reason=trim((string)($_POST['reason']??'')); $country=trim((string)($_POST['country']??'')); $note=trim((string)($_POST['note']??''));
    $ttl=(int)($_POST['ttl']??0); $custom_minutes=(int)($_POST['ttl_custom']??0);
    if(!($isValid = (is_ip($target)||is_cidr($target)))) { header('Location: panel.php?err=bad_target'); exit; }
    $ts = now_str();
    $exp=''; if($ttl>0){ $exp = add_minutes($ts,$ttl); } elseif($custom_minutes>0){ $exp = add_minutes($ts,$custom_minutes); }
    $entry = ['target'=>$target,'reason'=>$reason,'country'=>$country,'ts'=>$ts,'exp'=>$exp,'note'=>$note];
    $rows = array_map('parse_line', safe_read_lines($banFile));
    $rows[]=$entry;
    $rows = purge_expired(unique_by_target($rows));
    $lines=array_map('render_line',$rows);
    safe_write_lines($banFile,$lines);
    header('Location: panel.php?ok=ban'); exit;
  }

  if($act==='ban_bulk'){
    $bulk = (string)($_POST['bulk']??'');
    $rows = array_map('parse_line', safe_read_lines($banFile));
    $ts = now_str();
    foreach(preg_split('/\R/u',$bulk) as $ln){
      $ln=trim($ln); if($ln==='') continue;
      // allow "target|reason|country|exp=YYYY-mm-dd HH:MM:SS|note=..."
      $e = parse_line($ln);
      if(!$e['target']) continue;
      if(!(is_ip($e['target'])||is_cidr($e['target']))) continue;
      if($e['ts']==='') $e['ts']=$ts;
      $rows[]=$e;
    }
    $rows=purge_expired(unique_by_target($rows));
    $lines=array_map('render_line',$rows);
    safe_write_lines($banFile,$lines);
    header('Location: panel.php?ok=bulk'); exit;
  }

  if($act==='unban_one'){
    $t=trim((string)($_POST['target']??'')); if($t!==''){
      $rows=array_map('parse_line', safe_read_lines($banFile));
      $rows=array_values(array_filter($rows,fn($e)=>$e['target']!==$t));
      safe_write_lines($banFile, array_map('render_line',$rows));
    }
    header('Location: panel.php?ok=unban'); exit;
  }

  if($act==='unban_bulk'){
    $sel=(array)($_POST['targets']??[]);
    if($sel){
      $rows=array_map('parse_line', safe_read_lines($banFile));
      $rows=array_values(array_filter($rows,fn($e)=>!in_array($e['target'],$sel,true)));
      safe_write_lines($banFile, array_map('render_line',$rows));
    }
    header('Location: panel.php?ok=unban_bulk'); exit;
  }

  if($act==='unban_all'){
    safe_write_lines($banFile, []);
    header('Location: panel.php?ok=unban_all'); exit;
  }

  if($act==='white_add'){
    $t=trim((string)($_POST['white_target']??'')); if(is_ip($t)||is_cidr($t)){
      $lines=safe_read_lines($whiteFile); $lines[]=$t; $lines=array_values(array_unique(array_map('trim',$lines)));
      safe_write_lines($whiteFile,$lines);
    }
    header('Location: panel.php?ok=white_add'); exit;
  }
  if($act==='white_del'){
    $t=trim((string)($_POST['white_target']??'')); if($t!==''){
      $lines=safe_read_lines($whiteFile);
      $lines=array_values(array_filter($lines,fn($x)=>$x!==$t));
      safe_write_lines($whiteFile,$lines);
    }
    header('Location: panel.php?ok=white_del'); exit;
  }

  if($act==='clear_visits'){ safe_truncate($visitFile); header('Location: panel.php?ok=cv'); exit; }
  if($act==='clear_debug'){ safe_truncate($debugFile); header('Location: panel.php?ok=cd'); exit; }

  if($act==='export_json'){
    $rows=array_map('parse_line', safe_read_lines($banFile));
    $rows=purge_expired($rows);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="bans.json"');
    echo json_encode($rows, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE); exit;
  }
  if($act==='export_csv'){
    $rows=array_map('parse_line', safe_read_lines($banFile));
    $rows=purge_expired($rows);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="bans.csv"');
    $out=fopen('php://output','w');
    fputcsv($out,['target','type','reason','country','ts','exp','note']);
    foreach($rows as $e){ fputcsv($out,[$e['target'],target_type($e['target']),$e['reason'],$e['country'],$e['ts'],$e['exp'],$e['note']]); }
    fclose($out); exit;
  }
  if($act==='import_file' && isset($_FILES['file'])){
    $tmp=$_FILES['file']['tmp_name']??''; if(is_uploaded_file($tmp)){
      $data=file_get_contents($tmp);
      $newLines=[];
      if (str_ends_with(strtolower($_FILES['file']['name']??''),'.json')){
        $arr=@json_decode($data,true); if(is_array($arr)){
          foreach($arr as $e){
            $e=['target'=>$e['target']??'','reason'=>$e['reason']??'','country'=>$e['country']??'','ts'=>$e['ts']??now_str(),'exp'=>$e['exp']??'','note'=>$e['note']??''];
            if(!$e['target']) continue; if(!(is_ip($e['target'])||is_cidr($e['target']))) continue;
            $newLines[]=render_line($e);
          }
        }
      } else { // treat as text/CSV lines
        foreach(preg_split('/\R/u',(string)$data) as $ln){
          $ln=trim($ln); if($ln==='') continue;
          $e=parse_line($ln); if(!$e['target']) continue;
          if(!(is_ip($e['target'])||is_cidr($e['target']))) continue;
          if($e['ts']==='') $e['ts']=now_str();
          $newLines[]=render_line($e);
        }
      }
      $rows=array_map('parse_line', safe_read_lines($banFile));
      foreach($newLines as $l) $rows[]=parse_line($l);
      $rows=purge_expired(unique_by_target($rows));
      safe_write_lines($banFile, array_map('render_line',$rows));
    }
    header('Location: panel.php?ok=import'); exit;
  }

  if($act==='ban_from_log'){
    $ip=trim((string)($_POST['ip']??'')); if(is_ip($ip)){
      $ts=now_str(); $e=['target'=>$ip,'reason'=>trim((string)($_POST['reason']??'LOG')),'country'=>'','ts'=>$ts,'exp'=>'','note'=>'from visits.log'];
      $rows=array_map('parse_line', safe_read_lines($banFile)); $rows[]=$e;
      $rows=purge_expired(unique_by_target($rows));
      safe_write_lines($banFile, array_map('render_line',$rows));
    }
    header('Location: panel.php?ok=banlog'); exit;
  }

  header('Location: panel.php'); exit;
}

/* ===== Load data for UI ===== */
$cfg = load_config($configFile);
$mode = $cfg['mode'] ?? 'medium';

$bans = array_map('parse_line', safe_read_lines($banFile));
$bans = purge_expired($bans);
$bans = unique_by_target($bans);
safe_write_lines($banFile, array_map('render_line',$bans)); // persist purge/unique

$whites = safe_read_lines($whiteFile);

$visits = safe_read_lines($visitFile);
$debugs = safe_read_lines($debugFile);

/* Pagination helpers */
function paginate(array $arr, int $per, int $page): array {
  $total = max(1, (int)ceil(count($arr)/$per));
  $page = max(1, min($page, $total));
  $off = ($page-1)*$per;
  return ['slice'=>array_slice($arr,$off,$per), 'page'=>$page, 'total'=>$total];
}
$banPage = max(1,(int)($_GET['bp']??1));
$logPage = max(1,(int)($_GET['lp']??1));
$dbgPage = max(1,(int)($_GET['dp']??1));

$perBans=200; $perLogs=300; $perDbg=300;
$banPg = paginate($bans, $perBans, $banPage);
$visPg = paginate(array_reverse($visits), $perLogs, $logPage);  // последние сверху
$dbgPg = paginate(array_reverse($debugs), $perDbg, $dbgPage);

/* Extract IPs from visible visit lines */
function extract_ip(string $s): ?string {
  if(preg_match('/(?:(?:\d{1,3}\.){3}\d{1,3})/', $s, $m)) return $m[0];
  return null;
}
?>
<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Purple Admin PRO</title>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{ --bg1:#12091f; --bg2:#3a0f6e; --glass:rgba(255,255,255,.08); --stroke:rgba(255,255,255,.18);
       --text:#f4eaff; --muted:#bda7ff; --accent1:#8a2be2; --accent2:#b06ab3; --danger:#ff4b2b; --ok:#3ddc97; }
*{box-sizing:border-box} body{margin:0;background:linear-gradient(135deg,var(--bg1),var(--bg2));
font-family:Montserrat,system-ui,sans-serif;color:var(--text);min-height:100vh;padding:22px;display:flex;justify-content:center}
.container{width:min(1280px,100%);background:var(--glass);border:1px solid var(--stroke);backdrop-filter:blur(14px);
border-radius:18px;box-shadow:0 30px 80px rgba(0,0,0,.35);overflow:hidden}
.header{padding:20px;border-bottom:1px solid var(--stroke);display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.h1{font-size:22px;background:linear-gradient(90deg,var(--accent2),#a8c0ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0}
.sub{color:var(--muted);font-size:12px}
.grid{display:grid;gap:16px;padding:16px;grid-template-columns:1fr}
@media(min-width:1000px){.grid{grid-template-columns:1.2fr .8fr}}
.card{background:rgba(0,0,0,.25);border:1px solid var(--stroke);border-radius:14px;padding:14px}
.card h2{margin:0 0 10px;color:#e8d7ff;font-size:18px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.input,select,.file{flex:1;min-width:160px;padding:10px 12px;border-radius:10px;border:1px solid var(--stroke);background:rgba(255,255,255,.06);color:var(--text)}
.btn{padding:10px 14px;border-radius:10px;border:1px solid transparent;background:linear-gradient(90deg,var(--accent1),#9932cc);color:#fff;font-weight:700;cursor:pointer}
.btn:hover{filter:brightness(1.08)} .btn-ghost{background:rgba(255,255,255,.06);border-color:var(--stroke)}
.btn-danger{background:linear-gradient(90deg,var(--danger),#ff416c)} .btn-ok{background:linear-gradient(90deg,var(--ok),#41e0a8);color:#000}
.meta{color:var(--muted);font-size:12px} .sep{height:1px;background:var(--stroke);margin:10px 0}
.table{width:100%;border-collapse:collapse} .table th,.table td{padding:8px 10px;border-bottom:1px solid var(--stroke);font-size:13px;text-align:left}
.table th{color:#d7b9ff;cursor:pointer;user-select:none}
.badge{display:inline-block;border:1px solid var(--stroke);border-radius:999px;padding:2px 8px;font-size:12px}
.badge.ok{color:#c3ffea;border-color:rgba(61,220,151,.5)} .badge.warn{color:#ffe1b0;border-color:rgba(255,205,100,.4)}
.logs{max-height:360px;overflow:auto;background:rgba(0,0,0,.35);border:1px solid var(--stroke);border-radius:10px;padding:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:pre-wrap}
.listbox{max-height:420px;overflow:auto;border:1px solid var(--stroke);border-radius:10px}
.tools{display:flex;gap:10px;flex-wrap:wrap}
.controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.pager{display:flex;gap:8px;align-items:center}
.link{color:#c8a7ff;text-decoration:none} .link:hover{text-decoration:underline}
.code{font-family:ui-monospace,Menlo,Consolas,monospace}
.copy{cursor:pointer}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1 class="h1">Purple Admin PRO</h1>
    <div class="sub">Режим: <span class="badge"><?=htmlspecialchars($mode)?></span> • Банов: <b><?=count($bans)?></b> • Белый список: <b><?=count($whites)?></b></div>
    <form method="post" class="row" style="margin:0">
      <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="set_mode">
      <select name="mode" class="input" style="max-width:140px">
        <option value="low"    <?=$mode==='low'?'selected':''?>>low</option>
        <option value="medium" <?=$mode==='medium'?'selected':''?>>medium</option>
        <option value="high"   <?=$mode==='high'?'selected':''?>>high</option>
      </select>
      <button class="btn btn-ok">Сохранить</button>
    </form>
  </div>

  <div class="grid">
    <!-- БЛОК БАНОВ -->
    <div class="card">
      <h2>Баны (IP/CIDR) — добавить</h2>
      <form method="post" class="row" autocomplete="off">
        <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="ban_add">
        <input class="input" name="target" placeholder="IP (1.2.3.4) или CIDR (1.2.3.0/24)" required>
        <input class="input" name="reason" placeholder="Причина (DDOS / LOCATION / ... )">
        <input class="input" name="country" placeholder="Страна (опц.)">
        <input class="input" name="note" placeholder="Заметка (опц.)">
        <select class="input" name="ttl" style="max-width:180px">
          <option value="0">Навсегда</option>
          <option value="60">1 час</option>
          <option value="1440">24 часа</option>
          <option value="10080">7 дней</option>
        </select>
        <input class="input" name="ttl_custom" type="number" min="0" placeholder="Кастом (мин)">
        <button class="btn">Забанить</button>
      </form>
      <div class="sep"></div>
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="ban_bulk">
        <div class="row">
          <textarea class="input" name="bulk" rows="4" placeholder="Массово: по строке
1.2.3.4|DDOS|UA|2025-08-18 23:00:00|EXP=2025-08-19 23:00:00|NOTE=bot
10.0.0.0/8|LOCATION|||EXP=2025-08-25 00:00:00"></textarea>
        </div>
        <div class="row"><button class="btn">Добавить списком</button><span class="meta">Поддерживает IP и CIDR, поля разделены «|»</span></div>
      </form>

      <div class="sep"></div>
      <div class="controls">
        <input id="banSearch" class="input" placeholder="Поиск по любой колонке...">
        <form method="post" style="margin:0">
          <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="unban_all">
          <button class="btn btn-danger" onclick="return confirm('Точно снять все баны?')">Разбанить всё</button>
        </form>
        <form method="post" style="margin:0">
          <input type="hidden" name="_csrf" value="<?=$CSRF?>">
          <input type="hidden" name="_action" value="export_json">
          <button class="btn btn-ghost">Export JSON</button>
        </form>
        <form method="post" style="margin:0">
          <input type="hidden" name="_csrf" value="<?=$CSRF?>">
          <input type="hidden" name="_action" value="export_csv">
          <button class="btn btn-ghost">Export CSV</button>
        </form>
        <form method="post" enctype="multipart/form-data" style="margin:0" onsubmit="return confirm('Импорт заменит совпадающие цели (IP/CIDR). Продолжить?')">
          <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="import_file">
          <input class="file" type="file" name="file" accept=".txt,.csv,.json">
          <button class="btn">Импорт</button>
        </form>
      </div>

      <div class="listbox" style="margin-top:10px">
        <form method="post" id="bulkUnbanForm">
          <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="unban_bulk">
          <table class="table" id="banTable">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" id="checkAll"></th>
                <th data-s="target">Цель</th>
                <th data-s="type">Тип</th>
                <th data-s="reason">Причина</th>
                <th data-s="country">Страна</th>
                <th data-s="ts">Когда</th>
                <th data-s="exp">До</th>
                <th data-s="note">Заметка</th>
                <th>Действие</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach($banPg['slice'] as $e): $typ=target_type($e['target']); ?>
              <tr>
                <td><input type="checkbox" name="targets[]" value="<?=htmlspecialchars($e['target'])?>"></td>
                <td class="code copy" title="Скопировать"><?=$e['target']?htmlspecialchars($e['target']):'-'?></td>
                <td><?=$typ?></td>
                <td><?=htmlspecialchars($e['reason']?:'-')?></td>
                <td><?=htmlspecialchars($e['country']?:'-')?></td>
                <td><span class="meta"><?=htmlspecialchars($e['ts']?:'-')?></span></td>
                <td><span class="badge <?=($e['exp']&&strtotime($e['exp'])>time())?'ok':'warn'?>"><?=htmlspecialchars($e['exp']?:'-')?></span></td>
                <td><?=htmlspecialchars($e['note']?:'')?></td>
                <td>
                  <form method="post" style="display:inline" onsubmit="return confirm('Разбанить <?=$e['target']?>?')">
                    <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="unban_one">
                    <input type="hidden" name="target" value="<?=htmlspecialchars($e['target'])?>">
                    <button class="btn btn-ghost">Разбанить</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </form>
      </div>
      <div class="row" style="justify-content:space-between;margin-top:8px">
        <div class="pager">
          <a class="link" href="?bp=1">&laquo; В начало</a>
          <a class="link" href="?bp=<?=max(1,$banPg['page']-1)?>">&lsaquo; Назад</a>
          <span class="meta">Стр. <?=$banPg['page']?> / <?=$banPg['total']?></span>
          <a class="link" href="?bp=<?=min($banPg['total'],$banPg['page']+1)?>">Вперёд &rsaquo;</a>
          <a class="link" href="?bp=<?=$banPg['total']?>">В конец &raquo;</a>
        </div>
        <div class="tools">
          <button class="btn btn-danger" form="bulkUnbanForm" onclick="return confirm('Разбанить отмеченные?')">Массовый разбан</button>
        </div>
      </div>
    </div>

    <!-- БЕЛЫЙ СПИСОК -->
    <div class="card">
      <h2>Белый список</h2>
      <form method="post" class="row">
        <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="white_add">
        <input class="input" name="white_target" placeholder="IP или CIDR">
        <button class="btn btn-ok">Добавить</button>
      </form>
      <div class="listbox" style="margin-top:10px">
        <table class="table">
          <thead><tr><th>Цель</th><th>Тип</th><th>Действие</th></tr></thead>
          <tbody>
            <?php if(!$whites): ?>
              <tr><td colspan="3" class="meta">Пусто</td></tr>
            <?php else: foreach($whites as $w): ?>
              <tr>
                <td class="code copy"><?=$w?></td>
                <td><?=target_type($w)?></td>
                <td>
                  <form method="post" style="display:inline" onsubmit="return confirm('Удалить из белого: <?=$w?> ?')">
                    <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="white_del">
                    <input type="hidden" name="white_target" value="<?=htmlspecialchars($w)?>">
                    <button class="btn btn-ghost">Удалить</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ЛОГИ -->
    <div class="card">
      <h2>Логи посещений</h2>
      <form method="post" class="row" onsubmit="return confirm('Очистить visits.log?')">
        <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="clear_visits">
        <button class="btn btn-danger">Очистить</button>
      </form>
      <div class="logs">
<?php foreach($visPg['slice'] as $line):
  $ip = extract_ip($line);
  $safe = htmlspecialchars($line);
  if($ip): ?>
<div><?=$safe?> —
  <form method="post" style="display:inline">
    <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="ban_from_log">
    <input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>">
    <input type="hidden" name="reason" value="LOG">
    <button class="btn btn-ghost" title="Забанить <?=$ip?>">бан</button>
  </form>
</div>
<?php else: ?>
<div><?=$safe?></div>
<?php endif; endforeach; ?>
      </div>
      <div class="pager" style="margin-top:8px">
        <a class="link" href="?lp=1">&laquo;</a>
        <a class="link" href="?lp=<?=max(1,$visPg['page']-1)?>">&lsaquo;</a>
        <span class="meta">Стр. <?=$visPg['page']?> / <?=$visPg['total']?></span>
        <a class="link" href="?lp=<?=min($visPg['total'],$visPg['page']+1)?>">&rsaquo;</a>
        <a class="link" href="?lp=<?=$visPg['total']?>">&raquo;</a>
      </div>
    </div>

    <div class="card">
      <h2>Debug (Telegram)</h2>
      <form method="post" class="row" onsubmit="return confirm('Очистить debug.log?')">
        <input type="hidden" name="_csrf" value="<?=$CSRF?>"><input type="hidden" name="_action" value="clear_debug">
        <button class="btn btn-danger">Очистить</button>
      </form>
      <div class="logs"><?php foreach($dbgPg['slice'] as $line){ echo htmlspecialchars($line)."\n"; } ?></div>
      <div class="pager" style="margin-top:8px">
        <a class="link" href="?dp=1">&laquo;</a>
        <a class="link" href="?dp=<?=max(1,$dbgPg['page']-1)?>">&lsaquo;</a>
        <span class="meta">Стр. <?=$dbgPg['page']?> / <?=$dbgPg['total']?></span>
        <a class="link" href="?dp=<?=min($dbgPg['total'],$dbgPg['page']+1)?>">&rsaquo;</a>
        <a class="link" href="?dp=<?=$dbgPg['total']?>">&raquo;</a>
      </div>
    </div>
  </div>

  <div style="padding:12px 16px;border-top:1px solid var(--stroke);display:flex;justify-content:space-between;align-items:center">
    <span class="meta">&copy; <?=date('Y')?> • Purple Admin PRO</span>
    <a class="link" href="logout.php">Выйти</a>
  </div>
</div>

<script>
/* Поиск по таблице банов */
const banSearch = document.getElementById('banSearch');
const banRows = Array.from(document.querySelectorAll('#banTable tbody tr'));
banSearch?.addEventListener('input', e=>{
  const term = e.target.value.toLowerCase();
  banRows.forEach(tr=>{
    tr.style.display = tr.innerText.toLowerCase().includes(term) ? '' : 'none';
  });
});
/* Копирование */
document.querySelectorAll('.copy').forEach(el=>{
  el.addEventListener('click', ()=>{
    navigator.clipboard.writeText(el.textContent.trim());
    el.style.opacity=.6; setTimeout(()=>el.style.opacity=1,250);
  });
});
/* Чекбокс "все" */
const checkAll=document.getElementById('checkAll');
checkAll?.addEventListener('change',()=>{
  document.querySelectorAll('#banTable tbody input[type=checkbox]').forEach(cb=>cb.checked=checkAll.checked);
});
/* Сортировка */
document.querySelectorAll('#banTable th[data-s]').forEach(th=>{
  th.addEventListener('click',()=>{
    const idx = Array.from(th.parentNode.children).indexOf(th);
    const tbody = th.closest('table').querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr')).filter(r=>r.style.display!=='none');
    const asc = th.dataset.asc === '1' ? false : true; th.dataset.asc = asc ? '1':'0';
    rows.sort((a,b)=> (a.children[idx].innerText.trim()).localeCompare(b.children[idx].innerText.trim(), undefined, {numeric:true}));
    if(!asc) rows.reverse();
    rows.forEach(r=>tbody.appendChild(r));
  });
});
</script>
<div class="card" style="margin-top:18px">
  <h2 class="h2">Настройки</h2>
  <?php if (!empty($settings_saved)) { echo '<div class="badge" style="background:#2e7d32">Сохранено</div>'; } ?>
  <form method="post">
    <input type="hidden" name="_csrf" value="<?=$CSRF?>">
    <input type="hidden" name="_action" value="save_settings">
    <div class="row">
      <div class="col">
        <h3>Shield</h3>
        <label>Mode</label>
        <select name="shield_mode" class="input">
          <option value="low" <?=$CFG['shield']['mode']==='low'?'selected':''?>>low</option>
          <option value="medium" <?=$CFG['shield']['mode']==='medium'?'selected':''?>>medium</option>
          <option value="high" <?=$CFG['shield']['mode']==='high'?'selected':''?>>high</option>
        </select>
        <label>TTL (сек)</label>
        <input class="input" type="number" name="shield_ttl" value="<?=htmlspecialchars((string)$CFG['shield']['ttl'])?>">
        <label>Window (сек)</label>
        <input class="input" type="number" name="shield_window" value="<?=htmlspecialchars((string)$CFG['shield']['window'])?>">
        <label>Bind UA</label>
        <select name="shield_bind_ua" class="input">
          <option value="off" <?=$CFG['shield']['bind_ua']==='off'?'selected':''?>>off</option>
          <option value="loose" <?=$CFG['shield']['bind_ua']==='loose'?'selected':''?>>loose</option>
          <option value="strict" <?=$CFG['shield']['bind_ua']==='strict'?'selected':''?>>strict</option>
        </select>
        <label><input type="checkbox" name="shield_bind_ip" <?=$CFG['shield']['bind_ip']?'checked':''?>> Привязка к IP</label>
      </div>
      <div class="col">
        <h3>DDoS</h3>
        <label>Лимит в минуту</label>
        <input class="input" type="number" name="ddos_lpm" value="<?=htmlspecialchars((string)$CFG['ddos']['limit_per_minute'])?>">
        <label>Бан (мин)</label>
        <input class="input" type="number" name="ddos_ban" value="<?=htmlspecialchars((string)$CFG['ddos']['ban_minutes'])?>">
        <label><input type="checkbox" name="ddos_honeypot" <?=$CFG['ddos']['honeypot']?'checked':''?>> Honeypot включён</label>
        <h3 style="margin-top:16px">Logger</h3>
        <label>Bot token</label>
        <input class="input" type="text" name="logger_bot" value="<?=htmlspecialchars($CFG['logger']['bot_token'])?>">
        <label>Chat ID</label>
        <input class="input" type="text" name="logger_chat" value="<?=htmlspecialchars($CFG['logger']['chat_id'])?>">
      </div>
    </div>
    <button class="btn btn-ok" style="margin-top:12px">Сохранить</button>
  </form>
</div>
</body></html>
