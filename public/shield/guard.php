<?php
$__shield_cfg = require __DIR__.'/config.php';
require_once __DIR__.'/util.php';

$cookieName = $__shield_cfg['cookie'];
$cookie = $_COOKIE[$cookieName] ?? null;
$now = shield_now();

if ($cookie) {
  $claims = shield_cookie_parse($__shield_cfg['secret'], $cookie);
  if ($claims && isset($claims['exp']) && $claims['exp'] > $now && shield_claims_match($__shield_cfg, $claims)) {
    $claims['exp'] = $now + $__shield_cfg['ttl'];
    setcookie($cookieName, shield_cookie_value($__shield_cfg, $claims), [
      'expires' => $claims['exp'],'path'=>'/',
      'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
      'httponly' => true,'samesite' => 'Lax',
    ]);
    return;
  }
}

$payload = [
  'ts'=>$now,'exp'=>$now+$__shield_cfg['challenge_window'],
  'ip'=>shield_client_ip(),'uah'=>hash('sha256', shield_ua(), false),
  'diff'=>shield_difficulty($__shield_cfg['mode']),'rnd'=>bin2hex(random_bytes(8))
];
$json = json_encode($payload, JSON_UNESCAPED_SLASHES);
$sig  = shield_base64url_encode(shield_sign($__shield_cfg['secret'], $json));
$pld  = shield_base64url_encode($json);

http_response_code(403);
header('Content-Type: text/html; charset=utf-8');
?><!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Проверка браузера…</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial;background:#0f1226;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{width:min(640px,92vw);background:#161a36;border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.35)}.h{font-size:20px;margin:0 0 8px}.sub{opacity:.8;margin:0 0 14px}.bar{height:6px;background:#1f244b;border-radius:999px;overflow:hidden;margin:14px 0 8px}.fill{height:100%;width:0%;background:#5aa0ff;transition:width .2s}.meta{font-size:12px;opacity:.7;margin-top:8px}</style>
</head><body><div class="card"><div class="h">Идёт проверка браузера…</div><div class="sub">Обычно занимает секунду. Не закрывайте страницу.</div>
<div class="bar"><div class="fill" id="bar"></div></div><div class="meta" id="meta">Подготовка…</div></div>
<script>
const META=document.getElementById('meta'); const BAR=document.getElementById('bar');
const payload='<?= $pld ?>', sig='<?= $sig ?>';
function hex(b){return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function sha256Hex(str){const enc=new TextEncoder().encode(str); const buf=await crypto.subtle.digest('SHA-256',enc); return hex(buf);}
(async () => {
  try {
    META.textContent='Решение задачи…';
    let counter=0,last=0,done=false; const diff=JSON.parse(atob(payload.replace(/-/g,'+').replace(/_/g,'/'))).diff||18;
    while(!done){
      const suffix=(counter++).toString(16).padStart(8,'0')+Math.random().toString(16).slice(2,10);
      const h=await sha256Hex(payload+'.'+sig+'.'+suffix);
      let ok=true; const nibbles=Math.floor(diff/4), rem=diff%4;
      if(h.slice(0,nibbles)!=='0'.repeat(nibbles)) ok=false;
      if(ok && rem){ const next=parseInt(h[nibbles],16); const limit=8>>(rem-1); if(!(next<limit)) ok=false; }
      if(ok){
        done=true;
        const resp=await fetch('/shield/verify.php',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload,sig,suffix})});
        if(resp.ok){ location.reload(); } else { META.textContent='Не удалось подтвердить. Обновите страницу.'; }
      }
      const now=performance.now(); if(now-last>150){ last=now; const p=Math.min(90, Math.log2(counter+2)/diff*100); BAR.style.width=p.toFixed(1)+'%'; }
      await new Promise(r=>setTimeout(r,0));
    }
  } catch(e){ META.textContent='Браузер не поддерживает WebCrypto. Откройте в современном браузере.'; }
})();
</script></body></html><?php exit;
