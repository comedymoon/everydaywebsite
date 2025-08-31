<?php
declare(strict_types=1);
$cfg = require __DIR__.'/config.php';
require_once __DIR__.'/util.php';
header('Content-Type: application/json; charset=utf-8');
$raw = file_get_contents('php://input'); $data = json_decode($raw, true);
if (!is_array($data)) { http_response_code(400); echo '{"err":"bad json"}'; exit; }
$payload_b64 = $data['payload'] ?? ''; $sig_b64 = $data['sig'] ?? ''; $suffix = $data['suffix'] ?? '';
$payload_json = shield_base64url_decode($payload_b64); $sig_bin = shield_base64url_decode($sig_b64);
if (!$payload_json || !$sig_bin) { http_response_code(400); echo '{"err":"bad enc"}'; exit; }
if (!hash_equals($sig_bin, shield_sign($cfg['secret'], $payload_json))) { http_response_code(403); echo '{"err":"sig"}'; exit; }
$pl = json_decode($payload_json, true); if (!is_array($pl)) { http_response_code(400); echo '{"err":"payload"}'; exit; }
$now = shield_now(); if (($pl['ts'] ?? 0) > $now + 10 || ($pl['exp'] ?? 0) < $now) { http_response_code(403); echo '{"err":"expired"}'; exit; }
$uah_now = hash('sha256', shield_ua(), false); if (!hash_equals($uah_now, $pl['uah'] ?? '')) { http_response_code(403); echo '{"err":"ua"}'; exit; }
$ip_now  = shield_client_ip(); if (($pl['ip'] ?? '') !== $ip_now) { http_response_code(403); echo '{"err":"ip"}'; exit; }
$hex = hash('sha256', $payload_b64.'.'.$sig_b64.'.'.$suffix); $bits = (int)($pl['diff'] ?? 18);
if (!shield_prefix_bits_ok($hex, $bits)) { http_response_code(403); echo '{"err":"pow"}'; exit; }
$claims = array_merge(['ok'=>true,'iat'=>$now,'exp'=>$now+$cfg['ttl']], shield_bind_claims($cfg));
setcookie($cfg['cookie'], shield_cookie_value($cfg, $claims), ['expires'=>$claims['exp'],'path'=>'/','secure'=>(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off'),'httponly'=>true,'samesite'=>'Lax']);
echo '{"ok":true}';
