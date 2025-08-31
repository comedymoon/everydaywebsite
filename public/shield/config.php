<?php
function shield_default_config() : array {
  return [
    'secret' => getenv('SHIELD_SECRET') ?: 'CHANGE_ME_SUPER_SECRET_HEX',
    'mode'   => 'medium',
    'cookie' => getenv('SHIELD_COOKIE') ?: 'shield',
    'ttl'    => 3600,
    'challenge_window' => 120,
    'bind_ua' => 'loose',
    'bind_ip' => false,
  ];
}
function shield_load_config() : array {
  $root = dirname(__DIR__, 2);
  $jsonFile = $root . '/storage/config.json';
  $cfg = shield_default_config();
  if (is_file($jsonFile)) {
    $raw = @file_get_contents($jsonFile);
    $j = $raw ? json_decode($raw, true) : null;
    if (is_array($j) && isset($j['shield']) && is_array($j['shield'])) {
      $map = ['mode'=>'mode','ttl'=>'ttl','window'=>'challenge_window','bind_ua'=>'bind_ua','bind_ip'=>'bind_ip'];
      foreach ($map as $from=>$to) if (array_key_exists($from, $j['shield'])) $cfg[$to] = $j['shield'][$from];
    }
  }
  if ($x = getenv('SHIELD_MODE')) $cfg['mode'] = $x;
  if (($x = getenv('SHIELD_TTL')) !== false) $cfg['ttl'] = (int)$x;
  if (($x = getenv('SHIELD_WINDOW')) !== false) $cfg['challenge_window'] = (int)$x;
  if ($x = getenv('SHIELD_BIND_UA')) $cfg['bind_ua'] = $x;
  if (($x = getenv('SHIELD_BIND_IP')) !== false) $cfg['bind_ip'] = (bool)$x;
  return $cfg;
}
return shield_load_config();
