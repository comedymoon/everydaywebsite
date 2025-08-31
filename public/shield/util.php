<?php
function shield_client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }
function shield_ua(): string { return $_SERVER['HTTP_USER_AGENT'] ?? ''; }
function shield_now(): int { return time(); }

function shield_base64url_encode(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function shield_base64url_decode(string $txt): string {
  $pad = strlen($txt) % 4; if ($pad) $txt .= str_repeat('=', 4 - $pad);
  return base64_decode(strtr($txt, '-_', '+/'));
}

function shield_sign(string $secret, string $payload): string { return hash_hmac('sha256', $payload, $secret, true); }

function shield_cookie_value(array $cfg, array $claims): string {
  $json = json_encode($claims, JSON_UNESCAPED_SLASHES);
  $sig  = shield_sign($cfg['secret'], $json);
  return shield_base64url_encode($json) . '.' . shield_base64url_encode($sig);
}

function shield_cookie_parse(string $secret, string $cookie) {
  $parts = explode('.', $cookie, 2);
  if (count($parts) !== 2) return null;
  [$b64json, $b64sig] = $parts;
  $json = shield_base64url_decode($b64json);
  $sig  = shield_base64url_decode($b64sig);
  if (!hash_equals($sig, shield_sign($secret, $json))) return null;
  $claims = json_decode($json, true);
  return is_array($claims) ? $claims : null;
}

function shield_difficulty(string $mode): int { return $mode==='low' ? 16 : ($mode==='high' ? 22 : 18); }

function shield_prefix_bits_ok(string $hexHash, int $bits): bool {
  $nibbles = intdiv($bits, 4);
  $rem = $bits % 4;
  if (substr($hexHash, 0, $nibbles) !== str_repeat('0', $nibbles)) return false;
  if ($rem === 0) return true;
  $next = hexdec($hexHash[$nibbles] ?? 'f');
  $limit = 8 >> ($rem - 1);
  return $next < $limit;
}

function shield_bind_claims(array $cfg): array {
  $claims = [];
  if (($cfg['bind_ua'] ?? 'loose') !== 'off') {
    $claims['uah'] = hash('sha256', shield_ua(), false);
  }
  if (!empty($cfg['bind_ip'])) {
    $ip = shield_client_ip();
    if (strpos($ip, ':') !== false) {
      $claims['ipm'] = preg_replace('/:[0-9a-f]{1,4}(:[0-9a-f]{1,4}){0,3}$/i', '::', $ip);
    } else {
      $p = explode('.', $ip);
      $claims['ipm'] = $p[0].'.'.$p[1].'.'.$p[2].'.0';
    }
  }
  return $claims;
}

function shield_claims_match(array $cfg, array $claims): bool {
  if (($cfg['bind_ua'] ?? 'loose') !== 'off' && !empty($claims['uah'])) {
    $uah_now = hash('sha256', shield_ua(), false);
    if (($cfg['bind_ua'] ?? 'loose') === 'strict') {
      if (!hash_equals($uah_now, $claims['uah'])) return false;
    } else {
      if (substr($uah_now, 0, 12) !== substr($claims['uah'], 0, 12)) return false;
    }
  }
  if (!empty($cfg['bind_ip']) && !empty($claims['ipm'])) {
    $ip = shield_client_ip();
    if (strpos($ip, ':') !== false) {
      $ipm_now = preg_replace('/:[0-9a-f]{1,4}(:[0-9a-f]{1,4}){0,3}$/i', '::', $ip);
    } else {
      $p = explode('.', $ip);
      $ipm_now = $p[0].'.'.$p[1].'.'.$p[2].'.0';
    }
    if ($ipm_now !== $claims['ipm']) return false;
  }
  return true;
}
