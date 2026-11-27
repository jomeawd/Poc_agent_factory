<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
/* Agent Factory API. The web app talks only to this. No Docker socket, no secrets store. */

require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/db.php';
require_once __DIR__ . '/../src/jobs.php';
require_once __DIR__ . '/../src/agentfather.php';
require_once __DIR__ . '/../src/security.php';

const COOKIE = 'af_session';

function json_out(mixed $data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(int $code, string $detail): never
{
    throw new HttpError($detail, $code);
}

/** Request body as an array. Bad input never echoes submitted values back (they may hold a token). */
function body(): array
{
    $d = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($d)) {
        fail(422, 'Invalid request: body must be a JSON object');
    }
    return $d;
}

set_exception_handler(function (Throwable $e) {
    if ($e instanceof HttpError) {
        json_out(['detail' => $e->getMessage()], $e->getCode());
    }
    error_log('api error: ' . get_class($e) . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
    json_out(['detail' => 'Internal error'], 500);
});

assert_api_config(true);

// Schema + seeded owner, once per container.
if (!file_exists('/tmp/.af-init')) {
    db_init();
    touch('/tmp/.af-init');
}

// ---------------------------------------------------------------- auth
function sign(string $payload): string
{
    $secret = (string)getenv('SESSION_SECRET');
    $mac = hash_hmac('sha256', $payload, $secret);
    return rtrim(strtr(base64_encode("$payload|$mac"), '+/', '-_'), '=');
}

function current_user(): array
{
    $secret = (string)getenv('SESSION_SECRET');
    $raw = base64_decode(strtr($_COOKIE[COOKIE] ?? '', '-_', '+/'), true) ?: '';
    $parts = explode('|', $raw);
    if (count($parts) !== 2) {
        fail(401, 'Not signed in');
    }
    [$payload, $mac] = $parts;
    if (!hash_equals(hash_hmac('sha256', $payload, $secret), $mac)) {
        fail(401, 'Not signed in');
    }
    [$uid, $expStr] = explode(':', $payload) + [1 => '0'];
    $exp = (int)$expStr;
    if ($exp < time() || !is_uuid($uid)) {
        fail(401, 'Not signed in');
    }
    $u = q1('SELECT id, tenant_id, email, role FROM users WHERE id=?', $uid);
    if (!$u) {
        fail(401, 'Not signed in');
    }
    $u['csrf_token'] = csrf_token_for_session($uid, $exp, $secret);
    return $u;
}

// ---------------------------------------------------------------- helpers
function get_agent(string $id, array $u): array
{
    if (!is_uuid($id)) {
        fail(404, 'Agent not found');
    }
    return q1("SELECT * FROM agents WHERE id=? AND tenant_id=? AND state <> 'deleted'", $id, $u['tenant_id'])
        ?? fail(404, 'Agent not found');
}

function get_session(string $sid, array $u): array
{
    if (!is_uuid($sid)) {
        fail(404, 'Session not found');
    }
    $s = q1('SELECT * FROM agentfather_sessions WHERE id=? AND tenant_id=? AND user_id=?', $sid, $u['tenant_id'], $u['id'])
        ?? fail(404, 'Session not found');
    $s['messages'] = json_decode($s['messages'], true);
    $s['draft_config'] = $s['draft_config'] !== null ? json_decode($s['draft_config'], true) : null;
    return $s;
}

function session_out(array $s, ?string $error = null): array
{
    $state = $s['draft_config'] ?? ['answers' => [], 'asking' => af_next([])];
    $asking = array_key_exists('asking', $state) ? $state['asking'] : af_next($state['answers'] ?? []);
    $cfg = $err = null;
    if ($asking === null) {
        [$cfg, $err] = validate_config(af_build_config($state['answers'] ?? []));
    }
    return [
        'id' => $s['id'],
        'messages' => $s['messages'],
        'status' => $s['status'],
        'question' => af_question($asking),
        'complete' => $asking === null && $cfg !== null,
        'config' => $cfg,
        'validation_error' => $err,
        'error' => $error,
    ];
}

// ---------------------------------------------------------------- CORS + routes
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$corsHeaders = evaluate_cors(
    $method,
    $_SERVER['HTTP_ORIGIN'] ?? null,
    $_SERVER['HTTP_HOST'] ?? null,
    (string)(getenv('CORS_ALLOWED_ORIGINS') ?: '')
);
foreach ($corsHeaders as $k => $v) {
    header("$k: $v");
}
if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$m = [];
$route = function (string $verb, string $pattern) use ($method, $path, &$m): bool {
    return $method === $verb && (bool)preg_match("#^$pattern$#", $path, $m);
};

if ($route('GET', '/api/health')) {
    q1('SELECT 1');
    json_out(['ok' => true]);
}

$secureCookie = is_https_request();

if ($route('POST', '/api/login')) {
    $b = body();
    $email = strtolower(trim((string)($b['email'] ?? '')));
    $ip = client_ip();
    check_login_rate_limit($email, $ip);
    $u = q1('SELECT * FROM users WHERE email=?', $email);
    if (!$u || !password_verify((string)($b['password'] ?? ''), $u['password_hash'])) {
        record_login_failure($email, $ip);
        fail(401, 'Wrong email or password');
    }
    clear_login_failures($email, $ip);
    $exp = time() + 12 * 3600;
    setcookie(COOKIE, sign($u['id'] . ':' . $exp), cookie_options($exp, $secureCookie));
    json_out([
        'email' => $u['email'],
        'csrf_token' => csrf_token_for_session($u['id'], $exp, (string)getenv('SESSION_SECRET')),
    ]);
}

if ($route('POST', '/api/logout')) {
    // A signed-in user can only be logged out with their CSRF token (no cross-site logout).
    // Without a valid session there is nothing to protect, so the cookie is simply cleared.
    try {
        $session = current_user();
    } catch (HttpError) {
        $session = null;
    }
    if ($session !== null && !verify_csrf_token($session['csrf_token'], $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
        fail(403, 'Invalid or missing CSRF token');
    }
    setcookie(COOKIE, '', cookie_options(1, $secureCookie));
    json_out(['ok' => true]);
}

$u = current_user();

if (!in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
    if (!verify_csrf_token($u['csrf_token'], $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
        fail(403, 'Invalid or missing CSRF token');
    }
}

if ($route('GET', '/api/me')) {
    json_out(['email' => $u['email'], 'role' => $u['role'], 'csrf_token' => $u['csrf_token']]);
}

// ---------------------------------------------------------------- model providers
// Keys go straight to the broker's secrets store; the API only ever sees connected yes/no.
const PROVIDER_IDS = ['anthropic', 'gemini', 'groq'];

function providers_list(): array
{
    try {
        $rows = broker('GET', '/providers');
    } catch (StepError) {
        fail(502, 'Deployment broker unreachable');
    }
    return array_values(array_map(fn($r) => [
        'id' => (string)$r['id'], 'configured' => (bool)$r['configured'],
        'source' => $r['source'] ?? null, 'kind' => $r['kind'] ?? null,
    ], array_filter($rows, fn($r) => in_array($r['id'] ?? '', PROVIDER_IDS, true))));
}

function enabled_providers(): array
{
    return array_values(array_map(fn($r) => $r['id'], array_filter(providers_list(), fn($r) => $r['configured'])));
}

if ($route('GET', '/api/providers')) {
    json_out(providers_list());
}

if ($route('PUT', '/api/providers/([a-z]+)')) {
    if (!in_array($m[1], PROVIDER_IDS, true)) {
        fail(404, 'Unknown provider');
    }
    $key = body()['key'] ?? null;
    if (!is_string($key) || trim($key) === '' || strlen($key) > 400) {
        fail(422, 'Paste the API key.');
    }
    try {
        broker('PUT', '/providers/' . $m[1], ['value' => $key]);
    } catch (StepError $e) {
        $code = $e->getCode();
        fail($code >= 400 && $code < 500 ? $code : 502, $e->getMessage());
    }
    event($u['tenant_id'], null, 'provider_connected', 'completed', $m[1]);
    json_out(providers_list());
}

if ($route('DELETE', '/api/providers/([a-z]+)')) {
    if (!in_array($m[1], PROVIDER_IDS, true)) {
        fail(404, 'Unknown provider');
    }
    try {
        broker('DELETE', '/providers/' . $m[1]);
    } catch (StepError $e) {
        fail(502, $e->getMessage());
    }
    event($u['tenant_id'], null, 'provider_disconnected', 'completed', $m[1]);
    json_out(providers_list());
}

if (str_starts_with((string)$path, '/api/agentfather/')) {
    $GLOBALS['af_enabled_providers'] = enabled_providers();
}

if ($route('GET', '/api/agents')) {
    $rows = q("SELECT * FROM agents WHERE tenant_id=? AND state <> 'deleted' ORDER BY created_at DESC", $u['tenant_id']);
    json_out(array_map(fn($a) => public_agent($a, active_job($a['id'], $u['tenant_id'])), $rows));
}

if ($route('GET', '/api/agents/([0-9a-f-]+)')) {
    $a = get_agent($m[1], $u);
    $events = q(
        'SELECT timestamp, type, state, result, duration_ms, job_id FROM events WHERE agent_id=? AND tenant_id=? ORDER BY id DESC LIMIT 40',
        $a['id'],
        $u['tenant_id']
    );
    foreach ($events as &$e) {
        $e['timestamp'] = (new DateTimeImmutable($e['timestamp']))->format(DATE_ATOM);
        $e['duration_ms'] = $e['duration_ms'] !== null ? (int)$e['duration_ms'] : null;
    }
    json_out(public_agent($a, active_job($a['id'], $u['tenant_id'])) + ['events' => $events]);
}

if ($route('POST', '/api/agents/([0-9a-f-]+)/switch')) {
    $a = get_agent($m[1], $u);
    $b = body();
    if (!is_bool($b['enabled'] ?? null)) {
        fail(422, 'Invalid request: enabled');
    }
    $on = $b['enabled'];
    $type = $on ? ($a['state'] === 'failed' ? 'create' : 'enable') : 'disable';
    if (enqueue($a, $type) === null) {
        fail(409, 'A change is already in progress for this agent');
    }
    q('UPDATE agents SET enabled=?, state=? WHERE id=? AND tenant_id=?', $on, $on ? 'starting' : 'stopping', $a['id'], $u['tenant_id']);
    event($a['tenant_id'], $a['id'], $on ? 'switch_on' : 'switch_off', 'requested');
    json_out(public_agent(
        q1('SELECT * FROM agents WHERE id=? AND tenant_id=?', $a['id'], $u['tenant_id']),
        active_job($a['id'], $u['tenant_id'])
    ));
}

if ($route('DELETE', '/api/agents/([0-9a-f-]+)')) {
    $a = get_agent($m[1], $u);
    if (enqueue($a, 'delete') === null) {
        fail(409, 'A change is already in progress for this agent');
    }
    event($a['tenant_id'], $a['id'], 'delete', 'requested');
    json_out(['ok' => true]);
}

if ($route('POST', '/api/agentfather/sessions')) {
    if ($GLOBALS['af_enabled_providers'] === []) {
        fail(409, 'Connect a model provider first (Claude, Gemini or Groq).');
    }
    $sid = uuid4();
    $first = af_next([]);
    $msgs = [['role' => 'assistant', 'content' => AF_GREETING], ['role' => 'assistant', 'content' => af_prompt($first)]];
    q(
        'INSERT INTO agentfather_sessions(id, tenant_id, user_id, messages, draft_config) VALUES (?,?,?,?::jsonb,?::jsonb)',
        $sid,
        $u['tenant_id'],
        $u['id'],
        json_encode($msgs),
        json_encode(['answers' => new stdClass(), 'asking' => $first])
    );
    json_out(session_out(get_session($sid, $u)));
}

if ($route('POST', '/api/agentfather/sessions/([0-9a-f-]+)/messages')) {
    $s = get_session($m[1], $u);
    if ($s['status'] !== 'open') {
        fail(409, 'This conversation is closed');
    }
    $b = body();
    $state = $s['draft_config'] ?? ['answers' => [], 'asking' => af_next([])];
    $state['answers'] = (array)($state['answers'] ?? []);
    if (($b['action'] ?? '') === 'change') {
        $new = ['answers' => $state['answers'], 'asking' => CHANGE_Q];
        $shown = 'I want to change something.';
    } else {
        $choices = $b['choices'] ?? [];
        $text = $b['text'] ?? '';
        if (!is_array($choices) || !is_string($text) || mb_strlen($text) > 4000) {
            fail(422, 'Invalid request');
        }
        $choices = array_values(array_filter($choices, 'is_string'));
        [$new, $err, $shown] = af_answer($state, $choices, $text);
        if ($err !== null) {
            json_out(session_out($s, $err));
        }
    }
    $msgs = [...$s['messages'], ['role' => 'user', 'content' => $shown], ['role' => 'assistant', 'content' => af_prompt($new['asking'])]];
    q(
        'UPDATE agentfather_sessions SET messages=?::jsonb, draft_config=?::jsonb WHERE id=? AND tenant_id=? AND user_id=?',
        json_encode($msgs),
        json_encode(['answers' => (object)$new['answers'], 'asking' => $new['asking']]),
        $s['id'],
        $u['tenant_id'],
        $u['id']
    );
    json_out(session_out(get_session($s['id'], $u)));
}

if ($route('POST', '/api/agentfather/sessions/([0-9a-f-]+)/confirm')) {
    json_out(confirm_agent_session($m[1], $u, body()));
}

if ($route('POST', '/api/agentfather/sessions/([0-9a-f-]+)/cancel')) {
    $s = get_session($m[1], $u);
    q("UPDATE agentfather_sessions SET status='cancelled' WHERE id=? AND tenant_id=? AND user_id=? AND status='open'", $s['id'], $u['tenant_id'], $u['id']);
    json_out(['ok' => true]);
}

fail(404, 'Not found');
