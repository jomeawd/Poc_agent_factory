<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/jobs.php';
require_once __DIR__ . '/agentfather.php';

if (!class_exists('HttpError')) {
    final class HttpError extends RuntimeException {}
}

function api_fail(int $code, string $detail): never
{
    throw new HttpError($detail, $code);
}

function is_https_request(?array $server = null, ?array $env = null): bool
{
    $server ??= $_SERVER;
    $env ??= [
        'COOKIE_SECURE' => getenv('COOKIE_SECURE'),
        'TRUST_PROXY' => getenv('TRUST_PROXY'),
    ];
    $override = strtolower(trim((string)($env['COOKIE_SECURE'] ?? 'auto')));
    if ($override === 'true' || $override === '1') {
        return true;
    }
    if ($override === 'false' || $override === '0') {
        return false;
    }
    if (!empty($server['HTTPS']) && strtolower((string)$server['HTTPS']) !== 'off') {
        return true;
    }
    if ((string)($server['SERVER_PORT'] ?? '') === '443') {
        return true;
    }
    $trustProxy = strtolower(trim((string)($env['TRUST_PROXY'] ?? 'false')));
    if (($trustProxy === 'true' || $trustProxy === '1')
        && strtolower((string)($server['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }
    return false;
}

/** @return array{expires: int, path: string, httponly: bool, samesite: string, secure: bool} */
function cookie_options(int $expires, bool $secure): array
{
    return [
        'expires' => $expires,
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure' => $secure,
    ];
}

function csrf_token_for_session(string $uid, int $exp, string $secret): string
{
    return hash_hmac('sha256', "csrf:$uid:$exp", $secret);
}

function verify_csrf_token(string $expected, ?string $provided): bool
{
    if ($expected === '' || !is_string($provided) || $provided === '') {
        return false;
    }
    return hash_equals($expected, $provided);
}

/**
 * Evaluates CORS / Origin policy.
 * Returns headers to emit, or throws HttpError(403) if origin is disallowed.
 *
 * @return array<string, string>
 */
function evaluate_cors(string $method, ?string $origin, ?string $host, string $allowedCsv): array
{
    if ($origin === null || $origin === '') {
        return [];
    }
    $allowed = array_values(array_filter(array_map('trim', explode(',', $allowedCsv))));
    if ($allowed === []) {
        $originHost = parse_url($origin, PHP_URL_HOST);
        $originPort = parse_url($origin, PHP_URL_PORT);
        $originHostPort = $originPort ? "$originHost:$originPort" : $originHost;
        $sameOrigin = $host !== null && $host !== '' && strcasecmp((string)$originHostPort, $host) === 0;
        if (!$sameOrigin && !in_array($method, ['GET', 'HEAD'], true)) {
            api_fail(403, 'Cross-origin request denied');
        }
        return [];
    }
    if (!in_array($origin, $allowed, true)) {
        api_fail(403, 'Origin not allowed');
    }
    return [
        'Access-Control-Allow-Origin' => $origin,
        'Vary' => 'Origin',
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Allow-Headers' => 'Content-Type, X-CSRF-Token',
        'Access-Control-Allow-Methods' => 'GET, POST, DELETE, OPTIONS',
    ];
}

function client_ip(?array $server = null, ?bool $trustProxy = null): string
{
    $server ??= $_SERVER;
    $trustProxy ??= strtolower(trim((string)getenv('TRUST_PROXY'))) === 'true';
    if ($trustProxy && !empty($server['HTTP_X_FORWARDED_FOR'])) {
        // Only the RIGHTMOST entry was written by our proxy (Caddy sets it to the peer address);
        // anything to its left came from the client and can be forged.
        $parts = array_map('trim', explode(',', (string)$server['HTTP_X_FORWARDED_FOR']));
        $last = end($parts);
        if (filter_var($last, FILTER_VALIDATE_IP) !== false) {
            return $last;
        }
    }
    return substr((string)($server['REMOTE_ADDR'] ?? '0.0.0.0'), 0, 64);
}

function check_login_rate_limit(string $email, string $ip): void
{
    $row = q1('SELECT failures, locked_until FROM login_attempts WHERE email=? AND ip=?', $email, $ip);
    if ($row && !empty($row['locked_until'])) {
        $lockedUntil = strtotime((string)$row['locked_until']);
        if ($lockedUntil !== false && $lockedUntil > time()) {
            api_fail(429, 'Too many failed login attempts. Try again later.');
        }
    }
    // Account-wide cap, whatever the IP: spreading guesses over many addresses does not help.
    $recent = q1(
        "SELECT COALESCE(SUM(failures), 0) AS n FROM login_attempts WHERE email=? AND updated_at > now() - interval '15 minutes'",
        $email
    );
    if ((int)($recent['n'] ?? 0) >= LOGIN_ACCOUNT_MAX_FAILURES) {
        api_fail(429, 'Too many failed login attempts. Try again later.');
    }
}

/** Failures allowed per account in 15 minutes across all IPs (per-IP limit stays 5). */
const LOGIN_ACCOUNT_MAX_FAILURES = 20;

function record_login_failure(string $email, string $ip, int $maxFailures = 5, int $lockSeconds = 300): void
{
    $row = q1('SELECT failures, updated_at FROM login_attempts WHERE email=? AND ip=?', $email, $ip);
    $failures = 1;
    if ($row) {
        $updated = strtotime((string)$row['updated_at']);
        $failures = ($updated !== false && (time() - $updated) < 900) ? ((int)$row['failures'] + 1) : 1;
    }
    $lockedUntil = $failures >= $maxFailures ? gmdate('Y-m-d H:i:sP', time() + $lockSeconds) : null;
    // Keep the table small: rows older than a day no longer count for anything.
    q("DELETE FROM login_attempts WHERE updated_at < now() - interval '1 day' AND (locked_until IS NULL OR locked_until < now())");
    q(
        'INSERT INTO login_attempts(email, ip, failures, locked_until, updated_at) VALUES (?,?,?,?,now())
         ON CONFLICT (email, ip) DO UPDATE SET failures=EXCLUDED.failures, locked_until=EXCLUDED.locked_until, updated_at=now()',
        $email,
        $ip,
        $failures,
        $lockedUntil
    );
}

function clear_login_failures(string $email, string $ip): void
{
    q('DELETE FROM login_attempts WHERE email=? AND ip=?', $email, $ip);
}

function active_job(string $agentId, string $tenantId): ?array
{
    return q1(
        "SELECT * FROM jobs WHERE agent_id=? AND tenant_id=? AND state IN ('queued','running','rolling_back') LIMIT 1",
        $agentId,
        $tenantId
    );
}

function public_agent(array $a, ?array $job = null): array
{
    $acct = $a['channel_account'] ?? '';
    if ($a['channel_type'] === 'whatsapp' && strlen($acct) > 6) {
        $acct = substr($acct, 0, 4) . str_repeat('•', strlen($acct) - 6) . substr($acct, -2);
    }
    $iso = fn(?string $t) => $t ? (new DateTimeImmutable($t))->format(DATE_ATOM) : null;
    return [
        'id' => $a['id'],
        'name' => $a['name'],
        'job' => $a['job'],
        'channel_type' => $a['channel_type'],
        'channel_account' => $acct,
        'enabled' => (bool)$a['enabled'],
        'state' => $a['state'],
        'runtime' => $a['runtime'],
        'model' => $a['model'],
        'restricted' => json_decode($a['allowed_users'], true) !== [],
        'state_reason' => $a['state_reason'],
        'last_message_at' => $iso($a['last_message_at']),
        'created_at' => $iso($a['created_at']),
        'busy' => $job !== null,
        'pending_job' => $job ? ['type' => $job['type'], 'state' => $job['state'], 'step' => $job['current_step']] : null,
    ];
}

/**
 * Which job the On/Off switch should queue for an agent in $state.
 * Returns null when the agent is already where the switch asks (nothing to do).
 * Refuses (409) while a change is under way or after a failed deletion.
 */
function switch_job_type(string $state, bool $on): ?string
{
    return match ($state) {
        'inactive' => $on ? 'enable' : null,
        'failed' => $on ? 'create' : null,
        'active', 'unhealthy' => $on ? null : 'disable',
        'starting', 'stopping' => api_fail(409, 'A change is already in progress for this agent'),
        'delete_failed' => api_fail(409, 'Deleting this agent failed. Click Delete to try again.'),
        default => api_fail(409, 'This agent cannot be switched right now'),
    };
}

/**
 * On/Off switch. Locks the agent row, checks the transition, then queues the job and moves the
 * agent to starting/stopping in ONE transaction: the worker cannot see the job before the agent
 * row says starting/stopping, so it can never finish first and have its result overwritten.
 */
function switch_agent(string $agentId, array $u, bool $on): array
{
    $pdo = pdo();
    $pdo->beginTransaction();
    try {
        $a = q1("SELECT * FROM agents WHERE id=? AND tenant_id=? AND state <> 'deleted' FOR UPDATE", $agentId, $u['tenant_id'])
            ?? api_fail(404, 'Agent not found');
        $type = switch_job_type($a['state'], $on);
        if ($type !== null) {
            if (enqueue($a, $type) === null) {
                api_fail(409, 'A change is already in progress for this agent');
            }
            q('UPDATE agents SET enabled=?, state=? WHERE id=? AND tenant_id=?', $on, $on ? 'starting' : 'stopping', $a['id'], $u['tenant_id']);
            event($a['tenant_id'], $a['id'], $on ? 'switch_on' : 'switch_off', 'requested');
        }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
    return public_agent(
        q1('SELECT * FROM agents WHERE id=? AND tenant_id=?', $agentId, $u['tenant_id']),
        active_job($agentId, $u['tenant_id'])
    );
}

/**
 * Atomically confirms an AgentFather session:
 * locks session row, validates config/token, stores secret in broker, creates agent + job in DB transaction,
 * and deletes the stored secret via compensation if DB commit or enqueue fails.
 */
function confirm_agent_session(string $sid, array $u, array $body): array
{
    if (!is_uuid($sid)) {
        api_fail(404, 'Session not found');
    }
    if (array_diff(array_keys($body), ['telegram_token'])) {
        api_fail(422, 'Invalid request: unknown fields');
    }
    $token = trim((string)($body['telegram_token'] ?? ''));
    if ($token === '') {
        api_fail(422, 'Paste the Telegram bot token from @BotFather.');
    }

    $pdo = pdo();
    $pdo->beginTransaction();
    $secretRef = null;
    try {
        $s = q1(
            'SELECT * FROM agentfather_sessions WHERE id=? AND tenant_id=? AND user_id=? FOR UPDATE',
            $sid,
            $u['tenant_id'],
            $u['id']
        );
        if (!$s) {
            api_fail(404, 'Session not found');
        }
        if ($s['status'] !== 'open') {
            api_fail(409, 'This conversation is already closed');
        }
        $state = $s['draft_config'] !== null ? json_decode($s['draft_config'], true) : [];
        if (!is_array($state) || !array_key_exists('asking', $state) || $state['asking'] !== null) {
            api_fail(422, "Answer all of AgentFather's questions first.");
        }
        [$cfg, $err] = validate_config(af_build_config((array)($state['answers'] ?? [])));
        if (!$cfg) {
            api_fail(422, 'Configuration rejected by the platform: ' . ($err ?? 'incomplete'));
        }
        $enabled = $GLOBALS['af_enabled_providers'] ?? null;
        if ($enabled !== null && !in_array(AF_MODEL_PROVIDER[$cfg['model']], $enabled, true)) {
            api_fail(422, 'The model provider for this agent is not connected. Open Model providers, or click Change and pick another model.');
        }
        if ($cfg['channel_type'] === 'whatsapp') {
            api_fail(422, 'WhatsApp is not available in this POC yet. Click Change and choose Telegram.');
        }

        try {
            $sec = broker('POST', '/secrets', ['kind' => 'telegram', 'value' => $token]);
        } catch (StepError $e) {
            $code = $e->getCode();
            api_fail($code >= 400 && $code < 500 ? $code : 502, $e->getMessage());
        }
        $secretRef = (string)($sec['secret_ref'] ?? '');

        $aid = uuid4();
        q(
            "INSERT INTO agents(id, tenant_id, name, job, instructions, prohibited_tasks, channel_type, channel_account,
                 secret_ref, enabled, state, runtime, model, allowed_users) VALUES (?,?,?,?,?,?::jsonb,?,?,?,true,'starting',?,?,?::jsonb)",
            $aid,
            $u['tenant_id'],
            $cfg['name'],
            $cfg['job'],
            $cfg['instructions'],
            json_encode($cfg['prohibited_tasks']),
            $cfg['channel_type'],
            $sec['account'],
            $secretRef,
            $cfg['runtime'],
            $cfg['model'],
            json_encode($cfg['allowed_users'])
        );
        $updated = q1(
            "UPDATE agentfather_sessions SET status='confirmed' WHERE id=? AND tenant_id=? AND user_id=? AND status='open' RETURNING id",
            $s['id'],
            $u['tenant_id'],
            $u['id']
        );
        if (!$updated) {
            api_fail(409, 'This conversation is already closed');
        }
        $a = q1('SELECT * FROM agents WHERE id=? AND tenant_id=?', $aid, $u['tenant_id']);
        if (!$a) {
            throw new RuntimeException('Failed to read created agent');
        }
        event($u['tenant_id'], $aid, 'config_validated', 'completed');
        $jid = enqueue($a, 'create');
        if ($jid === null) {
            throw new RuntimeException('Failed to enqueue create job');
        }
        $pdo->commit();
        return public_agent($a, active_job($aid, $u['tenant_id']));
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if ($secretRef !== null && $secretRef !== '') {
            try {
                broker('DELETE', '/secrets/' . $secretRef);
            } catch (Throwable) {
                error_log("confirm compensation failed for secret $secretRef");
            }
        }
        throw $e;
    }
}
