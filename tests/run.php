<?php
declare(strict_types=1);

require_once __DIR__ . '/mock_pdo.php';
require_once __DIR__ . '/../api/src/config.php';
require_once __DIR__ . '/../api/src/db.php';
require_once __DIR__ . '/../api/src/agentfather.php';
require_once __DIR__ . '/../api/src/jobs.php';
require_once __DIR__ . '/../api/src/security.php';
require_once __DIR__ . '/../broker/lib.php';

$passed = 0;
$failed = 0;

function test(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
        echo "PASS: $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "FAIL: $name -- {$e->getMessage()}\n";
    }
}

function assert_true(bool $cond, string $msg = 'Expected true'): void
{
    if (!$cond) {
        throw new RuntimeException($msg);
    }
}

function assert_eq(mixed $expected, mixed $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(($msg ? "$msg: " : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function assert_throws(string $class, callable $fn, ?int $code = null): Throwable
{
    try {
        $fn();
    } catch (Throwable $e) {
        if (!$e instanceof $class) {
            throw new RuntimeException("Expected $class, got " . get_class($e) . ": {$e->getMessage()}");
        }
        if ($code !== null && $e->getCode() !== $code) {
            throw new RuntimeException("Expected code $code, got {$e->getCode()}: {$e->getMessage()}");
        }
        return $e;
    }
    throw new RuntimeException("Expected $class to be thrown");
}

function complete_answers(): array
{
    return [
        'purpose' => 'Customer support',
        'company' => 'Acme Bakery',
        'name' => 'Nova',
        'knowledge' => 'Open 8am to 6pm daily.',
        'tone' => ['Friendly and warm'],
        'language' => 'English only',
        'prohibited' => ['Promise refunds or discounts'],
        'fallback' => "Simply say it doesn't know",
        'runtime' => 'OpenClaw (recommended)',
        'model' => 'Claude Sonnet 4.6',
        'channel' => 'Telegram',
        'access' => AF_ACCESS_ANYONE,
    ];
}

// ---------------------------------------------------------------- 1. Config validation
test('config validation rejects missing, empty, and weak secrets without leaking values', function () {
    $bad = [
        'BROKER_TOKEN' => 'changeme',
        'SESSION_SECRET' => '',
        'OWNER_PASSWORD' => 'changeme',
        'DATABASE_URL' => 'postgresql://agentfactory:@db:5432/agentfactory',
        'BROKER_URL' => 'not-a-url',
    ];
    $errs = validate_api_env($bad, true);
    assert_eq(5, count($errs));
    $joined = implode(' ', $errs);
    assert_true(!str_contains($joined, 'changeme'), 'Error must not echo secret value');

    $brokerErrs = validate_broker_env(['BROKER_TOKEN' => 'short']);
    assert_eq(1, count($brokerErrs));

    $good = [
        'BROKER_TOKEN' => '0123456789abcdef0123456789abcdef',
        'SESSION_SECRET' => 'fedcba9876543210fedcba9876543210',
        'OWNER_PASSWORD' => 'Str0ngPass!2026',
        'DATABASE_URL' => 'postgresql://agentfactory:dbpass123@db:5432/agentfactory',
        'BROKER_URL' => 'http://broker:8100',
    ];
    assert_eq([], validate_api_env($good, true));
    assert_eq([], validate_broker_env(['BROKER_TOKEN' => $good['BROKER_TOKEN']]));
});

// ---------------------------------------------------------------- 2. AgentFather & input validation
test('AgentFather progression, redaction, and invalid input rejection', function () {
    $redacted = redact('my bot 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234 and sk-proj-1234567890abcdefghij');
    assert_true(!str_contains($redacted, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 'Telegram token must be redacted');
    assert_true(!str_contains($redacted, '1234567890abcdefghij'), 'Provider key must be redacted');

    $state = ['answers' => [], 'asking' => af_next([])];
    assert_eq('purpose', $state['asking']);

    [$badNameState, $err] = af_answer(['answers' => ['purpose' => 'Support', 'company' => 'Acme'], 'asking' => 'name'], [], '!');
    assert_true($err !== null);
    assert_eq('name', $badNameState['asking']);

    [$waState, $waErr] = af_answer(['answers' => [], 'asking' => 'channel'], ['WhatsApp (coming soon)'], '');
    assert_true($waErr !== null);

    $cfg = af_build_config(complete_answers());
    assert_true($cfg !== null);
    [$valid, $verr] = validate_config($cfg);
    assert_eq(null, $verr);
    assert_eq('openclaw', $valid['runtime']);

    [$badCfg, $badErr] = validate_config($cfg + ['extra' => 'nope']);
    assert_eq(null, $badCfg);
    assert_true($badErr !== null);
});

// ---------------------------------------------------------------- 3. Auth, cookies, CSRF, CORS, rate limiting
test('broker_authenticate rejects empty and wrong tokens', function () {
    assert_true(!broker_authenticate('', ''));
    assert_true(!broker_authenticate(null, 'anything'));
    $tok = '0123456789abcdef0123456789abcdef';
    assert_true(!broker_authenticate($tok, ''));
    assert_true(!broker_authenticate($tok, 'wrong'));
    assert_true(broker_authenticate($tok, $tok));
});

test('HTTPS cookie detection, logout attributes, CSRF, and CORS', function () {
    assert_true(!is_https_request(['HTTPS' => 'off', 'SERVER_PORT' => '80'], ['COOKIE_SECURE' => 'auto', 'TRUST_PROXY' => 'false']));
    assert_true(is_https_request(['HTTPS' => 'on'], ['COOKIE_SECURE' => 'auto', 'TRUST_PROXY' => 'false']));
    assert_true(is_https_request(['HTTP_X_FORWARDED_PROTO' => 'https'], ['COOKIE_SECURE' => 'auto', 'TRUST_PROXY' => 'true']));
    assert_true(!is_https_request(['HTTP_X_FORWARDED_PROTO' => 'https'], ['COOKIE_SECURE' => 'auto', 'TRUST_PROXY' => 'false']));

    $opts = cookie_options(1, true);
    assert_true($opts['httponly'] && $opts['secure'] && $opts['samesite'] === 'Strict');

    $csrf = csrf_token_for_session('11111111-1111-4111-8111-111111111111', time() + 3600, 'secret-value-123456');
    assert_true(verify_csrf_token($csrf, $csrf));
    assert_true(!verify_csrf_token($csrf, 'invalid'));
    assert_true(!verify_csrf_token($csrf, null));

    assert_throws(HttpError::class, fn() => evaluate_cors('POST', 'https://evil.example', 'localhost:3000', ''), 403);
    $cors = evaluate_cors('POST', 'https://app.example.com', 'api.example.com', 'https://app.example.com');
    assert_eq('https://app.example.com', $cors['Access-Control-Allow-Origin']);
});

test('login rate limiting locks out after 5 failures', function () {
    $store = [];
    set_pdo(new MockPdo(function (string $sql, array $params) use (&$store): array {
        if (str_starts_with($sql, 'SELECT failures, locked_until')) {
            $k = $params[0] . '|' . $params[1];
            return ['rows' => isset($store[$k]) ? [$store[$k]] : []];
        }
        if (str_starts_with($sql, 'SELECT failures, updated_at')) {
            $k = $params[0] . '|' . $params[1];
            return ['rows' => isset($store[$k]) ? [$store[$k]] : []];
        }
        if (str_starts_with($sql, 'INSERT INTO login_attempts')) {
            $k = $params[0] . '|' . $params[1];
            $store[$k] = [
                'failures' => $params[2],
                'locked_until' => $params[3],
                'updated_at' => gmdate('Y-m-d H:i:sP'),
            ];
            return ['rows' => []];
        }
        return ['rows' => []];
    }));

    for ($i = 0; $i < 5; $i++) {
        check_login_rate_limit('owner@acme.test', '127.0.0.1');
        record_login_failure('owner@acme.test', '127.0.0.1');
    }
    assert_throws(HttpError::class, fn() => check_login_rate_limit('owner@acme.test', '127.0.0.1'), 429);
});

test('client IP cannot be spoofed through X-Forwarded-For', function () {
    $peer = ['REMOTE_ADDR' => '172.20.0.9'];
    // Client-forged entries on the left are ignored; the proxy's (rightmost) entry wins.
    assert_eq('203.0.113.7', client_ip($peer + ['HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.7'], true));
    assert_eq('203.0.113.7', client_ip($peer + ['HTTP_X_FORWARDED_FOR' => '203.0.113.7'], true));
    // Garbage falls back to the socket peer, and the header is ignored when no proxy is trusted.
    assert_eq('172.20.0.9', client_ip($peer + ['HTTP_X_FORWARDED_FOR' => 'x" OR 1=1'], true));
    assert_eq('172.20.0.9', client_ip($peer + ['HTTP_X_FORWARDED_FOR' => '198.51.100.1'], false));
});

test('login is capped per account across IPs and old attempts are pruned', function () {
    $recentFailures = 0;
    $pruned = 0;
    set_pdo(new MockPdo(function (string $sql) use (&$recentFailures, &$pruned): array {
        if (str_starts_with($sql, 'SELECT COALESCE(SUM(failures)')) {
            return ['rows' => [['n' => $recentFailures]]];
        }
        if (str_starts_with($sql, 'DELETE FROM login_attempts WHERE updated_at')) {
            $pruned++;
        }
        return ['rows' => []];
    }));
    $recentFailures = LOGIN_ACCOUNT_MAX_FAILURES - 1;
    check_login_rate_limit('owner@acme.test', '198.51.100.99'); // fresh IP, under the account cap
    $recentFailures = LOGIN_ACCOUNT_MAX_FAILURES;
    assert_throws(HttpError::class, fn() => check_login_rate_limit('owner@acme.test', '198.51.100.100'), 429);
    record_login_failure('owner@acme.test', '198.51.100.100');
    assert_eq(1, $pruned);
});

// ---------------------------------------------------------------- 4. Manifest, secrets, and redaction
test('manifest building, broker validation, and secret atomic storage', function () {
    $aid = '11111111-1111-4111-8111-111111111111';
    $agentRow = [
        'id' => $aid,
        'name' => 'Nova',
        'job' => 'Support for Acme',
        'instructions' => 'Answer questions politely.',
        'prohibited_tasks' => json_encode(['Give legal advice']),
        'channel_type' => 'telegram',
        'secret_ref' => 'sec_' . str_repeat('a', 32),
        'runtime' => 'openclaw',
        'model' => 'claude-sonnet-4-6',
        'allowed_users' => json_encode(['123456789']),
    ];
    $m = manifest($agentRow);
    $validated = validate_manifest($m, $aid);
    assert_eq($aid, $validated['agent_id']);

    $oc = json_decode(openclaw_config($validated), true);
    assert_eq(['*'], $oc['tools']['deny']);
    assert_eq('allowlist', $oc['channels']['telegram']['dmPolicy']);

    $dir = sys_get_temp_dir() . '/af_test_secrets_' . bin2hex(random_bytes(4));
    mkdir($dir, 0700, true);
    try {
        $tok = '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234';
        $res = store_telegram_secret($tok, fn() => ['ok' => true, 'username' => 'novabot'], $dir);
        assert_eq('@novabot', $res['account']);
        $path = $dir . '/' . $res['secret_ref'];
        assert_true(is_file($path));
        assert_eq(0600, fileperms($path) & 0777);

        // Duplicate token refused
        assert_throws(HttpError::class, fn() => store_telegram_secret($tok, fn() => ['ok' => true, 'username' => 'novabot'], $dir), 409);

        delete_secret($res['secret_ref'], $dir);
        assert_true(!is_file($path));
    } finally {
        array_map('unlink', glob("$dir/*") ?: []);
        @unlink("$dir/.secrets.lock");
        @rmdir($dir);
    }

    assert_true(!str_contains(broker_redact('err 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
});

// ---------------------------------------------------------------- 5. Negative cases: confirm, tenant isolation, enqueue, cleanup, worker
test('negative cases: cross-tenant session, duplicate confirm, broker failure, DB failure + compensation', function () {
    $tenantA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    $tenantB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    $userA = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
    $sid = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
    $uA = ['id' => $userA, 'tenant_id' => $tenantA, 'email' => 'a@acme.test', 'role' => 'owner'];
    $uB = ['id' => 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'tenant_id' => $tenantB, 'email' => 'b@acme.test', 'role' => 'owner'];

    $draft = json_encode(['answers' => complete_answers(), 'asking' => null]);
    $sessionStatus = 'open';
    $failOnAgentInsert = false;
    $agents = [];

    $pdo = new MockPdo(function (string $sql, array $params) use ($sid, $tenantA, $userA, $draft, &$sessionStatus, &$failOnAgentInsert, &$agents): array {
        if (str_contains($sql, 'FROM agentfather_sessions')) {
            if ($params[0] === $sid && $params[1] === $tenantA && $params[2] === $userA) {
                return ['rows' => [[
                    'id' => $sid,
                    'tenant_id' => $tenantA,
                    'user_id' => $userA,
                    'status' => $sessionStatus,
                    'draft_config' => $draft,
                ]]];
            }
            return ['rows' => []];
        }
        if (str_starts_with($sql, 'INSERT INTO agents')) {
            if ($failOnAgentInsert) {
                throw make_pdo_exception('23502', 'null value violates not-null constraint');
            }
            $agents[$params[0]] = [
                'id' => $params[0],
                'tenant_id' => $params[1],
                'name' => $params[2],
                'job' => $params[3],
                'instructions' => $params[4],
                'prohibited_tasks' => $params[5],
                'channel_type' => $params[6],
                'channel_account' => $params[7],
                'secret_ref' => $params[8],
                'enabled' => true,
                'state' => 'starting',
                'runtime' => $params[9],
                'model' => $params[10],
                'allowed_users' => $params[11],
                'state_reason' => null,
                'last_message_at' => null,
                'created_at' => gmdate(DATE_ATOM),
            ];
            return ['rows' => []];
        }
        if (str_starts_with($sql, "UPDATE agentfather_sessions SET status='confirmed'")) {
            $sessionStatus = 'confirmed';
            return ['rows' => [['id' => $sid]]];
        }
        if (str_starts_with($sql, 'SELECT * FROM agents WHERE id=?')) {
            return ['rows' => isset($agents[$params[0]]) ? [$agents[$params[0]]] : []];
        }
        return ['rows' => []];
    });
    set_pdo($pdo);

    // Cross-tenant session -> 404
    assert_throws(HttpError::class, fn() => confirm_agent_session($sid, $uB, ['telegram_token' => '123:abc']), 404);

    // Broker failure -> 502, transaction rolled back, no agent created
    set_broker_handler(function () {
        throw new StepError('Deployment broker unreachable', 502);
    });
    assert_throws(HttpError::class, fn() => confirm_agent_session($sid, $uA, ['telegram_token' => '123:abc']), 502);
    assert_eq(2, $pdo->rollbacks);
    assert_eq([], $agents);

    // DB failure after secret storage -> rollback + compensating DELETE /secrets/{ref}
    $deletedSecrets = [];
    $failOnAgentInsert = true;
    set_broker_handler(function (string $method, string $path) use (&$deletedSecrets): array {
        if ($method === 'POST' && $path === '/secrets') {
            return ['secret_ref' => 'sec_' . str_repeat('b', 32), 'account' => '@novabot'];
        }
        if ($method === 'DELETE' && str_starts_with($path, '/secrets/')) {
            $deletedSecrets[] = $path;
            return ['deleted' => true];
        }
        return [];
    });
    assert_throws(PDOException::class, fn() => confirm_agent_session($sid, $uA, ['telegram_token' => '123:abc']));
    assert_eq(['/secrets/sec_' . str_repeat('b', 32)], $deletedSecrets);
    assert_eq(3, $pdo->rollbacks);

    // Successful confirm -> commits, then duplicate confirm -> 409
    $failOnAgentInsert = false;
    $out = confirm_agent_session($sid, $uA, ['telegram_token' => '123:abc']);
    assert_eq('Nova', $out['name']);
    assert_eq(1, $pdo->commits);
    assert_throws(HttpError::class, fn() => confirm_agent_session($sid, $uA, ['telegram_token' => '123:abc']), 409);
    set_broker_handler(null);
});

test('enqueue maps only 23505 on one_active_job_per_agent to null', function () {
    $agent = ['id' => '11111111-1111-4111-8111-111111111111', 'tenant_id' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'];

    set_pdo(new MockPdo(function () {
        throw make_pdo_exception('23505', 'duplicate key value violates unique constraint "one_active_job_per_agent"');
    }));
    assert_eq(null, enqueue($agent, 'enable'));

    set_pdo(new MockPdo(function () {
        throw make_pdo_exception('08006', 'connection failure');
    }));
    assert_throws(PDOException::class, fn() => enqueue($agent, 'enable'));
});

test('Docker cleanup failure throws instead of reporting success', function () {
    $id = '11111111-1111-4111-8111-111111111111';
    // Idempotent 404s succeed
    remove_all($id, fn() => [404, '{"message":"no such"}'], 'af-egress');

    // Docker 29: disconnecting egress from a network that does not exist yet answers 500 "not connected"
    remove_all($id, function (string $method, string $path): array {
        if (str_ends_with($path, '/disconnect')) {
            return [500, '{"message":"container abc is not connected to the network af-net-x"}'];
        }
        return [404, '{"message":"not found"}'];
    }, 'af-egress');

    // HTTP 500 on volume delete throws
    assert_throws(RuntimeException::class, function () use ($id) {
        remove_all($id, function (string $method, string $path): array {
            if (str_contains($path, '/volumes/')) {
                return [500, '{"message":"volume in use"}'];
            }
            return [404, '{"message":"not found"}'];
        }, 'af-egress');
    });
});

test('broker re-attaches egress only to its own agent networks', function () {
    $connected = [];
    $transport = function (string $method, string $path, mixed $body = null) use (&$connected): array {
        if ($method === 'GET' && str_starts_with($path, '/networks?')) {
            return [200, json_encode([
                ['Name' => 'af-net-a', 'Labels' => ['af.managed' => 'true', 'af.egress' => 'af-egress']],
                ['Name' => 'af-net-b', 'Labels' => ['af.managed' => 'true']],                          // legacy, unlabelled
                ['Name' => 'af-net-c', 'Labels' => ['af.managed' => 'true', 'af.egress' => 'af-egress']],
                ['Name' => 'af-net-other', 'Labels' => ['af.managed' => 'true', 'af.egress' => 'af-egress-ci']],
            ])];
        }
        if ($method === 'GET' && str_starts_with($path, '/networks/')) {
            $members = $path === '/networks/af-net-c' ? ['x' => ['Name' => 'af-egress']] : ['y' => ['Name' => 'af-agent-1']];
            return [200, json_encode(['Containers' => $members])];
        }
        if ($method === 'POST' && str_ends_with($path, '/connect')) {
            $connected[] = $path;
            return [200, ''];
        }
        return [404, '{}'];
    };
    assert_eq(2, ensure_egress_links($transport, 'af-egress'), 'networks fixed');
    assert_eq(['/networks/af-net-a/connect', '/networks/af-net-b/connect'], $connected);

    // Docker failure on connect is reported, not swallowed
    assert_throws(RuntimeException::class, fn() => ensure_egress_links(function (string $m, string $p) {
        if ($m === 'GET' && str_starts_with($p, '/networks?')) return [200, json_encode([['Name' => 'af-net-a', 'Labels' => ['af.egress' => 'af-egress']]])];
        if ($m === 'GET') return [200, json_encode(['Containers' => []])];
        return [500, '{"message":"boom"}'];
    }, 'af-egress'));
});

test('worker restart recovery re-queues interrupted running jobs without failing agents', function () {
    $aid = '11111111-1111-4111-8111-111111111111';
    $jid = '22222222-2222-4222-8222-222222222222';
    $tid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    $job = ['id' => $jid, 'tenant_id' => $tid, 'agent_id' => $aid, 'type' => 'create', 'state' => 'running'];
    $agentState = 'starting';
    $events = [];

    set_pdo(new MockPdo(function (string $sql, array $params) use (&$job, &$agentState, &$events): array {
        if (str_starts_with($sql, "SELECT * FROM jobs WHERE state='running'")) {
            return ['rows' => $job['state'] === 'running' ? [$job] : []];
        }
        if (str_starts_with($sql, "SELECT * FROM jobs WHERE state='rolling_back'")) {
            return ['rows' => []];
        }
        if (str_starts_with($sql, "UPDATE jobs SET state='queued'")) {
            $job['state'] = 'queued';
            return ['rows' => []];
        }
        if (str_starts_with($sql, 'INSERT INTO events')) {
            $events[] = $params[3];
            return ['rows' => []];
        }
        return ['rows' => []];
    }));

    $count = recover_interrupted_jobs(true);
    assert_eq(1, $count);
    assert_eq('queued', $job['state']);
    assert_eq('starting', $agentState);
    assert_eq(['job_recovered'], $events);
});

test('create pulls the image in its own step, with a timeout and lease longer than the pull', function () {
    $aid = '11111111-1111-4111-8111-111111111111';
    $agent = [
        'id' => $aid, 'tenant_id' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'name' => 'Nova', 'job' => 'support',
        'instructions' => 'Be helpful.', 'prohibited_tasks' => '[]', 'channel_type' => 'telegram',
        'secret_ref' => 'sec_' . str_repeat('a', 32), 'runtime' => 'hermes', 'model' => 'claude-haiku-5-5', 'allowed_users' => '[]',
    ];
    $leases = [];
    set_pdo(new MockPdo(function (string $sql, array $params) use ($agent, &$leases): array {
        if (str_starts_with($sql, 'SELECT * FROM agents WHERE id=?')) {
            return ['rows' => [$agent]];
        }
        if (str_starts_with($sql, 'UPDATE jobs SET current_step=?')) {
            $leases[$params[0]] = $params[1];
        }
        return ['rows' => []];
    }));
    $calls = [];
    set_broker_handler(function (string $method, string $path, ?array $json, array $query, int $timeout) use (&$calls): array {
        $calls[] = "$method $path $timeout";
        return str_ends_with($path, '/create') ? ['container_id' => 'c1'] : [];
    });
    run_job(['id' => '22222222-2222-4222-8222-222222222222', 'agent_id' => $aid, 'type' => 'create']);
    set_broker_handler(null);

    assert_eq([
        'POST /images/hermes/pull ' . BROKER_PULL_TIMEOUT,
        "POST /agents/$aid/create " . BROKER_TIMEOUT,
        "POST /agents/$aid/start " . BROKER_TIMEOUT,
    ], $calls);
    // The API outwaits the broker's Docker pull, and the lease outlives the API's wait.
    assert_true(BROKER_PULL_TIMEOUT > IMAGE_PULL_TIMEOUT, 'API must wait longer than the broker pull');
    assert_true($leases['pull_image'] > BROKER_PULL_TIMEOUT, 'pull lease must outlive the pull call');
    assert_true($leases['create_container'] > BROKER_TIMEOUT, 'create lease must outlive the create call');
});

test('broker pulls a missing pinned image once and never pulls an existing one', function () {
    $image = 'nousresearch/hermes-agent:v1@sha256:' . str_repeat('a', 64);
    $calls = [];
    $present = false;
    $transport = function (string $method, string $path, mixed $body, string $ct, int $timeout) use (&$calls, &$present): array {
        $calls[] = "$method " . strtok($path, '?') . " $timeout";
        if ($method === 'GET') {
            return $present ? [200, '{}'] : [404, '{"message":"no such image"}'];
        }
        $present = true;
        return [200, '{}'];
    };
    assert_eq(true, ensure_image($image, $transport));
    assert_eq(['GET /images/' . rawurlencode($image) . '/json 30', 'POST /images/create ' . IMAGE_PULL_TIMEOUT], $calls);
    $calls = [];
    assert_eq(false, ensure_image($image, $transport));
    assert_eq(1, count($calls));
});

test('switch only queues valid transitions and is a no-op when already there', function () {
    assert_eq('enable', switch_job_type('inactive', true));
    assert_eq('create', switch_job_type('failed', true));
    assert_eq('disable', switch_job_type('active', false));
    assert_eq(null, switch_job_type('active', true));
    assert_eq(null, switch_job_type('inactive', false));
    assert_eq(null, switch_job_type('failed', false));
    assert_throws(HttpError::class, fn() => switch_job_type('starting', false), 409);
    assert_throws(HttpError::class, fn() => switch_job_type('stopping', true), 409);
});

test('switch queues the job and moves the agent in one transaction', function () {
    $aid = '11111111-1111-4111-8111-111111111111';
    $u = ['id' => 'u1', 'tenant_id' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'];
    $agent = [
        'id' => $aid, 'tenant_id' => $u['tenant_id'], 'state' => 'active', 'enabled' => true, 'name' => 'Nova', 'job' => 'x',
        'channel_type' => 'telegram', 'channel_account' => '@nova', 'runtime' => 'openclaw', 'model' => 'm',
        'state_reason' => null, 'last_message_at' => null, 'created_at' => '2026-01-01T00:00:00Z', 'allowed_users' => '[]',
    ];
    $log = [];
    $dupJob = false;
    $pdo = new MockPdo(function (string $sql, array $params) use (&$agent, &$log, &$dupJob, &$pdo): array {
        if (str_contains($sql, 'FROM agents WHERE id=?')) {
            $log[] = str_contains($sql, 'FOR UPDATE') ? 'lock' : 'read';
            return ['rows' => [$agent]];
        }
        if (str_starts_with($sql, 'INSERT INTO jobs')) {
            if ($dupJob) {
                throw make_pdo_exception('23505', 'duplicate key value violates unique constraint "one_active_job_per_agent"');
            }
            $log[] = 'job:' . $params[3] . ($pdo->inTransaction() ? ' (tx)' : '');
            return ['rows' => []];
        }
        if (str_starts_with($sql, 'UPDATE agents SET enabled=?')) {
            $log[] = 'agent:' . $params[1] . ($pdo->inTransaction() ? ' (tx)' : '');
            $agent['state'] = $params[1];
        }
        return ['rows' => []];
    });
    set_pdo($pdo);

    $out = switch_agent($aid, $u, false);
    assert_eq(['lock', 'job:disable (tx)', 'agent:stopping (tx)', 'read'], $log);
    assert_eq(1, $pdo->commits);
    assert_eq('stopping', $out['state']);

    // Already active and switched on: nothing queued, nothing changed.
    $agent['state'] = 'active';
    $log = [];
    switch_agent($aid, $u, true);
    assert_eq(['lock', 'read'], $log);

    // Another job slipped in: 409 and the transaction is rolled back (agent not moved).
    $dupJob = true;
    assert_throws(HttpError::class, fn() => switch_agent($aid, $u, false), 409);
    assert_eq(1, $pdo->rollbacks);
    assert_eq('active', $agent['state']);
});

test('agents stuck in starting/stopping without a job are settled from the container', function () {
    $rows = [
        ['id' => 'a-run', 'tenant_id' => 't', 'state' => 'starting'],
        ['id' => 'a-stop', 'tenant_id' => 't', 'state' => 'stopping'],
        ['id' => 'a-dead', 'tenant_id' => 't', 'state' => 'starting'],
    ];
    $updates = [];
    set_pdo(new MockPdo(function (string $sql, array $params) use ($rows, &$updates): array {
        if (str_starts_with($sql, "SELECT * FROM agents WHERE state IN ('starting','stopping')")) {
            return ['rows' => $rows];
        }
        if (str_starts_with($sql, 'UPDATE agents SET state=?')) {
            $updates[$params[3]] = [$params[0], $params[1], $params[4]];
            return ['rows' => [['id' => $params[3]]]];
        }
        return ['rows' => []];
    }));
    set_broker_handler(fn(string $m, string $path) => ['running' => $path === '/agents/a-run/status']);
    assert_eq(3, settle_stuck_agents());
    set_broker_handler(null);
    assert_eq(['active', 'true', 'starting'], $updates['a-run']);
    assert_eq(['inactive', 'false', 'stopping'], $updates['a-stop']);
    assert_eq(['failed', 'false', 'starting'], $updates['a-dead']);
});

test('AgentFather refuses an answer that would push the instructions over the limit', function () {
    $answers = complete_answers();
    unset($answers['knowledge'], $answers['tone'], $answers['language'], $answers['prohibited'], $answers['fallback'],
          $answers['runtime'], $answers['model'], $answers['channel'], $answers['access']);
    $answers['purpose'] = str_repeat('p', 160);
    $answers['company'] = str_repeat('c', 199);
    $state = ['answers' => $answers, 'asking' => 'knowledge'];

    // 3000 characters is fine on its own, but not with long purpose/company/tones: refused right away.
    $tooLong = str_repeat('k', 3000);
    $state1 = $state;
    $state1['answers']['tone'] = array_map(fn($i) => str_repeat("t$i", 140), range(1, 4));
    [$same, $err] = af_answer($state1, [], $tooLong);
    assert_true($err !== null && str_contains($err, 'shorten this answer by at least'), 'expected a length error');
    assert_eq('knowledge', $same['asking'], 'stays on the same question');

    // Without the long tones the same knowledge fits, and the finished config validates.
    [$next, $err] = af_answer($state, [], $tooLong);
    assert_eq(null, $err);
    $full = $next['answers'] + complete_answers();
    [$cfg, $verr] = validate_config(af_build_config($full));
    assert_eq(null, $verr);
    assert_true(mb_strlen($cfg['instructions']) <= AF_INSTRUCTIONS_MAX);
});

test('AgentFather offers no model choices when every provider is disconnected', function () {
    $GLOBALS['af_enabled_providers'] = [];
    $q = af_question('model');
    unset($GLOBALS['af_enabled_providers']);
    // The UI shows its recovery actions for exactly this shape: choice-only and empty.
    assert_eq([], $q['options']);
    assert_eq(false, $q['other']);
    assert_eq('single', $q['kind']);
});

test('broker keeps the data volume unless asked to drop it', function () {
    $id = '11111111-1111-4111-8111-111111111111';
    $deleted = [];
    $transport = function (string $method, string $path) use (&$deleted): array {
        if ($method === 'DELETE') {
            $deleted[] = strtok($path, '?');
        }
        return [404, '{"message":"no such"}'];
    };
    remove_all($id, $transport, 'af-egress', keepVolume: true);
    assert_eq(["/containers/af-agent-$id", "/networks/af-net-$id"], $deleted);
    $deleted = [];
    remove_all($id, $transport, 'af-egress');
    assert_eq("/volumes/af-data-$id", end($deleted));
});

test('Off/On and re-creating an agent that ran keep its data; a failed first create does not', function () {
    $aid = '11111111-1111-4111-8111-111111111111';
    $agent = [
        'id' => $aid, 'tenant_id' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'name' => 'Nova', 'job' => 'support',
        'instructions' => 'Be helpful.', 'prohibited_tasks' => '[]', 'channel_type' => 'telegram',
        'secret_ref' => 'sec_' . str_repeat('a', 32), 'runtime' => 'openclaw', 'model' => 'claude-haiku-5-5', 'allowed_users' => '[]',
    ];
    $ranBefore = false;
    set_pdo(new MockPdo(function (string $sql) use ($agent, &$ranBefore): array {
        if (str_starts_with($sql, 'SELECT * FROM agents WHERE id=?')) {
            return ['rows' => [$agent]];
        }
        if (str_starts_with($sql, "SELECT 1 FROM events WHERE agent_id=? AND type='start_and_health_check'")) {
            return ['rows' => $ranBefore ? [['?column?' => 1]] : []];
        }
        if (str_starts_with($sql, 'SELECT current_step')) {
            return ['rows' => [['current_step' => 'start_and_health_check']]];
        }
        return ['rows' => []];
    }));
    $seen = [];
    set_broker_handler(function (string $method, string $path, ?array $json, array $query) use (&$seen): array {
        if (str_ends_with($path, '/start')) {
            throw new StepError('Agent runtime exited during start', 500);  // force a rollback
        }
        $seen["$method " . (str_ends_with($path, '/create') ? 'create' : (str_ends_with($path, '/pull') ? 'pull' : 'delete'))] = $query['keep_data'] ?? 'no';
        return ['container_id' => 'c1'];
    });
    $job = fn(string $type) => ['id' => '22222222-2222-4222-8222-222222222222', 'agent_id' => $aid, 'type' => $type];

    run_job($job('enable'));                       // Off -> On
    assert_eq(['true', 'true'], [$seen['POST create'], $seen['DELETE delete']]);

    $seen = [];
    run_job($job('create'));                       // first create that never ran: data may go
    assert_eq(['no', 'no'], [$seen['POST create'], $seen['DELETE delete']]);

    $seen = [];
    $ranBefore = true;
    run_job($job('create'));                       // re-create after a failure, agent had run before
    assert_eq(['true', 'true'], [$seen['POST create'], $seen['DELETE delete']]);
    set_broker_handler(null);
});

test('reconcile surfaces unhealthy agents after a grace period and only polls running ones', function () {
    $agent = ['id' => 'health-1', 'tenant_id' => 't', 'state' => 'active', 'last_message_at' => null, 'channel_type' => 'telegram'];
    $polledSql = null;
    $events = [];
    set_pdo(new MockPdo(function (string $sql, array $params) use (&$agent, &$polledSql, &$events): array {
        if (str_starts_with($sql, "SELECT * FROM agents WHERE state IN ('active','unhealthy')")) {
            $polledSql = $sql;
            return ['rows' => [$agent]];
        }
        if (str_starts_with($sql, 'UPDATE agents SET state=?')) {     // guarded transition
            $agent['state'] = $params[0];
            return ['rows' => [['id' => $agent['id']]]];
        }
        if (str_starts_with($sql, 'INSERT INTO events')) {
            $events[] = $params[3];
        }
        return ['rows' => []];
    }));
    $health = 'unhealthy';
    set_broker_handler(function () use (&$health): array {
        return ['running' => true, 'health' => $health, 'last_activity' => null];
    });

    reconcile();
    reconcile();
    assert_eq('active', $agent['state'], 'a short blip is not reported');
    reconcile();
    assert_eq('unhealthy', $agent['state'], 'reported after UNHEALTHY_CHECKS passes');
    $health = 'healthy';
    reconcile();
    assert_eq('active', $agent['state'], 'back to active once healthy');
    assert_eq(['health_degraded', 'health_recovered'], $events);
    // Inactive agents are no longer polled.
    assert_true(!str_contains((string)$polledSql, "'inactive'"), 'inactive agents must not be polled');
    set_broker_handler(null);
});

test('an unhealthy agent can still be switched off', function () {
    assert_eq('disable', switch_job_type('unhealthy', false));
    assert_eq(null, switch_job_type('unhealthy', true));
});

echo "\nSummary: $passed passed, $failed failed\n";
exit($failed > 0 ? 1 : 0);
