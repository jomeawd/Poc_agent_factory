<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
/*
 * Deployment Broker: the only component allowed to talk to Docker.
 * Narrow API: secrets, create, start, stop, delete, status, health.
 * Every request is authenticated with BROKER_TOKEN and validated against the agent
 * manifest schema before any Docker call. Secrets never leave this service except as
 * env vars injected into the one agent container that owns them.
 */

require_once __DIR__ . '/lib.php';

function out(mixed $data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

set_exception_handler(function (Throwable $e) {
    if ($e instanceof HttpError) {
        out(['detail' => $e->getMessage()], $e->getCode());
    }
    logline('error: ' . get_class($e) . ': ' . $e->getMessage());
    out(['detail' => 'Deployment broker internal error'], 500);
});

assert_broker_config();

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path !== '/health' || $method !== 'GET') {
    $expected = getenv('BROKER_TOKEN');
    $provided = $_SERVER['HTTP_X_BROKER_TOKEN'] ?? '';
    if (!broker_authenticate(is_string($expected) ? $expected : null, $provided)) {
        fail(401, 'unauthorized');
    }
}

function body(): array
{
    $d = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($d)) {
        fail(400, 'body must be a JSON object');
    }
    return $d;
}

$m = [];
$route = function (string $verb, string $p) use ($method, $path, &$m): bool {
    return $method === $verb && (bool)preg_match("#^$p$#", $path, $m);
};

if ($route('GET', '/health')) {
    docker_ok('GET', '/_ping');
    // Self-heal agent egress links at most every 30 s (the compose healthcheck calls this every 5 s).
    $stamp = sys_get_temp_dir() . '/af-egress-check';
    if (!is_file($stamp) || time() - (int)@filemtime($stamp) >= 30) {
        @touch($stamp);
        try {
            $fixed = ensure_egress_links();
            if ($fixed > 0) {
                logline("re-attached egress to $fixed agent network(s)");
            }
        } catch (Throwable $e) {
            logline('egress self-heal failed: ' . get_class($e));
        }
    }
    out(['ok' => true]);
}

if ($route('POST', '/secrets')) {
    $b = body();
    if (($b['kind'] ?? '') !== 'telegram' || !is_string($b['value'] ?? null)) {
        fail(422, 'invalid secret');
    }
    $res = store_telegram_secret($b['value'], 'verify_telegram_token_live');
    logline("stored secret {$res['secret_ref']} for telegram bot {$res['account']}");
    out($res);
}

if ($route('GET', '/providers')) {
    out(providers_status());
}

if ($route('PUT', '/providers/([a-z]+)')) {
    $p = provider_id($m[1]);
    $b = body();
    if (!is_string($b['value'] ?? null) || strlen($b['value']) > 400) {
        fail(422, 'invalid key');
    }
    store_provider_credential($p, $b['value'], 'verify_provider_live');
    logline("provider $p connected from the page");
    out(providers_status());
}

if ($route('DELETE', '/providers/([a-z]+)')) {
    $p = provider_id($m[1]);
    delete_provider_credential($p);
    logline("provider $p disconnected from the page");
    out(providers_status());
}

if ($route('DELETE', '/secrets/(sec_[a-f0-9]{32})')) {
    delete_secret($m[1]);
    logline("deleted secret {$m[1]}");
    out(['deleted' => true]);
}

if ($route('POST', '/images/([a-z]+)/pull')) {
    $image = runtime_image($m[1]);
    $pulled = ensure_image($image);
    if ($pulled) {
        logline("pulled runtime image for {$m[1]}");
    }
    out(['pulled' => $pulled]);
}

if ($route('POST', '/agents/([0-9a-f-]+)/create')) {
    $id = agent_id($m[1]);
    $man = validate_manifest(body(), $id);
    $token = read_secret($man['secret_ref']);
    [$cname, $vname, $nname] = names($id);
    $spec = runtime_spec($man, $vname);
    $image = $spec['image'];
    $egress = getenv('EGRESS_CONTAINER');
    $labels = ['af.managed' => 'true', 'af.agent_id' => $id];

    // The image is pulled by its own step (POST /images/{runtime}/pull). Creating never pulls,
    // so this request stays short and cannot outlive the API's timeout and rollback.
    if (docker('GET', '/images/' . rawurlencode($image) . '/json', null, 'application/json', 30)[0] === 404) {
        fail(409, 'Runtime image is not on the host yet; retry the deployment.');
    }

    // Idempotent: whatever a previous (possibly interrupted) attempt left is removed,
    // so a retry can never produce a second container for this agent. The data volume is
    // reused as is (creating an existing volume is a no-op in Docker).
    $keepData = ($_GET['keep_data'] ?? '') === 'true';
    remove_all($id, keepVolume: true);

    try {
        docker_ok('POST', '/networks/create', ['Name' => $nname, 'Driver' => 'bridge', 'Internal' => true, 'Labels' => $labels + ['af.egress' => $egress]]);
        docker_ok('POST', "/networks/$nname/connect", ['Container' => $egress]);
        docker_ok('POST', '/volumes/create', ['Name' => $vname, 'Labels' => $labels]);
        $proxy = "http://$egress:8888";
        $env = [
            ...$spec['env'],
            "TELEGRAM_BOT_TOKEN=$token",
            "HTTPS_PROXY=$proxy", "HTTP_PROXY=$proxy", "https_proxy=$proxy", "http_proxy=$proxy",
            'NO_PROXY=127.0.0.1,localhost', 'no_proxy=127.0.0.1,localhost',
        ];
        $uid = $spec['uid'];
        $create = [
            'Image' => $image,
            'User' => "$uid:$uid",
            'Env' => $env,
            'Labels' => $labels + ['af.runtime' => $man['runtime']],
            'Healthcheck' => [
                'Test' => $spec['health'],
                'Interval' => 3_000_000_000, 'Timeout' => 5_000_000_000, 'Retries' => 3, 'StartPeriod' => 5_000_000_000,
            ],
            'HostConfig' => [
                // Fixed by the platform, never by the request.
                'NanoCpus' => 1_000_000_000, 'Memory' => 2 * 1024 ** 3, 'PidsLimit' => 512,
                'ReadonlyRootfs' => true, 'Tmpfs' => $spec['tmpfs'], 'Init' => true,
                'CapDrop' => ['ALL'], 'SecurityOpt' => ['no-new-privileges'], 'Privileged' => false,
                'NetworkMode' => $nname,
                'Mounts' => [['Type' => 'volume', 'Source' => $vname, 'Target' => $spec['dir']]],
                'RestartPolicy' => ['Name' => 'unless-stopped'],
            ],
        ];
        if ($spec['entrypoint']) {
            $create['Entrypoint'] = $spec['entrypoint'];
        }
        if ($spec['cmd']) {
            $create['Cmd'] = $spec['cmd'];
        }
        $c = docker_ok('POST', '/containers/create?name=' . $cname, $create);
        docker_ok('PUT', "/containers/{$c['Id']}/archive?path=" . rawurlencode($spec['dir']), tar($spec['files'], $uid), 'application/x-tar');
        logline('created container ' . substr($c['Id'], 0, 12) . " for agent $id");
        out(['container_id' => $c['Id']]);
    } catch (Throwable $e) {
        try {
            remove_all($id, keepVolume: $keepData);
        } catch (Throwable) {
            // Preserve the original failure while attempting best-effort cleanup.
        }
        throw $e;
    }
}

if ($route('POST', '/agents/([0-9a-f-]+)/start')) {
    $id = agent_id($m[1]);
    [$cname] = names($id);
    if (!container($cname)) {
        fail(404, 'Container does not exist.');
    }
    docker_ok('POST', "/containers/$cname/start");
    $deadline = time() + 120;
    while (time() < $deadline) {
        $st = container($cname)['State'] ?? [];
        if (($st['Health']['Status'] ?? '') === 'healthy') {
            logline("agent $id healthy");
            out(['health' => 'healthy']);
        }
        if (in_array($st['Status'] ?? '', ['exited', 'dead'], true)) {
            fail(500, 'Agent runtime exited during start (exit code ' . ($st['ExitCode'] ?? '?') . ').');
        }
        sleep(1);
    }
    fail(504, 'Agent runtime did not become healthy within 120 seconds.');
}

if ($route('POST', '/agents/([0-9a-f-]+)/stop')) {
    $id = agent_id($m[1]);
    [$cname] = names($id);
    if (!container($cname)) {
        out(['status' => 'missing']);
    }
    docker_ok('POST', "/containers/$cname/stop?t=10", null, 'application/json', 30);
    logline("agent $id stopped");
    out(['status' => container($cname)['State']['Status'] ?? 'unknown']);
}

if ($route('DELETE', '/agents/([0-9a-f-]+)')) {
    $id = agent_id($m[1]);
    $keepData = ($_GET['keep_data'] ?? '') === 'true';
    remove_all($id, keepVolume: $keepData);
    $ref = $_GET['secret_ref'] ?? '';
    $keep = ($_GET['keep_secret'] ?? '') === 'true';
    if ($ref !== '' && !$keep) {
        delete_secret($ref);
    }
    logline("agent $id removed (secret kept=" . ($keep ? 'true' : 'false') . ', data kept=' . ($keepData ? 'true' : 'false') . ')');
    out(['deleted' => true]);
}

if ($route('GET', '/agents/([0-9a-f-]+)/status')) {
    $id = agent_id($m[1]);
    [$cname] = names($id);
    $c = container($cname);
    if (!$c) {
        out(['exists' => false, 'running' => false, 'health' => null, 'last_activity' => null]);
    }
    $last = null;
    if ($c['State']['Running']) {
        // Real platform-side signal: newest session-transcript write inside the agent volume.
        $ex = docker_ok('POST', "/containers/$cname/exec", [
            'Cmd' => ['sh', '-c', "find " . STATE_DIR . "/agents /opt/data/sessions -type f -printf '%T@\\n' 2>/dev/null | sort -n | tail -1"],
            'User' => $c['Config']['User'] ?: '1000:1000', 'AttachStdout' => true, 'AttachStderr' => false,
        ]);
        [, $raw] = docker('POST', "/exec/{$ex['Id']}/start", ['Detach' => false, 'Tty' => false]);
        $stdout = '';
        for ($i = 0; $i + 8 <= strlen($raw);) {
            $len = unpack('N', substr($raw, $i + 4, 4))[1];
            if ($raw[$i] === "\x01") {
                $stdout .= substr($raw, $i + 8, $len);
            }
            $i += 8 + $len;
        }
        $last = trim($stdout) !== '' ? (float)trim($stdout) : null;
    }
    out([
        'exists' => true,
        'running' => $c['State']['Running'],
        'health' => $c['State']['Health']['Status'] ?? null,
        'last_activity' => $last,
    ]);
}

fail(404, 'not found');
