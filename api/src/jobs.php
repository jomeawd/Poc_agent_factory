<?php
declare(strict_types=1);
/* Postgres-backed job queue + reconciler. Hands create/enable/disable/delete jobs to the broker. */

require_once __DIR__ . '/db.php';

final class StepError extends RuntimeException {}

/** @internal Allows tests to inject a fake broker handler without HTTP/Docker. */
function set_broker_handler(?callable $handler): void
{
    broker_handler($handler, true);
}

function broker_handler(?callable $override = null, bool $replace = false): ?callable
{
    static $handler = null;
    if ($replace) {
        $handler = $override;
    }
    return $handler;
}

/** Default wait for a broker call; covers create plus the 120 s health check of start. */
const BROKER_TIMEOUT = 150;
/** Image pulls: the broker gives Docker 600 s, the API waits a bit longer so it never gives up first. */
const BROKER_PULL_TIMEOUT = 660;
/** A job's lease must outlast the broker call of its current step, or recovery would re-run it. */
const STEP_LEASE_MARGIN = 60;

/** Calls the Deployment Broker. Errors become StepError with a safe message (never a secret). */
function broker(string $method, string $path, ?array $json = null, array $query = [], int $timeout = BROKER_TIMEOUT): array
{
    $custom = broker_handler();
    if ($custom !== null) {
        return $custom($method, $path, $json, $query, $timeout);
    }

    $url = rtrim((string)getenv('BROKER_URL'), '/') . $path . ($query ? '?' . http_build_query($query) : '');
    $ch = curl_init($url);
    $headers = ['X-Broker-Token: ' . getenv('BROKER_TOKEN')];
    $opts = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 5,
    ];
    if ($json !== null) {
        $headers[] = 'Content-Type: application/json';
        $opts[CURLOPT_POSTFIELDS] = json_encode($json);
    }
    $opts[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($ch, $opts);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false || $code === 0) {
        throw new StepError('Deployment broker unreachable');
    }
    $data = json_decode($body, true);
    if ($code >= 400) {
        $detail = is_array($data) && is_string($data['detail'] ?? null) ? $data['detail'] : "broker error HTTP $code";
        throw new StepError($detail, $code);
    }
    return is_array($data) ? $data : [];
}

/**
 * Enqueues a job for an agent.
 * Returns null ONLY on unique-index violation (SQLSTATE 23505 on one_active_job_per_agent).
 * Other PDO errors are logged safely and rethrown.
 */
function enqueue(array $agent, string $type): ?string
{
    $id = uuid4();
    try {
        q(
            "INSERT INTO jobs(id, tenant_id, agent_id, type, state, idempotency_key) VALUES (?,?,?,?,'queued',?)",
            $id,
            $agent['tenant_id'],
            $agent['id'],
            $type,
            "{$agent['id']}:$type:$id"
        );
    } catch (PDOException $e) {
        if ((string)$e->getCode() === '23505' && str_contains($e->getMessage(), 'one_active_job_per_agent')) {
            return null;
        }
        error_log('enqueue error: SQLSTATE ' . $e->getCode());
        throw $e;
    }
    event($agent['tenant_id'], $agent['id'], "job_{$type}_queued", 'queued', null, $id);
    return $id;
}

function manifest(array $a): array
{
    return [
        'agent_id' => $a['id'],
        'name' => $a['name'],
        'job' => $a['job'],
        'instructions' => $a['instructions'],
        'prohibited_tasks' => json_decode($a['prohibited_tasks'], true),
        'channel_type' => $a['channel_type'],
        'secret_ref' => $a['secret_ref'],
        'runtime' => $a['runtime'],
        'model' => $a['model'],
        'allowed_users' => json_decode($a['allowed_users'], true),
    ];
}

/**
 * Whether a job must keep the agent's data volume (sessions, memory) when it (re)creates the
 * container or rolls back. Only a first creation that never got the agent running may drop it;
 * Off/On and re-creating an agent that already ran always keep it.
 */
function keeps_agent_data(string $jobType, string $agentId): bool
{
    if ($jobType === 'enable') {
        return true;
    }
    return q1(
        "SELECT 1 FROM events WHERE agent_id=? AND type='start_and_health_check' AND state='completed' LIMIT 1",
        $agentId
    ) !== null;
}

function set_agent(string $id, array $fields): void
{
    $cols = implode(', ', array_map(fn($k) => "$k=?", array_keys($fields)));
    q("UPDATE agents SET $cols WHERE id=?", ...[...array_values($fields), $id]);
}

function renew_job_lease(string $jid, int $seconds = 180): void
{
    q(
        "UPDATE jobs SET lease_expires_at = now() + (? * interval '1 second'), updated_at=now() WHERE id=? AND state='running'",
        $seconds,
        $jid
    );
}

/**
 * Recovers interrupted or stale-lease jobs without losing them or wrongly failing agents.
 * - On worker startup ($startup = true), any 'running' job belonged to the previous dead worker and is re-queued.
 * - Periodically ($startup = false), any 'running' job with an expired lease is re-queued.
 * - Any interrupted 'rolling_back' job completes best-effort cleanup and is marked failed.
 */
function recover_interrupted_jobs(bool $startup = false): int
{
    $recovered = 0;
    $runningSql = $startup
        ? "SELECT * FROM jobs WHERE state='running'"
        : "SELECT * FROM jobs WHERE state='running' AND (lease_expires_at IS NULL OR lease_expires_at < now())";

    foreach (q($runningSql) as $j) {
        q(
            "UPDATE jobs SET state='queued', current_step=NULL, lease_expires_at=NULL, updated_at=now() WHERE id=? AND state='running'",
            $j['id']
        );
        event($j['tenant_id'], $j['agent_id'], 'job_recovered', 'queued', 'Re-queued after worker interruption', $j['id']);
        $recovered++;
    }

    $rbSql = $startup
        ? "SELECT * FROM jobs WHERE state='rolling_back'"
        : "SELECT * FROM jobs WHERE state='rolling_back' AND (lease_expires_at IS NULL OR lease_expires_at < now())";

    foreach (q($rbSql) as $j) {
        $a = q1('SELECT * FROM agents WHERE id=?', $j['agent_id']);
        if ($a) {
            $query = ['secret_ref' => $a['secret_ref'] ?? '', 'keep_secret' => 'true'];
            if (keeps_agent_data($j['type'], $a['id'])) {
                $query['keep_data'] = 'true';
            }
            try {
                broker('DELETE', "/agents/{$a['id']}", null, $query);
            } catch (StepError) {
                // Cleanup will run again on retry.
            }
            set_agent($a['id'], [
                'state' => 'failed',
                'enabled' => false,
                'container_id' => null,
                'state_reason' => 'Interrupted during rollback; retry to re-create',
            ]);
        }
        q("UPDATE jobs SET state='failed', error='Interrupted during rollback', lease_expires_at=NULL, updated_at=now() WHERE id=?", $j['id']);
        $recovered++;
    }

    return $recovered;
}

function run_job(array $job): void
{
    $a = q1('SELECT * FROM agents WHERE id=?', $job['agent_id']);
    if (!$a) {
        q("UPDATE jobs SET state='failed', error='Agent not found', lease_expires_at=NULL, updated_at=now() WHERE id=?", $job['id']);
        return;
    }
    $tenant = $a['tenant_id'];
    $jid = $job['id'];
    $aid = $a['id'];

    $step = function (string $name, callable $fn, int $timeout = BROKER_TIMEOUT) use ($tenant, $aid, $jid) {
        q(
            "UPDATE jobs SET current_step=?, lease_expires_at = now() + (? * interval '1 second'), updated_at=now() WHERE id=?",
            $name,
            $timeout + STEP_LEASE_MARGIN,
            $jid
        );
        $t0 = microtime(true);
        try {
            $res = $fn();
        } catch (StepError $e) {
            event($tenant, $aid, $name, 'failed', $e->getMessage(), $jid, (int)((microtime(true) - $t0) * 1000));
            throw $e;
        }
        event($tenant, $aid, $name, 'completed', null, $jid, (int)((microtime(true) - $t0) * 1000));
        return $res;
    };

    // Decided before the job runs: its own health check must not turn a first create into a "re-create".
    $keepData = in_array($job['type'], ['create', 'enable'], true) && keeps_agent_data($job['type'], $aid);
    $dataQuery = $keepData ? ['keep_data' => 'true'] : [];

    try {
        switch ($job['type']) {
            case 'create':
            case 'enable':
                set_agent($aid, ['state' => 'starting', 'state_reason' => null]);
                $step('validate_config', function () use ($a) {
                    if ($a['channel_type'] !== 'telegram') {
                        throw new StepError('WhatsApp is not available in this POC (OpenClaw only supports WhatsApp Web linking). See README.');
                    }
                });
                $step(
                    'pull_image',
                    fn() => broker('POST', "/images/{$a['runtime']}/pull", null, [], BROKER_PULL_TIMEOUT),
                    BROKER_PULL_TIMEOUT
                );
                $res = $step('create_container', fn() => broker('POST', "/agents/$aid/create", manifest($a), $dataQuery));
                set_agent($aid, ['container_id' => $res['container_id']]);
                $step('start_and_health_check', fn() => broker('POST', "/agents/$aid/start"));
                set_agent($aid, ['state' => 'active', 'state_reason' => null]);
                break;
            case 'disable':
                set_agent($aid, ['state' => 'stopping']);
                $step('stop_container', fn() => broker('POST', "/agents/$aid/stop"));
                set_agent($aid, ['state' => 'inactive']);
                break;
            case 'delete':
                $step('delete_container_and_channel', fn() => broker('DELETE', "/agents/$aid", null, ['secret_ref' => $a['secret_ref'] ?? '']));
                set_agent($aid, ['state' => 'deleted', 'enabled' => false, 'container_id' => null]);
                break;
        }
        q("UPDATE jobs SET state='completed', current_step=NULL, lease_expires_at=NULL, updated_at=now() WHERE id=?", $jid);
    } catch (Throwable $e) {
        $reason = $e instanceof StepError ? $e->getMessage() : 'Unexpected error in the platform';
        if (!$e instanceof StepError) {
            error_log("job $jid crashed: " . get_class($e));
        }
        $failedStep = q1('SELECT current_step FROM jobs WHERE id=?', $jid)['current_step'] ?? null;
        if (in_array($job['type'], ['create', 'enable'], true)) {
            q("UPDATE jobs SET state='rolling_back', lease_expires_at = now() + interval '180 seconds', updated_at=now() WHERE id=?", $jid);
            try {
                broker('DELETE', "/agents/$aid", null, ['secret_ref' => $a['secret_ref'] ?? '', 'keep_secret' => 'true'] + $dataQuery);
                event($tenant, $aid, 'rollback', 'completed', null, $jid);
            } catch (StepError $e2) {
                event($tenant, $aid, 'rollback', 'failed', $e2->getMessage() . ' (cleanup will run on retry)', $jid);
            }
            set_agent($aid, [
                'state' => 'failed',
                'enabled' => false,
                'container_id' => null,
                'state_reason' => "$reason (step: $failedStep)",
            ]);
        } elseif ($job['type'] === 'delete') {
            set_agent($aid, ['state' => 'failed', 'state_reason' => "Delete failed: $reason"]);
        } else {
            set_agent($aid, ['state' => 'failed', 'state_reason' => $reason]);
        }
        q("UPDATE jobs SET state='failed', error=?, lease_expires_at=NULL, updated_at=now() WHERE id=?", $reason, $jid);
    }
}

function claim_job(): ?array
{
    return q1("UPDATE jobs SET state='running', lease_expires_at = now() + interval '180 seconds', updated_at=now() WHERE id = (
                 SELECT id FROM jobs WHERE state='queued' ORDER BY created_at
                 FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *");
}

/**
 * Unsticks agents left in starting/stopping with no job behind them (written by an older
 * version, or by a crash between two statements): the UI locks the switch in those states.
 * The container decides: running -> active, otherwise inactive (stopping) or failed (starting).
 * Guarded on the state read, so a switch made in the meantime is never overwritten.
 */
function settle_stuck_agents(): int
{
    $rows = q("SELECT * FROM agents WHERE state IN ('starting','stopping') AND NOT EXISTS (
                 SELECT 1 FROM jobs j WHERE j.agent_id=agents.id AND j.state IN ('queued','running','rolling_back'))");
    $settled = 0;
    foreach ($rows as $a) {
        try {
            $running = (bool)(broker('GET', "/agents/{$a['id']}/status")['running'] ?? false);
        } catch (StepError) {
            continue;
        }
        [$state, $enabled, $reason] = match (true) {
            $running => ['active', true, null],
            $a['state'] === 'stopping' => ['inactive', false, null],
            default => ['failed', false, 'Start was interrupted; switch on to retry'],
        };
        $done = q(
            "UPDATE agents SET state=?, enabled=?, state_reason=? WHERE id=? AND state=? AND NOT EXISTS (
               SELECT 1 FROM jobs j WHERE j.agent_id=agents.id AND j.state IN ('queued','running','rolling_back'))
             RETURNING id",
            $state,
            $enabled,
            $reason,
            $a['id'],
            $a['state']
        );
        if ($done) {
            event($a['tenant_id'], $a['id'], 'state_settled', $state, "was {$a['state']} with no job");
            $settled++;
        }
    }
    return $settled;
}

/** Consecutive unhealthy reconcile passes (5 s apart) before an agent is shown as Unhealthy. */
const UNHEALTHY_CHECKS = 3;

/**
 * Updates an agent only if it is still in the state read and no job took it over in the meantime,
 * so the reconciler never overwrites a switch the user just made.
 */
function transition_agent(array $a, array $fields): bool
{
    $cols = implode(', ', array_map(fn($k) => "$k=?", array_keys($fields)));
    return q(
        "UPDATE agents SET $cols WHERE id=? AND state=? AND NOT EXISTS (
           SELECT 1 FROM jobs j WHERE j.agent_id=agents.id AND j.state IN ('queued','running','rolling_back'))
         RETURNING id",
        ...[...array_values($fields), $a['id'], $a['state']]
    ) !== [];
}

/**
 * Makes the list reflect where containers really are, and records message activity.
 * Only agents that should be running are polled (stopped ones cannot drift or receive messages).
 * Health: a running container whose health check keeps failing (e.g. lost Telegram) is shown
 * as Unhealthy after UNHEALTHY_CHECKS passes, and back to Active once healthy again.
 */
function reconcile(): void
{
    static $unhealthyStreak = [];
    settle_stuck_agents();
    $rows = q("SELECT * FROM agents WHERE state IN ('active','unhealthy') AND NOT EXISTS (
                 SELECT 1 FROM jobs j WHERE j.agent_id=agents.id AND j.state IN ('queued','running','rolling_back'))");
    foreach ($rows as $a) {
        $id = $a['id'];
        try {
            $s = broker('GET', "/agents/$id/status");
        } catch (StepError) {
            continue;
        }
        if (!$s['running']) {
            unset($unhealthyStreak[$id]);
            if (transition_agent($a, ['state' => 'failed', 'enabled' => false, 'state_reason' => 'Container stopped unexpectedly'])) {
                event($a['tenant_id'], $id, 'container_lost', 'failed');
            }
            continue;
        }
        if (($s['health'] ?? null) === 'unhealthy') {
            $unhealthyStreak[$id] = ($unhealthyStreak[$id] ?? 0) + 1;
            if ($a['state'] === 'active' && $unhealthyStreak[$id] >= UNHEALTHY_CHECKS
                && transition_agent($a, ['state' => 'unhealthy', 'state_reason' => 'Health check failing (for example, Telegram or the model is unreachable)'])) {
                event($a['tenant_id'], $id, 'health_degraded', 'unhealthy');
            }
        } else {
            unset($unhealthyStreak[$id]);
            if ($a['state'] === 'unhealthy' && ($s['health'] ?? null) === 'healthy'
                && transition_agent($a, ['state' => 'active', 'state_reason' => null])) {
                event($a['tenant_id'], $id, 'health_recovered', 'active');
            }
        }
        if (!empty($s['last_activity'])) {
            $ts = (float)$s['last_activity'];
            $prev = $a['last_message_at'] ? (float)(new DateTimeImmutable($a['last_message_at']))->format('U.u') : 0.0;
            if ($ts > $prev + 0.001) {
                q('UPDATE agents SET last_message_at=to_timestamp(?) WHERE id=?', $ts, $id);
                event($a['tenant_id'], $id, 'message_handled', 'completed', null, null, null, $a['channel_type']);
            }
        }
    }
}
