<?php
declare(strict_types=1);

const SCHEMA = <<<SQL
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, email text UNIQUE NOT NULL,
  password_hash text NOT NULL, role text NOT NULL DEFAULT 'owner');
CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL, job text NOT NULL,
  instructions text NOT NULL, prohibited_tasks jsonb NOT NULL DEFAULT '[]',
  channel_type text NOT NULL CHECK (channel_type IN ('telegram','whatsapp')),
  channel_account text, secret_ref text, enabled boolean NOT NULL DEFAULT true,
  state text NOT NULL CHECK (state IN ('starting','active','unhealthy','stopping','inactive','failed','delete_failed','deleted')),
  state_reason text, container_id text, last_message_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS agentfather_sessions (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  messages jsonb NOT NULL DEFAULT '[]', draft_config jsonb,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','confirmed','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS jobs (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, agent_id uuid NOT NULL,
  type text NOT NULL CHECK (type IN ('create','enable','disable','delete')),
  state text NOT NULL CHECK (state IN ('queued','running','completed','failed','rolling_back')),
  current_step text, error text, idempotency_key text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS events (
  id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, agent_id uuid, job_id uuid,
  timestamp timestamptz NOT NULL DEFAULT now(), type text NOT NULL, channel text,
  input_summary text, state text, result text, duration_ms integer);
CREATE TABLE IF NOT EXISTS login_attempts (
  email text NOT NULL,
  ip text NOT NULL,
  failures integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (email, ip)
);
-- Added after the brief's 5-table model: runtime choice, model choice, Telegram allowlist.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS runtime text NOT NULL DEFAULT 'openclaw' CHECK (runtime IN ('openclaw','hermes'));
ALTER TABLE agents ADD COLUMN IF NOT EXISTS model text NOT NULL DEFAULT 'claude-sonnet-4-6';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS allowed_users jsonb NOT NULL DEFAULT '[]';
-- Job lease for worker restart recovery.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;
-- 'unhealthy': container running but its health check fails. 'delete_failed': a delete to retry.
-- Widen older databases once (the check looks for the newest state).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agents_state_check'
                 AND pg_get_constraintdef(oid) LIKE '%delete_failed%') THEN
    ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_state_check;
    ALTER TABLE agents ADD CONSTRAINT agents_state_check
      CHECK (state IN ('starting','active','unhealthy','stopping','inactive','failed','delete_failed','deleted'));
  END IF;
END $$;
-- At most one in-flight job per agent: the DB enforces it, not the UI.
CREATE UNIQUE INDEX IF NOT EXISTS one_active_job_per_agent ON jobs(agent_id)
  WHERE state IN ('queued','running','rolling_back');
SQL;

/** @internal Allows tests to inject a mock/fake PDO instance. */
function set_pdo(?PDO $custom): void
{
    pdo($custom, true);
}

function pdo(?PDO $override = null, bool $replace = false): PDO
{
    static $pdo = null;
    if ($replace) {
        $pdo = $override;
        if ($pdo === null) {
            return new PDO('sqlite::memory:');
        }
        return $pdo;
    }
    if ($pdo === null) {
        $u = parse_url((string)getenv('DATABASE_URL'));
        if (!is_array($u) || empty($u['host']) || empty($u['path'])) {
            throw new RuntimeException('Invalid DATABASE_URL');
        }
        $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s', $u['host'], $u['port'] ?? 5432, ltrim($u['path'], '/'));
        $pdo = new PDO($dsn, $u['user'] ?? '', $u['pass'] ?? '', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}

/** @return array<int, array<string, mixed>> */
function q(string $sql, mixed ...$args): array
{
    $st = pdo()->prepare($sql);
    $st->execute(array_map(fn($a) => is_bool($a) ? ($a ? 'true' : 'false') : $a, $args));
    return $st->columnCount() ? $st->fetchAll() : [];
}

/** @return array<string, mixed>|null */
function q1(string $sql, mixed ...$args): ?array
{
    return q($sql, ...$args)[0] ?? null;
}

function uuid4(): string
{
    $b = random_bytes(16);
    $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
    $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

function is_uuid(string $s): bool
{
    return (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s);
}

function db_init(): void
{
    for ($i = 0; $i < 30; $i++) {
        try {
            pdo();
            break;
        } catch (PDOException) {
            sleep(1);
        }
    }
    $email = strtolower(getenv('OWNER_EMAIL') ?: 'owner@acme.test');
    $password = getenv('OWNER_PASSWORD');
    if (!is_string($password) || $password === '') {
        throw new RuntimeException('OWNER_PASSWORD must be configured');
    }
    // The API's PHP workers and the job worker all run this on cold start. Concurrent
    // CREATE TABLE IF NOT EXISTS can still collide in the Postgres catalog, so serialize it.
    pdo()->exec('SELECT pg_advisory_lock(' . DB_INIT_LOCK . ')');
    try {
        pdo()->exec(SCHEMA);
        if (!q1('SELECT 1 FROM users WHERE email=?', $email)) {
            q(
                "INSERT INTO users(id, tenant_id, email, password_hash, role) VALUES (?,?,?,?,'owner') ON CONFLICT DO NOTHING",
                uuid4(),
                uuid4(),
                $email,
                password_hash($password, PASSWORD_DEFAULT)
            );
        }
    } finally {
        pdo()->exec('SELECT pg_advisory_unlock(' . DB_INIT_LOCK . ')');
    }
}

/** Advisory lock key for schema initialization (arbitrary, unique to this app). */
const DB_INIT_LOCK = 7_406_221_101;

function event(
    string $tenant,
    ?string $agent,
    string $type,
    ?string $state = null,
    ?string $result = null,
    ?string $job = null,
    ?int $ms = null,
    ?string $channel = null
): void {
    q(
        'INSERT INTO events(tenant_id, agent_id, job_id, type, channel, state, result, duration_ms) VALUES (?,?,?,?,?,?,?,?)',
        $tenant,
        $agent,
        $job,
        $type,
        $channel,
        $state,
        $result,
        $ms
    );
}
