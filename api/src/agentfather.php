<?php
declare(strict_types=1);
/*
 * AgentFather: the platform's own agent. It recommends; the platform decides.
 *
 * It runs a guided questionnaire (one question at a time, with clickable choices and
 * free text), then turns the answers into a configuration that validate_config()
 * checks against a fixed schema before anything is created. It has no access to
 * Docker, secrets or other agents.
 *
 * Session state lives in agentfather_sessions.draft_config:
 *   {"answers": {question_id: value}, "asking": question_id|null}
 */

const AF_GREETING = "Hi, I'm AgentFather. I'll ask you a few questions to set up your new agent. "
    . 'Tap a choice or type your own answer.';

const OTHER_NAME = 'Type my own name';
const AF_RUNTIMES = ['OpenClaw (recommended)' => 'openclaw', 'Hermes Agent' => 'hermes'];
const AF_MODELS = [
    'Claude Sonnet 5.5 (recommended, balanced)' => 'claude-sonnet-5-5',
    'Claude Opus 5.5 (most capable, slower)' => 'claude-opus-5-5',
    'Claude Haiku 5.5 (fastest)' => 'claude-haiku-5-5',
    'Claude Sonnet 4.6' => 'claude-sonnet-4-6',
    'Gemini 3.8 Flash' => 'gemini-3-8-flash',
    'Groq GPT OSS 120B' => 'groq-gpt-oss-120b',
];
const AF_MODEL_PROVIDER = [
    'claude-sonnet-5-5' => 'anthropic', 'claude-opus-5-5' => 'anthropic', 'claude-haiku-5-5' => 'anthropic',
    'claude-sonnet-4-6' => 'anthropic', 'gemini-3-8-flash' => 'gemini', 'groq-gpt-oss-120b' => 'groq',
];

/**
 * Models AgentFather may offer: only those whose provider is connected on the "Model providers" page.
 * $GLOBALS['af_enabled_providers'] is set by the API per request; unset (tests/CLI) means "all".
 */
function af_models(): array
{
    $enabled = $GLOBALS['af_enabled_providers'] ?? null;
    if ($enabled === null) return AF_MODELS;
    return array_filter(AF_MODELS, fn($id) => in_array(AF_MODEL_PROVIDER[$id], $enabled, true));
}

const AF_ACCESS_ANYONE = 'Anyone with the QR code or link';
const AF_ACCESS_LIST = 'Only people I list';
const CHANGE_Q = '__change';

/** The questionnaire, in order. kind: single | multi | text. */
function af_questions(): array
{
    return [
        'purpose' => [
            'label' => 'Main job', 'kind' => 'single', 'other' => true,
            'text' => "What is your agent's main job?",
            'options' => ['Customer support', 'Bookings and reservations', 'Sales and lead qualification', 'Internal team assistant'],
            'placeholder' => 'Or describe its job in one line…',
        ],
        'company' => [
            'label' => 'Company', 'kind' => 'text',
            'text' => 'What is the name of your company or business?',
            'placeholder' => 'e.g. Le Petit Bistro',
        ],
        'name' => [
            'label' => 'Agent name', 'kind' => 'single', 'other' => true,
            'text' => 'What should the agent be called? People will see this name.',
            'options' => ['Nova', 'Alex', 'Sam'],
            'placeholder' => 'Or type a name (2-40 letters, digits, spaces)…',
        ],
        'knowledge' => [
            'label' => 'What it knows', 'kind' => 'text',
            'text' => 'What should it know to do its job? Paste the key facts: what you do, opening hours, products or services, prices, address, useful links…',
            'placeholder' => 'Key facts about your business…',
        ],
        'tone' => [
            'label' => 'Tone', 'kind' => 'multi', 'other' => false,
            'text' => 'How should it talk to people? Pick one or more.',
            'options' => ['Friendly and warm', 'Short and to the point', 'Formal and polite', 'Detailed explanations', 'Uses emojis'],
        ],
        'language' => [
            'label' => 'Language', 'kind' => 'single', 'other' => true,
            'text' => 'Which language should it answer in?',
            'options' => ["The user's language", 'English only', 'French only'],
            'placeholder' => 'Or type a language…',
        ],
        'prohibited' => [
            'label' => 'Prohibited tasks', 'kind' => 'multi', 'other' => true,
            'text' => 'What must it refuse to do? Pick all that apply, and type any other rule (separate several with ";").',
            'options' => [
                'Promise refunds or discounts',
                'Quote prices that are not in its instructions',
                'Share personal or internal data',
                'Give legal, medical or financial advice',
                'Discuss politics or religion',
                'Answer requests unrelated to the business',
            ],
            'placeholder' => 'Other things it must refuse…',
            'allow_empty' => true,
        ],
        'fallback' => [
            'label' => "When it can't help", 'kind' => 'single', 'other' => false,
            'text' => "When it can't answer or help, what should it do?",
            'options' => ['Give a contact to reach a human', 'Say a team member will follow up', "Simply say it doesn't know"],
        ],
        'fallback_contact' => [
            'label' => 'Contact to give', 'kind' => 'text',
            'text' => 'Which contact should it give? (phone number, email or link)',
            'placeholder' => 'e.g. +33 1 23 45 67 89 or hello@example.com',
            'if' => fn(array $a) => ($a['fallback'] ?? '') === 'Give a contact to reach a human',
        ],
        'runtime' => [
            'label' => 'Runtime', 'kind' => 'single', 'other' => false,
            'text' => 'Which agent runtime should run it?',
            'options' => array_keys(AF_RUNTIMES),
        ],
        'model' => [
            'label' => 'Model', 'kind' => 'single', 'other' => false,
            'text' => 'Which AI model should it use?',
            'options' => array_keys(af_models()),
        ],
        'channel' => [
            'label' => 'Channel', 'kind' => 'single', 'other' => false,
            'text' => 'Where should people talk to it?',
            'options' => ['Telegram', 'WhatsApp (coming soon)'],
        ],
        'access' => [
            'label' => 'Who can talk to it', 'kind' => 'single', 'other' => false,
            'text' => 'Who can talk to it on Telegram?',
            'options' => [AF_ACCESS_ANYONE, AF_ACCESS_LIST],
        ],
        'access_ids' => [
            'label' => 'Allowed Telegram users', 'kind' => 'text',
            'text' => 'Paste the numeric Telegram user IDs allowed to talk to it, separated by commas. (Each person can get their ID by messaging @userinfobot on Telegram.)',
            'placeholder' => 'e.g. 123456789, 987654321',
            'if' => fn(array $a) => ($a['access'] ?? '') === AF_ACCESS_LIST,
        ],
    ];
}

/** Secrets never reach the DB or the UI history. */
function redact(string $text): string
{
    $text = preg_replace('/\b\d{5,15}:[A-Za-z0-9_-]{30,50}\b/', '[redacted secret]', $text); // Telegram bot token
    $text = preg_replace('/sk-[A-Za-z0-9_\-]{20,}/', '[redacted secret]', $text);              // provider keys
    return preg_replace('/\bAIza[A-Za-z0-9_\-]{20,}\b|\bgsk_[A-Za-z0-9_\-]{20,}\b/', '[redacted secret]', $text);
}

function af_applicable(string $id, array $answers): bool
{
    $q = af_questions()[$id];
    return !isset($q['if']) || $q['if']($answers);
}

function af_next(array $answers): ?string
{
    foreach (af_questions() as $id => $_) {
        if (!array_key_exists($id, $answers) && af_applicable($id, $answers)) return $id;
    }
    return null;
}

/** Question payload for the UI (choices to render as buttons). */
function af_question(?string $id): ?array
{
    if ($id === null) return null;
    if ($id === CHANGE_Q) {
        $labels = [];
        foreach (af_questions() as $qid => $q) if (!isset($q['if'])) $labels[] = $q['label'];
        return ['id' => CHANGE_Q, 'kind' => 'single', 'options' => $labels, 'other' => false, 'placeholder' => ''];
    }
    $q = af_questions()[$id];
    return ['id' => $id, 'kind' => $q['kind'], 'options' => $q['options'] ?? [], 'other' => $q['other'] ?? true,
            'placeholder' => $q['placeholder'] ?? 'Type your answer…', 'allow_empty' => $q['allow_empty'] ?? false];
}

/**
 * Applies one answer. $choices are clicked options, $text is typed text.
 * @return array{0: array, 1: ?string, 2: string} [new state, error, text shown as the owner's message]
 */
function af_answer(array $state, array $choices, string $text): array
{
    $answers = $state['answers'] ?? [];
    $id = $state['asking'] ?? af_next($answers);
    $text = trim(redact($text));

    if ($id === CHANGE_Q) {
        foreach (af_questions() as $qid => $q) {
            if (in_array($q['label'], $choices, true)) {
                unset($answers[$qid]);
                if ($qid === 'fallback') unset($answers['fallback_contact']);
                if ($qid === 'access') unset($answers['access_ids']);
                return [['answers' => $answers, 'asking' => $qid], null, "Change: {$q['label']}"];
            }
        }
        return [$state, 'Pick what you want to change.', ''];
    }
    if ($id === null) return [$state, 'All questions are answered. Review the summary.', ''];

    $q = af_questions()[$id];
    $allowed = $q['options'] ?? [];
    foreach ($choices as $c) if (!in_array($c, $allowed, true)) return [$state, 'Unknown choice.', ''];

    switch ($q['kind']) {
        case 'text':
            if ($id === 'access_ids') {
                $ids = array_values(array_unique(array_filter(array_map('trim', preg_split('/[\s,;]+/', $text)))));
                foreach ($ids as $x) if (!preg_match('/^\d{3,15}$/', $x)) return [$state, 'Telegram user IDs are numbers only (get yours from @userinfobot).', ''];
                if (!$ids || count($ids) > 50) return [$state, 'Paste between 1 and 50 Telegram user IDs.', ''];
                $value = $ids;
                $shown = implode(', ', $ids);
                break;
            }
            if (mb_strlen($text) < 2) return [$state, 'Please type an answer.', ''];
            $max = $id === 'knowledge' ? 3000 : 200;
            if (mb_strlen($text) > $max) return [$state, "Please keep it under $max characters.", ''];
            $value = $text;
            $shown = $text;
            break;
        case 'single':
            $value = $choices[0] ?? $text;
            if ($value === '') return [$state, 'Pick a choice or type an answer.', ''];
            if (!$choices && !($q['other'] ?? false)) return [$state, 'Pick one of the choices.', ''];
            if ($id === 'name' && !preg_match("/^[A-Za-z0-9][A-Za-z0-9 _'\-]{1,39}$/", $value)) {
                return [$state, "A name is 2-40 letters, digits, spaces, - _ '.", ''];
            }
            if ($id === 'channel' && $value !== 'Telegram') {
                return [$state, 'WhatsApp is not available in this POC yet (OpenClaw only supports WhatsApp Web linking). Please pick Telegram.', ''];
            }
            if (mb_strlen($value) > 160) return [$state, 'Please keep it under 160 characters.', ''];
            $shown = $value;
            break;
        default: // multi
            $extra = array_values(array_filter(array_map('trim', explode(';', $text))));
            $value = [...$choices, ...$extra];
            if (!$value && !($q['allow_empty'] ?? false)) return [$state, 'Pick at least one.', ''];
            if (count($value) > 15) return [$state, 'Too many items.', ''];
            foreach ($value as $v) if (mb_strlen($v) > 300) return [$state, 'Each item must be under 300 characters.', ''];
            $shown = $value ? implode(' · ', $value) : 'None';
    }
    $answers[$id] = $value;
    if ($id === 'fallback' && !af_applicable('fallback_contact', $answers)) unset($answers['fallback_contact']);
    if ($id === 'access' && !af_applicable('access_ids', $answers)) unset($answers['access_ids']);
    // Each field has its own limit, but together they must still fit the agent's instructions.
    $over = mb_strlen(af_instructions($answers)) - AF_INSTRUCTIONS_MAX;
    if ($over > 0) {
        return [$state, "Together, your answers are too long for the agent's instructions. Please shorten this answer by at least $over characters.", ''];
    }
    return [['answers' => $answers, 'asking' => af_next($answers)], null, $shown];
}

function af_prompt(?string $id): string
{
    if ($id === null) return 'Here is the configuration. Review it, paste your Telegram bot token and click Confirm.';
    if ($id === CHANGE_Q) return 'What do you want to change?';
    return af_questions()[$id]['text'];
}

/** Turns the answers into the agent configuration (validated afterwards by validate_config). */
/** Upper bound for the generated instructions (validate_config enforces the same). */
const AF_INSTRUCTIONS_MAX = 4000;

/**
 * The agent's instructions text. Works on partial answers too (missing ones count as empty),
 * so each answer can be checked against the overall limit as soon as it is given.
 */
function af_instructions(array $a): string
{
    $company = $a['company'] ?? '';
    $lines = ["You are " . ($a['name'] ?? '') . ", the AI agent of {$company}. Your role: " . ($a['purpose'] ?? '') . '.', ''];
    $lines[] = 'Tone: ' . strtolower(implode(', ', (array)($a['tone'] ?? []))) . '.';
    $lines[] = match ($a['language'] ?? '') {
        "The user's language" => "Language: answer in the language the person writes in.",
        default => 'Language: ' . ($a['language'] ?? '') . '.',
    };
    $lines[] = '';
    $lines[] = "What you know about {$company}:";
    $lines[] = $a['knowledge'] ?? '';
    $lines[] = '';
    $lines[] = 'Only state facts that are written above. If you are not sure, do not invent an answer.';
    $lines[] = match ($a['fallback'] ?? '') {
        'Give a contact to reach a human' => 'When you cannot help, tell the person to contact the team: ' . ($a['fallback_contact'] ?? '') . '.',
        'Say a team member will follow up' => 'When you cannot help, say that a team member will follow up soon.',
        default => "When you cannot help, simply say that you don't know.",
    };
    return implode("\n", $lines);
}

function af_build_config(array $a): ?array
{
    if (af_next($a) !== null) return null;
    $purpose = $a['purpose'];
    $company = $a['company'];
    return [
        'name' => $a['name'],
        'job' => mb_substr("$purpose for $company", 0, 160),
        'instructions' => af_instructions($a),
        'prohibited_tasks' => $a['prohibited'],
        'channel_type' => 'telegram',
        'runtime' => AF_RUNTIMES[$a['runtime']],
        'model' => AF_MODELS[$a['model']],
        'allowed_users' => $a['access'] === AF_ACCESS_LIST ? array_values($a['access_ids']) : [],
    ];
}

/**
 * Fixed schema + allowed values. Anything else is rejected.
 * @return array{0: ?array, 1: ?string} [config, error]
 */
function validate_config(mixed $d): array
{
    if (!is_array($d) || !$d) return [null, 'incomplete'];
    $allowed = ['name', 'job', 'instructions', 'prohibited_tasks', 'channel_type', 'runtime', 'model', 'allowed_users'];
    if ($extra = array_diff(array_keys($d), $allowed)) return [null, 'unknown fields: ' . implode(', ', $extra)];
    foreach ($allowed as $k) if (!array_key_exists($k, $d)) return [null, "$k: missing"];
    foreach (['name', 'job', 'instructions', 'channel_type'] as $k) if (!is_string($d[$k])) return [null, "$k: must be text"];
    $name = trim($d['name']);
    if (!preg_match("/^[A-Za-z0-9][A-Za-z0-9 _'\-]{1,39}$/", $name)) return [null, "name: 2-40 letters, digits, spaces, - _ '"];
    $job = trim($d['job']);
    if (mb_strlen($job) < 3 || mb_strlen($job) > 160) return [null, 'job: 3-160 characters'];
    $ins = trim($d['instructions']);
    if (mb_strlen($ins) < 5 || mb_strlen($ins) > AF_INSTRUCTIONS_MAX) return [null, 'instructions: 5-' . AF_INSTRUCTIONS_MAX . ' characters'];
    if (!is_array($d['prohibited_tasks']) || count($d['prohibited_tasks']) > 20) return [null, 'prohibited_tasks: list of at most 20'];
    $tasks = [];
    foreach ($d['prohibited_tasks'] as $t) {
        if (!is_string($t) || mb_strlen($t) > 300) return [null, 'prohibited_tasks: each must be text under 300 characters'];
        if (trim($t) !== '') $tasks[] = trim($t);
    }
    if (!in_array($d['channel_type'], ['telegram', 'whatsapp'], true)) return [null, 'channel_type: telegram or whatsapp'];
    if (!in_array($d['runtime'], AF_RUNTIMES, true)) return [null, 'runtime: not allowed'];
    if (!in_array($d['model'], AF_MODELS, true)) return [null, 'model: not allowed'];
    if (!is_array($d['allowed_users']) || count($d['allowed_users']) > 50) return [null, 'allowed_users: at most 50'];
    foreach ($d['allowed_users'] as $x) if (!is_string($x) || !preg_match('/^\d{3,15}$/', $x)) return [null, 'allowed_users: numeric Telegram ids'];
    return [['name' => $name, 'job' => $job, 'instructions' => $ins, 'prohibited_tasks' => $tasks,
             'channel_type' => $d['channel_type'], 'runtime' => $d['runtime'], 'model' => $d['model'],
             'allowed_users' => array_values($d['allowed_users'])], null];
}
