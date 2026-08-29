/**
 * `secure-npm doctor | edit-policy | log | policy | validate | version`.
 *
 * doctor exists because every layer here fails open when it is not wired up:
 * a shim that is not on PATH, a pnpm config that was overwritten, an .npmrc
 * that lost its line — none of them announce themselves. It answers the only
 * question that matters: is any of this actually running?
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { loadPolicy } from './policy.mjs';
import Logger from './logs/Logger.mjs';
import { runtimeStatus } from './runtime.mjs';
import { compromisedCacheStatus } from './compromised.mjs';
import { runValidate } from './validate.mjs';
import { findManager } from './which.mjs';
import {
    IS_WINDOWS,
    APP_AUDIT_LOG_FILE,
    APP_BIN_DIR,
    APP_CONFIG_DIR,
    APP_ENTRYPOINT,
    LOCAL_POLICY_FILE,
    MODULE_ROOT_PATH,
    NPM_USR_CONFIG_FILE,
    PNPM_CONFIG_FILE,
    PNPM_HOOK_FILE,
    POLICY_FILE,
    APP_RUNTIME_DIR,
    APP_SHIM_MARKER_FILE,
} from './paths.mjs';

const OK = '  ok    ';
const BAD = '  FAIL  ';
const MEH = '  warn  ';

function line(status, label, detail) {
    Logger.write(`${status}${label.padEnd(34)}${detail ?? ''}\n`);
}

function pathContainsBinDir() {
    const target = path.resolve(APP_BIN_DIR).toLowerCase();
    return (process.env.PATH ?? '')
        .split(path.delimiter)
        .some(entry => path.resolve(entry.replace(/^"|"$/g, '')).toLowerCase() === target);
}

/** Version declared by a tree's package.json, or null when there is none to read. */
function packageVersion(root) {
    try {
        return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version ?? null;
    } catch {
        return null;
    }
}

/**
 * Which version is actually installed.
 *
 * Resolved at install time from the repository's package.json and recorded in
 * the stamp, so it is the version the shims and the pnpm hook are running —
 * which is not necessarily the version of the clone this command was started
 * from. When the two differ, the clone is ahead and nothing on the machine
 * knows about it yet.
 */
function reportVersion() {
    const running = packageVersion(MODULE_ROOT_PATH);
    const { stamp } = runtimeStatus();

    if (!stamp?.version) {
        line(MEH, 'version', `${running ?? 'unknown'} here — nothing is installed yet`);
        return;
    }

    stamp.version === running
        ? line(OK, 'version', `${stamp.version} installed`)
        : line(MEH, 'version', `${stamp.version} installed, ${running ?? 'unknown'} in this working copy`);
}

/**
 * The deployed runtime is the one thing here with no equivalent of its own
 * error message: a copy that has fallen behind its source enforces yesterday's
 * policy perfectly happily, and says nothing at all about it.
 */
function reportRuntime(fail) {
    const { state, stamp } = runtimeStatus();

    if (state === 'missing') {
        fail('runtime deployed', `missing: ${APP_RUNTIME_DIR} — run "node installer.mjs" from the repository`);
        return;
    }

    if (state === 'unstamped') {
        fail('runtime deployed', `${APP_RUNTIME_DIR} carries no stamp — re-run "node installer.mjs"`);
        return;
    }

    if (state === 'stale') {
        line(OK, 'runtime deployed', APP_RUNTIME_DIR);
        fail('runtime up to date', `the source has changed — run "node ${path.join(stamp.source, 'installer.mjs')}"`);
        return;
    }

    line(OK, 'runtime deployed', `${APP_RUNTIME_DIR} (${stamp.deployedAt})`);
    state === 'source-gone'
        ? line(MEH, 'runtime source', `no longer at ${stamp.source} — updates cannot be checked`)
        : line(OK, 'runtime source', stamp.source);
}

/**
 * The malicious-package list, reported from the cache alone: doctor says what
 * is wired up, and going to the network to answer that would turn a missing
 * connection into a failed check rather than a stale one.
 */
function reportCompromisedList(policy, fail) {
    const { source, cached } = compromisedCacheStatus(policy);

    if (!source) {
        line(MEH, 'malicious-package list', 'off — "compromisedPackagesSource" is not set in policy.json');
        return;
    }

    if (!cached) {
        line(MEH, 'malicious-package list', `${source} (not fetched yet — the next install fetches it)`);
        return;
    }

    const ageHours = Math.round((Date.now() - cached.fetchedAt) / 3_600_000);
    const detail = `${cached.count} package(s), fetched ${ageHours}h ago`;

    // Past the stale window an install is refused outright, so it is a failure
    // here rather than a note: the machine is one offline moment from blocking.
    ageHours * 60 > policy.compromisedPackagesMaxStaleMinutes
        ? fail('malicious-package list', `${detail} — older than the max-stale window, installs will be refused`)
        : line(OK, 'malicious-package list', detail);
}

function doctor() {
    const policy = loadPolicy();
    let failures = 0;
    const fail = (label, detail) => {
        failures += 1;
        line(BAD, label, detail);
    };

    Logger.write(`\nsecure-npm doctor — running from ${MODULE_ROOT_PATH}\n\n`);

    reportVersion();
    reportRuntime(fail);

    fs.existsSync(POLICY_FILE) ? line(OK, 'policy file', POLICY_FILE) : fail('policy file', `missing: ${POLICY_FILE}`);
    fs.existsSync(LOCAL_POLICY_FILE)
        ? line(OK, 'local policy overlay', LOCAL_POLICY_FILE)
        : line(OK, 'local policy overlay', 'none — "secure-npm edit-policy" creates one');

    line(
        OK,
        'release age',
        `${policy.minimumReleaseAgeMinutes} min (${(policy.minimumReleaseAgeMinutes / 1440).toFixed(1)} days)`
    );
    line(OK, 'blocked managers', [...policy.blockedManagers.keys()].join(', ') || 'none');
    line(OK, 'blocked packages', `${policy.blockedPackages.length} pattern(s)`);

    reportCompromisedList(policy, fail);

    // Worth naming rather than counting: these are the only sources allowed in
    // without a publish date behind them.
    line(
        policy.allowExoticSources ? MEH : OK,
        'git sources allowed',
        policy.allowExoticSources
            ? 'every git and tarball source (allowExoticSources is on)'
            : policy.allowedGitSources.map(({ source }) => source).join(', ') || 'none'
    );

    fs.existsSync(APP_SHIM_MARKER_FILE)
        ? line(OK, 'shim directory', APP_BIN_DIR)
        : fail('shim directory', `not installed: ${APP_BIN_DIR} — run "node installer.mjs"`);

    // Shims written before the runtime was deployed still start the repository
    // copy, which keeps working right up until the clone moves.
    const shimFile = path.join(APP_BIN_DIR, IS_WINDOWS ? 'npm.cmd' : 'npm');
    if (fs.existsSync(shimFile)) {
        fs.readFileSync(shimFile, 'utf8').includes(APP_ENTRYPOINT)
            ? line(OK, 'shims start the runtime', APP_ENTRYPOINT)
            : fail('shims start the runtime', `${shimFile} points elsewhere — re-run "node installer.mjs"`);
    }

    pathContainsBinDir()
        ? line(OK, 'shim directory on PATH', 'yes')
        : fail('shim directory on PATH', `add ${APP_BIN_DIR} to PATH, ahead of Node's own bin directory`);

    for (const name of ['npm', 'pnpm']) {
        const found = findManager(name);
        found ? line(OK, `real ${name}`, found.file) : line(MEH, `real ${name}`, 'not found on PATH');
    }

    if (!fs.existsSync(PNPM_CONFIG_FILE)) {
        fail('pnpm global config', `missing: ${PNPM_CONFIG_FILE}`);
    } else {
        const contents = fs.readFileSync(PNPM_CONFIG_FILE, 'utf8');
        contents.includes(PNPM_HOOK_FILE)
            ? line(OK, 'pnpm hook wired', PNPM_HOOK_FILE)
            : fail('pnpm hook wired', `globalPnpmfile does not point at ${PNPM_HOOK_FILE}`);
        /^\s*minimumReleaseAge\s*:/m.test(contents)
            ? line(OK, 'pnpm release-age policy', 'set')
            : fail('pnpm release-age policy', 'minimumReleaseAge is not set');
        /^\s*trustPolicy\s*:\s*no-downgrade/m.test(contents)
            ? line(OK, 'pnpm trust policy', 'no-downgrade')
            : line(MEH, 'pnpm trust policy', 'not set to no-downgrade');

        // Editing allowedGitSources without re-running the installer leaves
        // pnpm blocking natively what the policy now allows — and the error
        // comes from pnpm, which knows nothing about the whitelist.
        const blocksNatively = /^\s*blockExoticSubdeps\s*:\s*true/m.test(contents);
        const shouldBlockNatively = !policy.allowExoticSources && policy.allowedGitSources.length === 0;
        blocksNatively === shouldBlockNatively
            ? line(OK, 'pnpm exotic sub-dependencies', blocksNatively ? 'blocked natively' : 'delegated to the hook')
            : fail('pnpm exotic sub-dependencies', 'no longer matches the policy — run "node installer.mjs"');
    }

    if (!fs.existsSync(NPM_USR_CONFIG_FILE)) {
        fail('npm user config', `missing: ${NPM_USR_CONFIG_FILE}`);
    } else {
        /^\s*ignore-scripts\s*=\s*true/m.test(fs.readFileSync(NPM_USR_CONFIG_FILE, 'utf8'))
            ? line(OK, 'npm ignore-scripts', NPM_USR_CONFIG_FILE)
            : fail('npm ignore-scripts', `not set in ${NPM_USR_CONFIG_FILE}`);
    }

    // A blocked manager already installed keeps working if it is reachable by
    // its own absolute path, which the shims cannot intercept.
    for (const command of policy.blockedManagers.keys()) {
        const found = findManager(command);
        if (found) line(MEH, `blocked manager present`, `${command} → ${found.file}`);
    }

    line(fs.existsSync(APP_AUDIT_LOG_FILE) ? OK : MEH, 'audit log', APP_AUDIT_LOG_FILE);

    Logger.write(`\n${failures === 0 ? 'All guard rails are in place.' : `${failures} check(s) failed.`}\n\n`);
    return failures === 0 ? 0 : 1;
}

function showLog(argv) {
    const count = Number.parseInt(argv[0] ?? '20', 10);
    if (!fs.existsSync(APP_AUDIT_LOG_FILE)) {
        Logger.write(`no audit log yet: ${APP_AUDIT_LOG_FILE}\n`);
        return 0;
    }

    const lines = fs.readFileSync(APP_AUDIT_LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-count);
    for (const raw of lines) {
        try {
            const entry = JSON.parse(raw);
            const argv = Array.isArray(entry.argv) && entry.argv.length ? ` ${entry.argv.join(' ')}` : '';
            const subject = entry.command ?? `${entry.phase ?? ''}`;
            Logger.write(
                `${entry.ts}  ${String(entry.event).toUpperCase().padEnd(5)}  ${subject}${argv}\n`
            );

            const violations = entry.violations ?? (entry.rule ? [entry] : []);
            for (const violation of violations) {
                const where = violation.subject ? `${violation.subject} — ` : '';
                Logger.write(`    ${violation.rule}: ${where}${violation.reason}\n`);
            }
        } catch {
            Logger.write(`${raw}\n`);
        }
    }
    return 0;
}

function showPolicy() {
    const policy = loadPolicy();
    Logger.write(
        `${JSON.stringify(
            {
                sources: policy.sources,
                minimumReleaseAgeMinutes: policy.minimumReleaseAgeMinutes,
                minimumReleaseAgeExclude: [...policy.minimumReleaseAgeExclude],
                allowExoticSources: policy.allowExoticSources,
                allowedGitSources: policy.allowedGitSources.map(({ source }) => source),
                forceIgnoreScripts: policy.forceIgnoreScripts,
                compromisedPackagesSource: policy.compromisedPackagesSource,
                compromisedPackagesRefreshMinutes: policy.compromisedPackagesRefreshMinutes,
                compromisedPackagesMaxStaleMinutes: policy.compromisedPackagesMaxStaleMinutes,
                blockedManagers: Object.fromEntries(policy.blockedManagers),
                blockedPackages: policy.blockedPackages.map(({ source, reason }) => ({ pattern: source, reason })),
                registries: policy.registries,
            },
            null,
            4
        )}\n`
    );
    return 0;
}

function showVersion() {
    const require = createRequire(import.meta.url);
    const { name, version } = require(path.join(MODULE_ROOT_PATH, 'package.json'));
    const { stamp } = runtimeStatus();

    // Two versions, because they are two different things: what this command is
    // running from, and what the shims and the pnpm hook load on every install.
    const rows = [
        { label: 'root', value: MODULE_ROOT_PATH },
        { label: 'entry', value: APP_ENTRYPOINT },
        { label: 'installed', value: stamp?.version ? `${stamp.version} (${stamp.deployedAt})` : 'nothing deployed' },
    ];

    Logger.write(`${name} ${version}\n${Logger.styles.columns(rows).join('\n')}\n`);
    return 0;
}

/* -------------------------------------------------------------- edit-policy */

/**
 * Seeded rather than left empty, because the merge is shallow and that is not
 * the obvious half of it: a key written here replaces the shared value outright
 * instead of adding to it. `$` keys are ignored by the compiler, so the examples
 * document the shape without quietly taking effect.
 */
const OVERLAY_TEMPLATE = {
    $comment: [
        'Machine-local policy overlay, shallow-merged on top of the shared policy.json.',
        'A key set here REPLACES the shared value, it does not extend it.',
        'Keys starting with $ are ignored — rename an example to switch it on.',
        'Re-run "node installer.mjs" from the repository afterwards: pnpm reads its own',
        'copy of these settings, generated at install time.',
    ],
    $examples: {
        minimumReleaseAgeMinutes: 4320,
        minimumReleaseAgeExclude: ['some-package', 'other-package@1.2.3'],
        allowedGitSources: ['github.com/safari-digital/*'],
        allowExoticSources: false,
    },
};

/**
 * $VISUAL / $EDITOR first, and waited on: a terminal editor needs the terminal,
 * and blocking is what makes it possible to check the file once it closes.
 * The desktop handler is the fallback and returns immediately, so nothing can
 * be validated in that case.
 */
function openEditor(file) {
    const editor = process.env.VISUAL || process.env.EDITOR;
    const target = `"${file}"`;

    const command = editor
        ? `${editor} ${target}`
        : IS_WINDOWS
          ? `start "" ${target}`
          : process.platform === 'darwin'
            ? `open ${target}`
            : `xdg-open ${target}`;

    const { error } = spawnSync(command, { shell: true, stdio: 'inherit' });

    return { launched: !error, waited: Boolean(editor), command };
}

function editPolicy() {
    fs.mkdirSync(APP_CONFIG_DIR, { recursive: true });

    const created = !fs.existsSync(LOCAL_POLICY_FILE);
    if (created) fs.writeFileSync(LOCAL_POLICY_FILE, `${JSON.stringify(OVERLAY_TEMPLATE, null, 4)}\n`);

    Logger.write(`${created ? 'created' : 'editing'} ${LOCAL_POLICY_FILE}\n`);

    const { launched, waited, command } = openEditor(LOCAL_POLICY_FILE);
    if (!launched) {
        Logger.write(`could not start an editor (${command}) — open the file above yourself\n`);
        return 0;
    }

    if (!waited) {
        Logger.write('run "secure-npm doctor" once you are done to check the result\n');
        return 0;
    }

    // An overlay that does not parse takes every npm and pnpm command down with
    // it, so it is worth catching here rather than on the next install.
    try {
        JSON.parse(fs.readFileSync(LOCAL_POLICY_FILE, 'utf8'));
    } catch (error) {
        Logger.writeErr(`\nthis file is not valid JSON — every npm and pnpm command will fail until it is\n`);
        Logger.writeErr(`  ${error.message}\n`);
        return 1;
    }

    const { stamp } = runtimeStatus();
    const installer = stamp?.source ? path.join(stamp.source, 'installer.mjs') : 'installer.mjs';
    Logger.write(`\npnpm keeps its own copy of the release-age, trust and exotic-source settings.\n`);
    Logger.write(`If you changed any of those, re-run "node ${installer}", then "secure-npm doctor".\n`);

    return 0;
}

export function runSelfCommand(command, argv) {
    switch (command) {
        case 'doctor': {
            const code = doctor();
            Logger.pruneAuditLog(loadPolicy().logRetentionDays);
            return code;
        }
        case 'edit-policy':
            return editPolicy();
        case 'log':
            return showLog(argv);
        case 'policy':
            return showPolicy();
        case 'validate':
            return runValidate(argv);
        case 'version':
            return showVersion();
        default:
            Logger.writeErr(`secure-npm: unknown command "${command}"\n`);
            return 2;
    }
}
