/**
 * `secure-npm doctor | log | policy | version`.
 *
 * doctor exists because every layer here fails open when it is not wired up:
 * a shim that is not on PATH, a pnpm config that was overwritten, an .npmrc
 * that lost its line — none of them announce themselves. It answers the only
 * question that matters: is any of this actually running?
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { loadPolicy } from './policy.mjs';
import { pruneAuditLog } from './logger.mjs';
import { findManager } from './which.mjs';
import {
    auditLogFile,
    binDir,
    entryPoint,
    installRoot,
    localPolicyFile,
    npmUserConfigFile,
    pnpmConfigFile,
    pnpmHookFile,
    policyFile,
    shimMarkerFile,
} from './paths.mjs';

const OK = '  ok    ';
const BAD = '  FAIL  ';
const MEH = '  warn  ';

function line(status, label, detail) {
    process.stdout.write(`${status}${label.padEnd(34)}${detail ?? ''}\n`);
}

function pathContainsBinDir() {
    const target = path.resolve(binDir).toLowerCase();
    return (process.env.PATH ?? '')
        .split(path.delimiter)
        .some(entry => path.resolve(entry.replace(/^"|"$/g, '')).toLowerCase() === target);
}

function doctor() {
    const policy = loadPolicy();
    let failures = 0;
    const fail = (label, detail) => {
        failures += 1;
        line(BAD, label, detail);
    };

    process.stdout.write(`\nsecure-npm doctor — install root ${installRoot}\n\n`);

    fs.existsSync(policyFile) ? line(OK, 'policy file', policyFile) : fail('policy file', `missing: ${policyFile}`);
    if (fs.existsSync(localPolicyFile)) line(OK, 'local policy overlay', localPolicyFile);

    line(
        OK,
        'release age',
        `${policy.minimumReleaseAgeMinutes} min (${(policy.minimumReleaseAgeMinutes / 1440).toFixed(1)} days)`
    );
    line(OK, 'blocked managers', [...policy.blockedManagers.keys()].join(', ') || 'none');
    line(OK, 'blocked packages', `${policy.blockedPackages.length} pattern(s)`);

    fs.existsSync(shimMarkerFile)
        ? line(OK, 'shim directory', binDir)
        : fail('shim directory', `not installed: ${binDir} — run "node install.mjs"`);

    pathContainsBinDir()
        ? line(OK, 'shim directory on PATH', 'yes')
        : fail('shim directory on PATH', `add ${binDir} to PATH, ahead of Node's own bin directory`);

    for (const name of ['npm', 'pnpm']) {
        const found = findManager(name);
        found ? line(OK, `real ${name}`, found.file) : line(MEH, `real ${name}`, 'not found on PATH');
    }

    const pnpmConfig = pnpmConfigFile();
    if (!fs.existsSync(pnpmConfig)) {
        fail('pnpm global config', `missing: ${pnpmConfig}`);
    } else {
        const contents = fs.readFileSync(pnpmConfig, 'utf8');
        contents.includes(pnpmHookFile)
            ? line(OK, 'pnpm hook wired', pnpmHookFile)
            : fail('pnpm hook wired', `globalPnpmfile does not point at ${pnpmHookFile}`);
        /^\s*minimumReleaseAge\s*:/m.test(contents)
            ? line(OK, 'pnpm release-age policy', 'set')
            : fail('pnpm release-age policy', 'minimumReleaseAge is not set');
        /^\s*trustPolicy\s*:\s*no-downgrade/m.test(contents)
            ? line(OK, 'pnpm trust policy', 'no-downgrade')
            : line(MEH, 'pnpm trust policy', 'not set to no-downgrade');
    }

    const npmrc = npmUserConfigFile();
    if (!fs.existsSync(npmrc)) {
        fail('npm user config', `missing: ${npmrc}`);
    } else {
        /^\s*ignore-scripts\s*=\s*true/m.test(fs.readFileSync(npmrc, 'utf8'))
            ? line(OK, 'npm ignore-scripts', npmrc)
            : fail('npm ignore-scripts', `not set in ${npmrc}`);
    }

    // A blocked manager already installed keeps working if it is reachable by
    // its own absolute path, which the shims cannot intercept.
    for (const command of policy.blockedManagers.keys()) {
        const found = findManager(command);
        if (found) line(MEH, `blocked manager present`, `${command} → ${found.file}`);
    }

    line(fs.existsSync(auditLogFile) ? OK : MEH, 'audit log', auditLogFile);

    process.stdout.write(`\n${failures === 0 ? 'All guard rails are in place.' : `${failures} check(s) failed.`}\n\n`);
    return failures === 0 ? 0 : 1;
}

function showLog(argv) {
    const count = Number.parseInt(argv[0] ?? '20', 10);
    if (!fs.existsSync(auditLogFile)) {
        process.stdout.write(`no audit log yet: ${auditLogFile}\n`);
        return 0;
    }

    const lines = fs.readFileSync(auditLogFile, 'utf8').split('\n').filter(Boolean).slice(-count);
    for (const raw of lines) {
        try {
            const entry = JSON.parse(raw);
            const argv = Array.isArray(entry.argv) && entry.argv.length ? ` ${entry.argv.join(' ')}` : '';
            const subject = entry.command ?? `${entry.phase ?? ''}`;
            process.stdout.write(
                `${entry.ts}  ${String(entry.event).toUpperCase().padEnd(5)}  ${subject}${argv}\n`
            );

            const violations = entry.violations ?? (entry.rule ? [entry] : []);
            for (const violation of violations) {
                const where = violation.subject ? `${violation.subject} — ` : '';
                process.stdout.write(`    ${violation.rule}: ${where}${violation.reason}\n`);
            }
        } catch {
            process.stdout.write(`${raw}\n`);
        }
    }
    return 0;
}

function showPolicy() {
    const policy = loadPolicy();
    process.stdout.write(
        `${JSON.stringify(
            {
                sources: policy.sources,
                minimumReleaseAgeMinutes: policy.minimumReleaseAgeMinutes,
                minimumReleaseAgeExclude: [...policy.minimumReleaseAgeExclude],
                allowExoticSources: policy.allowExoticSources,
                forceIgnoreScripts: policy.forceIgnoreScripts,
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
    const { name, version } = require(path.join(installRoot, 'package.json'));
    process.stdout.write(`${name} ${version}\n  root ${installRoot}\n  entry ${entryPoint}\n`);
    return 0;
}

export function runSelfCommand(command, argv) {
    switch (command) {
        case 'doctor': {
            const code = doctor();
            pruneAuditLog(loadPolicy().logRetentionDays);
            return code;
        }
        case 'log':
            return showLog(argv);
        case 'policy':
            return showPolicy();
        case 'version':
            return showVersion();
        default:
            process.stderr.write(`secure-npm: unknown command "${command}"\n`);
            return 2;
    }
}
