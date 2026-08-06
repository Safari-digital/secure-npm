/**
 * Handing control to the real package manager, and refusing to.
 */

import { spawn } from 'node:child_process';
import { audit, reportBlocks } from './logger.mjs';

/**
 * Runs the genuine binary with the caller's stdio, so the wrapper stays
 * invisible once the checks have passed.
 *
 * `node <cli.js>` is preferred over the launcher script: on Windows a `.cmd`
 * can only be spawned through a shell, and putting a shell between the user's
 * arguments and the package manager is both a quoting bug and an injection
 * surface.
 */
export function delegate({ manager, argv, cwd, env = {} }) {
    const [file, args] =
        manager.kind === 'node-script'
            ? [process.execPath, [manager.file, ...argv]]
            : [manager.file, [...argv]];

    return new Promise(resolve => {
        const child = spawn(file, args, {
            cwd,
            stdio: 'inherit',
            shell: manager.kind !== 'node-script' && process.platform === 'win32',
            env: { ...process.env, ...env },
        });

        child.on('error', error => {
            process.stderr.write(`secure-npm: could not start ${manager.file}: ${error.message}\n`);
            resolve(1);
        });

        child.on('close', (code, signal) => resolve(signal ? 1 : (code ?? 0)));
    });
}

/** Reports every violation, records them, and stops. Never partially applied. */
export function abort({ violations, command, cwd, phase }) {
    const grouped = new Map();
    for (const violation of violations) {
        if (!grouped.has(violation.rule)) grouped.set(violation.rule, []);
        grouped.get(violation.rule).push(violation);
    }

    for (const [rule, entries] of grouped) {
        reportBlocks({
            rule,
            title: `${entries.length} ${entries.length === 1 ? 'violation' : 'violations'} in ${command}`,
            entries: entries.map(entry => `${entry.subject} — ${entry.reason}`),
            hint: entries.find(entry => entry.hint)?.hint,
        });
    }

    audit({
        event: 'block',
        phase,
        command,
        cwd,
        violations: violations.map(({ rule, subject, reason }) => ({ rule, subject, reason })),
    });

    return 1;
}
