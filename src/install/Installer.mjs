import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
    APP_BIN_DIR,
    APP_ENTRYPOINT,
    APP_RUNTIME_DIR,
    APP_RUNTIME_STAMP_FILE, APP_SHIM_MARKER_FILE,
    IS_WINDOWS,
    LOCAL_POLICY_FILE,
    MODULE_ROOT_PATH,
    NPM_USR_CONFIG_FILE,
    PNPM_CONFIG_DIR,
    PNPM_CONFIG_FILE,
    PNPM_HOOK_FILE,
    RUNTIME_POLICY_FILE
} from "../paths.mjs";
import { DEPLOYED, fingerprint } from "../runtime.mjs";
import { loadPolicy } from "../policy.mjs";
import Logger from "../logs/Logger.mjs";

export default class Installer {
    /** @type {{ label: string, value: string, depth: number }[]} **/
    static #done = [];
    /** @type {string[]} **/
    static #notes = [];

    static #BLOCK_BEGIN         = '# >>> secure-npm >>>';
    static #BLOCK_END           = '# <<< secure-npm <<<';
    static #MANAGED_MARKER      = 'managed by secure-npm';
    static #REGENERATE_HINT     = 'regenerate with "node installer.mjs"';

    static #flags               = new Set(process.argv.slice(2));
    static #hasYesFlag          = () => this.#flags.has('-y');

    /**
     * @param {string} label
     * @param {string} value
     * @param {number} [depth]
     * @returns {undefined}
     */
    static #report = (label, value, depth = 0) => void this.#done.push({ label, value, depth });

    /**
     * @param {string} message
     * @returns {undefined}
     */
    static #note = (message) => void this.#notes.push(message);

    /** @returns {Promise<undefined>} **/
    static async install() {
        const { dim } = Logger.styles
        const proceed = await this.#confirm('installing', [
            { label: 'runtime', value: APP_RUNTIME_DIR },
            { label: 'shims', value: APP_BIN_DIR },
            { label: 'pnpm config', value: `${PNPM_CONFIG_FILE} ${dim('(rewritten)')}` },
            { label: 'npm config', value: `${NPM_USR_CONFIG_FILE} ${dim('(managed block)')}` },
            { label: 'PATH', value: this.#pathTouchedSummary('managed block') },
        ]);
        if (!proceed) return;

        // Read from the repository, which is the source of truth at install time.
        const policy = loadPolicy();
        this.#installRuntime();
        this.#installShims(policy);
        this.#installPnpmConfig(policy);
        this.#installNpmrc();
        this.#installPath();
        this.#note('re-run this installer after every "git pull"');
        this.#printReport('secure-npm installer', 'secure-npm doctor');
    }

    /** @returns {Promise<undefined>} **/
    static async uninstall() {
        const { dim } = Logger.styles
        const proceed = await this.#confirm('uninstalling', [
            { label: 'runtime', value: `${APP_RUNTIME_DIR} ${dim('(removed)')}` },
            { label: 'shims', value: `${APP_BIN_DIR} ${dim('(removed)')}` },
            { label: 'pnpm config', value: `${PNPM_CONFIG_FILE} ${dim('(removed when managed)')}` },
            { label: 'npm config', value: `${NPM_USR_CONFIG_FILE} ${dim('(managed block removed)')}` },
            { label: 'PATH', value: this.#pathTouchedSummary('managed block removed') },
        ]);
        if (!proceed) return;

        this.#removeRuntime();
        this.#removeShims();
        this.#removePnpmConfig();
        this.#removeNpmrcBlock();

        if (IS_WINDOWS)
            this.#removePathWindows();
        else
            this.#removePathPosix();

        if (fs.existsSync(LOCAL_POLICY_FILE))
            this.#report('local policy', `${LOCAL_POLICY_FILE} ${dim('(hand-written, left alone)')}`);

        this.#printReport('secure-npm uninstaller');
    }

    /**
     * @param {string} action
     * @param {{ label: string, value: string }[]} planned
     * @returns {Promise<boolean>}
     */
    static async #confirm(action, planned) {
        if (this.#hasYesFlag()) return true;

        const { dim, yellow, bold, columns } = Logger.styles
        Logger.write(`\n${yellow('!')} ${bold('secure-npm')}  ${action} will touch:\n\n`);
        Logger.write(`${columns(planned, dim).join('\n')}\n\n`);

        const answer = await Logger.ask(`  continue? ${dim('[y/N]')} `);
        if (/^y(es)?$/i.test(answer.trim())) return true;

        Logger.write(`\n  aborted - nothing was changed ${dim('(pass -y to skip the prompt)')}\n\n`);
        process.exitCode = 1;
        return false;
    }

    /** @returns {undefined} **/
    static #installRuntime() {
        const { dim } = Logger.styles;

        for (const entry of DEPLOYED) {
            const from = path.join(MODULE_ROOT_PATH, entry);
            if (!fs.existsSync(from))
                throw new Error(`cannot deploy the runtime: ${from} is missing`);
        }

        fs.rmSync(APP_RUNTIME_DIR, { recursive: true, force: true });
        fs.mkdirSync(APP_RUNTIME_DIR, { recursive: true });

        for (const entry of DEPLOYED) {
            fs.cpSync(
                path.join(MODULE_ROOT_PATH, entry),
                path.join(APP_RUNTIME_DIR, entry),
                { recursive: true }
            );
        }

        const { version } = JSON.parse(fs.readFileSync(path.join(MODULE_ROOT_PATH, 'package.json'), 'utf8'));
        const stamp = {
            source: MODULE_ROOT_PATH,
            version,
            deployedAt: new Date().toISOString(),
            fingerprint: fingerprint(APP_RUNTIME_DIR),
        };

        fs.writeFileSync(APP_RUNTIME_STAMP_FILE, `${JSON.stringify(stamp, null, 4)}\n`);
        this.#report('runtime', APP_RUNTIME_DIR);
        this.#report('from', `${MODULE_ROOT_PATH} ${dim(`(v${stamp.version})`)}`, 1);
    }

    /** @returns {undefined} **/
    static #removeRuntime() {
        const { dim } = Logger.styles;
        if (!fs.existsSync(APP_RUNTIME_DIR)) {
            return;
        }

        fs.rmSync(APP_RUNTIME_DIR, { recursive: true, force: true });
        this.#report('runtime', `${APP_RUNTIME_DIR} ${dim('(removed)')}`);
    }

    static #posixShim = (route) => [
        '#!/bin/sh',
        `# ${this.#MANAGED_MARKER}: do not edit, ${this.#REGENERATE_HINT}`,
        `exec node "${APP_ENTRYPOINT}" ${route} "$@"\n`
    ].join('\n');

    static #windowsCmdShim = (route) => [
        '@ECHO OFF\r',
        `REM ${this.#MANAGED_MARKER}: do not edit, ${this.#REGENERATE_HINT}\r`,
        'SETLOCAL\r',
        `node "${APP_ENTRYPOINT}" ${route} %*\r`,
        'EXIT /B %ERRORLEVEL%\r\n'
    ].join('\n');

    static #windowsPowerShellShim = (route) => [
        '#!/usr/bin/env pwsh',
        `# ${this.#MANAGED_MARKER}: do not edit, ${this.#REGENERATE_HINT}`,
        `node "${APP_ENTRYPOINT}" ${route} @args`,
        'exit $LASTEXITCODE\n'
    ].join('\n');

    static #writeShim(name, route = name) {
        // The extensionless script is written on Windows too: Git Bash and MSYS
        // resolve it, and they are how most Windows Node work actually happens.
        fs.writeFileSync(path.join(APP_BIN_DIR, name), this.#posixShim(route), { mode: 0o755 });

        if (IS_WINDOWS) {
            fs.writeFileSync(path.join(APP_BIN_DIR, `${name}.cmd`), this.#windowsCmdShim(route));
            fs.writeFileSync(path.join(APP_BIN_DIR, `${name}.ps1`), this.#windowsPowerShellShim(route));
        }
    }

    /** @returns {undefined} **/
    static #installShims(policy) {
        fs.mkdirSync(APP_BIN_DIR, { recursive: true });
        fs.writeFileSync(
            APP_SHIM_MARKER_FILE,
            [
                `${this.#MANAGED_MARKER}\nruntime=${APP_RUNTIME_DIR}\n`,
                'This marker tells the wrapper to skip this directory when it looks for the',
                'real package managers on PATH. Removing it causes infinite recursion.\n'
            ].join('\n')
        );

        const wrapped = ['npm', 'npx', 'pnpm', 'pnpx'];
        const refused = [...policy.blockedManagers.keys()];

        for (const manager of [...wrapped, ...refused]) this.#writeShim(manager);
        this.#writeShim('secure-npm', '--self');

        this.#report('shims', APP_BIN_DIR);
        this.#report('wrapped', wrapped.join(', '), 1);
        this.#report('refused', refused.join(', '), 1);
        this.#report('tool', 'secure-npm', 1);
    }

    /** @returns {undefined} **/
    static #removeShims() {
        const { dim } = Logger.styles;
        if (!fs.existsSync(APP_BIN_DIR)) return;
        fs.rmSync(APP_BIN_DIR, { recursive: true, force: true });
        this.#report('shims', `${APP_BIN_DIR} ${dim('(removed)')}`);
    }

    static #pnpmConfigContents(policy) {
        const exclude = [...policy.minimumReleaseAgeExclude];
        return [
            `# ${this.#MANAGED_MARKER} — ${this.#REGENERATE_HINT}`,
            `# Source of truth: ${RUNTIME_POLICY_FILE}, overlaid with ${LOCAL_POLICY_FILE}`,
            '#',
            '# Applies to every pnpm project on this machine, including projects with no',
            '# pnpm-workspace.yaml and including "pnpm dlx". A project may tighten these in',
            '# its own pnpm-workspace.yaml; this file is the floor.',
            '',
            '# A version must have existed for this long before pnpm may resolve it.',
            '# Strict mode fails the install instead of quietly widening the exclude list.',
            `minimumReleaseAge: ${policy.minimumReleaseAgeMinutes}`,
            'minimumReleaseAgeStrict: true',
            'minimumReleaseAgeIgnoreMissingTime: false',
            ...(exclude.length ? ['minimumReleaseAgeExclude:', ...exclude.map(entry => `  - '${entry}'`)] : []),
            '',
            '# Refuses a version published with weaker guarantees than an earlier one.',
            `trustPolicy: ${policy.trustPolicy}`,
            `trustPolicyIgnoreAfter: ${policy.trustPolicyIgnoreAfterMinutes}`,
            '',
            '# No lifecycle scripts at install time. A project that genuinely needs to',
            '# compile fails loudly (ERR_PNPM_IGNORED_BUILDS) rather than running code.',
            `ignoreScripts: ${policy.forceIgnoreScripts}`,
            '',
            '# git and tarball sub-dependencies carry no publish date and no provenance,',
            '# which is exactly how the checks above get bypassed.',
            '#',
            '# This setting is a boolean, so it cannot express "these repositories and no',
            '# others". With allowedGitSources in use it is therefore handed to the hook',
            '# below, which enforces the same rule per repository, at every depth.',
            `blockExoticSubdeps: ${!policy.allowExoticSources && policy.allowedGitSources.length === 0}`,
            '',
            '# Name-based blocking and the git whitelist, neither of which pnpm has a',
            '# setting for.',
            `globalPnpmfile: '${PNPM_HOOK_FILE}'`,
            ''
        ].join('\n');
    }

    /** @returns {undefined} **/
    static #installPnpmConfig(policy) {
        fs.mkdirSync(PNPM_CONFIG_DIR, { recursive: true });

        if (fs.existsSync(PNPM_CONFIG_FILE)) {
            const existing = fs.readFileSync(PNPM_CONFIG_FILE, 'utf8');
            if (!existing.includes(this.#MANAGED_MARKER)) {
                const backup = `${PNPM_CONFIG_FILE}.bak-${Date.now()}`;
                fs.copyFileSync(PNPM_CONFIG_FILE, backup);
                this.#note(`existing pnpm config was not written by this tool — backed up to ${backup}`);
            }
        }

        fs.writeFileSync(PNPM_CONFIG_FILE, this.#pnpmConfigContents(policy));
        this.#report('pnpm config', PNPM_CONFIG_FILE);
    }

    /** @returns {undefined} **/
    static #removePnpmConfig() {
        const { dim } = Logger.styles;
        if (!fs.existsSync(PNPM_CONFIG_FILE)) {
            return;
        }
        if (!fs.readFileSync(PNPM_CONFIG_FILE, 'utf8').includes(this.#MANAGED_MARKER)) {
            this.#report('pnpm config', `${PNPM_CONFIG_FILE} ${dim('(edited by hand, left alone)')}`);
            return;
        }

        fs.rmSync(PNPM_CONFIG_FILE);
        this.#report('pnpm config', `${PNPM_CONFIG_FILE} ${dim('(removed)')}`);
    }

    /** @returns {'updated' | 'created' | 'appended'} **/
    static #upsertManagedBlock(file, body) {
        const block = [this.#BLOCK_BEGIN, body.trimEnd(), this.#BLOCK_END].join('\n');
        const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';

        if (existing.includes(this.#BLOCK_BEGIN) && existing.includes(this.#BLOCK_END)) {
            const start = existing.indexOf(this.#BLOCK_BEGIN);
            const end = existing.indexOf(this.#BLOCK_END) + this.#BLOCK_END.length;
            fs.writeFileSync(file, `${existing.slice(0, start)}${block}${existing.slice(end)}`);
            return 'updated';
        }

        const separator = existing === '' || existing.endsWith('\n') ? '' : '\n';
        fs.writeFileSync(file, `${existing}${separator}${block}\n`);
        return existing === '' ? 'created' : 'appended';
    }

    /** @returns {boolean} **/
    static #removeManagedBlock(file) {
        if (!fs.existsSync(file)) return false;

        const existing = fs.readFileSync(file, 'utf8');
        if (!existing.includes(this.#BLOCK_BEGIN) || !existing.includes(this.#BLOCK_END)) return false;

        const start = existing.indexOf(this.#BLOCK_BEGIN);
        const end = existing.indexOf(this.#BLOCK_END) + this.#BLOCK_END.length;
        const stripped = `${existing.slice(0, start)}${existing.slice(end)}`.replace(/\n{3,}/g, '\n\n');

        fs.writeFileSync(file, stripped.trimStart());
        return true;
    }

    /** @returns {undefined} **/
    static #installNpmrc() {
        const action = this.#upsertManagedBlock(
            NPM_USR_CONFIG_FILE,
            [
                `# ${this.#MANAGED_MARKER} — ${this.#REGENERATE_HINT}`,
                '# npm has no release-age or provenance setting; the wrapper enforces those.',
                '# This line is the part npm can enforce by itself, and it keeps holding even',
                '# when npm is invoked by a tool that never sees the shim.',
                'ignore-scripts=true'
            ].join('\n')
        );

        const { dim } = Logger.styles;
        this.#report('npm config', `${NPM_USR_CONFIG_FILE} ${dim(`(${action})`)}`);
    }

    /** @returns {undefined} **/
    static #removeNpmrcBlock() {
        if (this.#removeManagedBlock(NPM_USR_CONFIG_FILE)) {
            const { dim } = Logger.styles;
            this.#report('npm config', `${NPM_USR_CONFIG_FILE} ${dim('(managed block removed)')}`);
        }
    }

    static #SHELL_STARTUP_FILES = ['.profile', '.bashrc', '.zshrc'];
    static #shellStartupTargets() {
        const candidates = this.#SHELL_STARTUP_FILES
            .map(name => path.join(os.homedir(), name))
            .filter(file => fs.existsSync(file));
        return candidates.length ? candidates : [path.join(os.homedir(), '.profile')];
    }

    static #pathTouchedSummary(hint) {
        const { dim } = Logger.styles;
        if (IS_WINDOWS) {
            return `the user PATH ${dim('(via PowerShell)')}`;
        }

        const targets = this.#shellStartupTargets().map(file => file.replace(os.homedir(), '~'));
        return `${targets.join('  ')} ${dim(`(${hint})`)}`;
    }

    static #windowsUserPath = () => execFileSync(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-Command', "[Environment]::GetEnvironmentVariable('Path','User')"],
        { encoding: 'utf8' }
    ).trim();

    static #setWindowsUserPath = (value) => void execFileSync(
        'powershell',
        [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `[Environment]::SetEnvironmentVariable('Path', $env:SECURE_NPM_NEW_PATH, 'User')`,
        ],
        { encoding: 'utf8', env: { ...process.env, SECURE_NPM_NEW_PATH: value } }
    );

    static #installPathWindows() {
        const current = this.#windowsUserPath();
        const entries = current.split(';').filter(Boolean);

        const { dim } = Logger.styles;
        if (entries.some(entry => path.resolve(entry).toLowerCase() === path.resolve(APP_BIN_DIR).toLowerCase())) {
            this.#report('PATH', `already contains the shim directory ${dim('(unchanged)')}`);
            return;
        }

        const backup = path.join(APP_BIN_DIR, `path-backup-${Date.now()}.txt`);
        fs.writeFileSync(backup, current);

        // setx is deliberately avoided: it truncates PATH at 1024 characters.
        this.#setWindowsUserPath([APP_BIN_DIR, ...entries].join(';'));
        this.#report('PATH', `shim directory prepended to the user PATH ${dim('(updated)')}`);
        this.#report('backup', backup, 1);
        this.#note('open a new terminal for the PATH change to take effect');
    }

    static #installPathPosix() {
        const body = [
            `# ${this.#MANAGED_MARKER} — ${this.#REGENERATE_HINT}`,
            `export PATH="${APP_BIN_DIR}:$PATH"`
        ].join('\n');

        for (const file of this.#shellStartupTargets()) {
            this.#upsertManagedBlock(file, body);
            this.#report('PATH', file);
        }

        this.#note('open a new shell, or source the file above, for the PATH change to take effect');
    }

    /** @returns {undefined} **/
    static #installPath() {
        if (IS_WINDOWS) this.#installPathWindows();
        else this.#installPathPosix();
    }

    static #removePathWindows() {
        const { dim } = Logger.styles;
        const current = this.#windowsUserPath();
        const target = path.resolve(APP_BIN_DIR).toLowerCase();
        const kept = current
            .split(';')
            .filter(Boolean)
            .filter(entry => path.resolve(entry).toLowerCase() !== target);

        if (kept.length === current.split(';').filter(Boolean).length) return;

        this.#setWindowsUserPath(kept.join(';'));
        this.#report('PATH', `shim directory removed from the user PATH ${dim('(updated)')}`);
    }

    static #removePathPosix() {
        const { dim } = Logger.styles;
        for (const name of this.#SHELL_STARTUP_FILES) {
            const file = path.join(os.homedir(), name);
            if (this.#removeManagedBlock(file)) this.#report('PATH', `${file} ${dim('(managed block removed)')}`);
        }
    }

    /**
     * @param {string} title
     * @param {string | null} [next]
     * @returns {undefined}
     */
    static #printReport(title, next = null) {
        const { dim, yellow, bold, columns } = Logger.styles

        Logger.write(`\n${bold(title)}\n\n`);
        const rows = [
            ...this.#done,
            ...this.#notes.map(note => ({ label: 'note', value: note })),
            ...(next ? [{ label: 'next', value: bold(next) }] : []),
        ];
        if (!rows.length) {
            Logger.write(`  ${dim('nothing to remove')}\n\n`);
            return;
        }

        const lines = columns(rows, label => (label.trimEnd() === 'note' ? yellow(label) : dim(label)));
        const sections = [
            lines.slice(0, this.#done.length),
            lines.slice(this.#done.length)
        ].filter(section => section.length);

        Logger.write(`${sections.map(section => section.join('\n')).join('\n\n')}\n\n`);
    }
}
