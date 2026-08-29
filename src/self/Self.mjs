import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import Logger from '../logs/Logger.mjs';
import Policy from '../policy/Policy.mjs';
import System from '../system/System.mjs';
import Runtime from '../install/Runtime.mjs';
import Compromised from '../compromised/Compromised.mjs';
import Validate from './Validate.mjs';
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
} from '../paths.mjs';

/**
 * `secure-npm doctor | edit-policy | log | policy | validate | version`.
 * doctor exists because every layer fails open when it is not wired up, and
 * none of them announce themselves.
 */
export default class Self {
    static #OK = '  ok    ';
    static #BAD = '  FAIL  ';
    static #MEH = '  warn  ';

    /**
     * Seeded rather than empty, because the merge is shallow and that is not
     * the obvious half: a key written here replaces the shared value outright.
     * `$` keys are ignored, so the examples document without taking effect.
     */
    static #OVERLAY_TEMPLATE = {
        $comment: [
            'Machine-local policy overlay, shallow-merged on top of the shared policy.json.',
            'A key set here REPLACES the shared value, it does not extend it.',
            'Keys starting with $ are ignored - rename an example to switch it on.',
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

    static #line(status, label, detail) {
        Logger.write(`${status}${label.padEnd(34)}${detail ?? ''}\n`);
    }

    static #pathContainsBinDir() {
        const target = path.resolve(APP_BIN_DIR).toLowerCase();
        return (process.env.PATH ?? '')
            .split(path.delimiter)
            .some(entry => path.resolve(entry.replace(/^"|"$/g, '')).toLowerCase() === target);
    }

    static #packageVersion(root) {
        try {
            return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version ?? null;
        } catch {
            return null;
        }
    }

    /**
     * The stamp records the installed version - not necessarily the version of
     * the clone this command was started from.
     */
    static #reportVersion() {
        const running = this.#packageVersion(MODULE_ROOT_PATH);
        const { stamp } = Runtime.status();

        if (!stamp?.version) {
            this.#line(this.#MEH, 'version', `${running ?? 'unknown'} here - nothing is installed yet`);
            return;
        }

        stamp.version === running
            ? this.#line(this.#OK, 'version', `${stamp.version} installed`)
            : this.#line(this.#MEH, 'version', `${stamp.version} installed, ${running ?? 'unknown'} in this working copy`);
    }

    /** A copy that has fallen behind enforces yesterday's policy and says nothing. **/
    static #reportRuntime(fail) {
        const { state, stamp } = Runtime.status();

        if (state === 'missing') {
            fail('runtime deployed', `missing: ${APP_RUNTIME_DIR} - run "node installer.mjs" from the repository`);
            return;
        }

        if (state === 'unstamped') {
            fail('runtime deployed', `${APP_RUNTIME_DIR} carries no stamp - re-run "node installer.mjs"`);
            return;
        }

        if (state === 'stale') {
            this.#line(this.#OK, 'runtime deployed', APP_RUNTIME_DIR);
            fail('runtime up to date', `the source has changed - run "node ${path.join(stamp.source, 'installer.mjs')}"`);
            return;
        }

        this.#line(this.#OK, 'runtime deployed', `${APP_RUNTIME_DIR} (${stamp.deployedAt})`);
        state === 'source-gone'
            ? this.#line(this.#MEH, 'runtime source', `no longer at ${stamp.source} - updates cannot be checked`)
            : this.#line(this.#OK, 'runtime source', stamp.source);
    }

    /** Reported from the cache alone - the network would turn "missing connection" into a failed check. **/
    static #reportCompromisedList(policy, fail) {
        const { source, cached } = Compromised.cacheStatus(policy);

        if (!source) {
            this.#line(this.#MEH, 'malicious-package list', 'off - "compromisedPackagesSource" is not set in policy.json');
            return;
        }

        if (!cached) {
            this.#line(this.#MEH, 'malicious-package list', `${source} (not fetched yet - the next install fetches it)`);
            return;
        }

        const ageHours = Math.round((Date.now() - cached.fetchedAt) / 3_600_000);
        const detail = `${cached.count} package(s), fetched ${ageHours}h ago`;

        // Past the stale window installs are refused outright - one offline moment from blocking.
        ageHours * 60 > policy.compromisedPackagesMaxStaleMinutes
            ? fail('malicious-package list', `${detail} - older than the max-stale window, installs will be refused`)
            : this.#line(this.#OK, 'malicious-package list', detail);
    }

    static #doctor() {
        const policy = Policy.load();
        let failures = 0;
        const fail = (label, detail) => {
            failures += 1;
            this.#line(this.#BAD, label, detail);
        };

        Logger.write(`\nsecure-npm doctor - running from ${MODULE_ROOT_PATH}\n\n`);

        this.#reportVersion();
        this.#reportRuntime(fail);

        fs.existsSync(POLICY_FILE)
            ? this.#line(this.#OK, 'policy file', POLICY_FILE)
            : fail('policy file', `missing: ${POLICY_FILE}`);
        fs.existsSync(LOCAL_POLICY_FILE)
            ? this.#line(this.#OK, 'local policy overlay', LOCAL_POLICY_FILE)
            : this.#line(this.#OK, 'local policy overlay', 'none - "secure-npm edit-policy" creates one');

        this.#line(
            this.#OK,
            'release age',
            `${policy.minimumReleaseAgeMinutes} min (${(policy.minimumReleaseAgeMinutes / 1440).toFixed(1)} days)`
        );
        this.#line(this.#OK, 'blocked managers', [...policy.blockedManagers.keys()].join(', ') || 'none');
        this.#line(this.#OK, 'blocked packages', `${policy.blockedPackages.length} pattern(s)`);

        this.#reportCompromisedList(policy, fail);

        this.#line(
            policy.allowExoticSources ? this.#MEH : this.#OK,
            'git sources allowed',
            policy.allowExoticSources
                ? 'every git and tarball source (allowExoticSources is on)'
                : policy.allowedGitSources.map(({ source }) => source).join(', ') || 'none'
        );

        fs.existsSync(APP_SHIM_MARKER_FILE)
            ? this.#line(this.#OK, 'shim directory', APP_BIN_DIR)
            : fail('shim directory', `not installed: ${APP_BIN_DIR} - run "node installer.mjs"`);

        // Shims written before the runtime was deployed still start the repository copy.
        const shimFile = path.join(APP_BIN_DIR, IS_WINDOWS ? 'npm.cmd' : 'npm');
        if (fs.existsSync(shimFile)) {
            fs.readFileSync(shimFile, 'utf8').includes(APP_ENTRYPOINT)
                ? this.#line(this.#OK, 'shims start the runtime', APP_ENTRYPOINT)
                : fail('shims start the runtime', `${shimFile} points elsewhere - re-run "node installer.mjs"`);
        }

        this.#pathContainsBinDir()
            ? this.#line(this.#OK, 'shim directory on PATH', 'yes')
            : fail('shim directory on PATH', `add ${APP_BIN_DIR} to PATH, ahead of Node's own bin directory`);

        for (const name of ['npm', 'pnpm']) {
            const found = System.findManager(name);
            found
                ? this.#line(this.#OK, `real ${name}`, found.file)
                : this.#line(this.#MEH, `real ${name}`, 'not found on PATH');
        }

        if (!fs.existsSync(PNPM_CONFIG_FILE)) {
            fail('pnpm global config', `missing: ${PNPM_CONFIG_FILE}`);
        } else {
            const contents = fs.readFileSync(PNPM_CONFIG_FILE, 'utf8');
            contents.includes(PNPM_HOOK_FILE)
                ? this.#line(this.#OK, 'pnpm hook wired', PNPM_HOOK_FILE)
                : fail('pnpm hook wired', `globalPnpmfile does not point at ${PNPM_HOOK_FILE}`);
            /^\s*minimumReleaseAge\s*:/m.test(contents)
                ? this.#line(this.#OK, 'pnpm release-age policy', 'set')
                : fail('pnpm release-age policy', 'minimumReleaseAge is not set');
            /^\s*trustPolicy\s*:\s*no-downgrade/m.test(contents)
                ? this.#line(this.#OK, 'pnpm trust policy', 'no-downgrade')
                : this.#line(this.#MEH, 'pnpm trust policy', 'not set to no-downgrade');

            // Editing allowedGitSources without reinstalling leaves pnpm
            // blocking natively what the policy now allows.
            const blocksNatively = /^\s*blockExoticSubdeps\s*:\s*true/m.test(contents);
            const shouldBlockNatively = !policy.allowExoticSources && policy.allowedGitSources.length === 0;
            blocksNatively === shouldBlockNatively
                ? this.#line(
                      this.#OK,
                      'pnpm exotic sub-dependencies',
                      blocksNatively ? 'blocked natively' : 'delegated to the hook'
                  )
                : fail('pnpm exotic sub-dependencies', 'no longer matches the policy - run "node installer.mjs"');
        }

        if (!fs.existsSync(NPM_USR_CONFIG_FILE)) {
            fail('npm user config', `missing: ${NPM_USR_CONFIG_FILE}`);
        } else {
            /^\s*ignore-scripts\s*=\s*true/m.test(fs.readFileSync(NPM_USR_CONFIG_FILE, 'utf8'))
                ? this.#line(this.#OK, 'npm ignore-scripts', NPM_USR_CONFIG_FILE)
                : fail('npm ignore-scripts', `not set in ${NPM_USR_CONFIG_FILE}`);
        }

        // A blocked manager reachable by absolute path is out of the shims' reach.
        for (const command of policy.blockedManagers.keys()) {
            const found = System.findManager(command);
            if (found) this.#line(this.#MEH, `blocked manager present`, `${command} → ${found.file}`);
        }

        this.#line(fs.existsSync(APP_AUDIT_LOG_FILE) ? this.#OK : this.#MEH, 'audit log', APP_AUDIT_LOG_FILE);

        Logger.write(`\n${failures === 0 ? 'All guard rails are in place.' : `${failures} check(s) failed.`}\n\n`);
        return failures === 0 ? 0 : 1;
    }

    static #showLog(argv) {
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
                Logger.write(`${entry.ts}  ${String(entry.event).toUpperCase().padEnd(5)}  ${subject}${argv}\n`);

                const violations = entry.violations ?? (entry.rule ? [entry] : []);
                for (const violation of violations) {
                    const where = violation.subject ? `${violation.subject} - ` : '';
                    Logger.write(`    ${violation.rule}: ${where}${violation.reason}\n`);
                }
            } catch {
                Logger.write(`${raw}\n`);
            }
        }
        return 0;
    }

    static #showPolicy() {
        const policy = Policy.load();
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

    static #showVersion() {
        const require = createRequire(import.meta.url);
        const { name, version } = require(path.join(MODULE_ROOT_PATH, 'package.json'));
        const { stamp } = Runtime.status();

        // Two versions, two different things: what this command runs from, and
        // what the shims and the pnpm hook load on every install.
        const rows = [
            { label: 'root', value: MODULE_ROOT_PATH },
            { label: 'entry', value: APP_ENTRYPOINT },
            { label: 'installed', value: stamp?.version ? `${stamp.version} (${stamp.deployedAt})` : 'nothing deployed' },
        ];

        Logger.write(`${name} ${version}\n${Logger.styles.columns(rows).join('\n')}\n`);
        return 0;
    }

    /**
     * $VISUAL / $EDITOR first, and waited on - blocking is what makes it
     * possible to check the file once it closes. The desktop handler is the
     * fallback and returns immediately.
     */
    static #openEditor(file) {
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

    static #editPolicy() {
        fs.mkdirSync(APP_CONFIG_DIR, { recursive: true });

        const created = !fs.existsSync(LOCAL_POLICY_FILE);
        if (created) fs.writeFileSync(LOCAL_POLICY_FILE, `${JSON.stringify(this.#OVERLAY_TEMPLATE, null, 4)}\n`);

        Logger.write(`${created ? 'created' : 'editing'} ${LOCAL_POLICY_FILE}\n`);

        const { launched, waited, command } = this.#openEditor(LOCAL_POLICY_FILE);
        if (!launched) {
            Logger.write(`could not start an editor (${command}) - open the file above yourself\n`);
            return 0;
        }

        if (!waited) {
            Logger.write('run "secure-npm doctor" once you are done to check the result\n');
            return 0;
        }

        // An overlay that does not parse takes every npm and pnpm command down with it.
        try {
            JSON.parse(fs.readFileSync(LOCAL_POLICY_FILE, 'utf8'));
        } catch (error) {
            Logger.writeErr(`\nthis file is not valid JSON - every npm and pnpm command will fail until it is\n`);
            Logger.writeErr(`  ${error.message}\n`);
            return 1;
        }

        const { stamp } = Runtime.status();
        const installer = stamp?.source ? path.join(stamp.source, 'installer.mjs') : 'installer.mjs';
        Logger.write(`\npnpm keeps its own copy of the release-age, trust and exotic-source settings.\n`);
        Logger.write(`If you changed any of those, re-run "node ${installer}", then "secure-npm doctor".\n`);

        return 0;
    }

    /** @returns {number | Promise<number>} **/
    static run(command, argv) {
        switch (command) {
            case 'doctor': {
                const code = this.#doctor();
                Logger.pruneAuditLog(Policy.load().logRetentionDays);
                return code;
            }
            case 'edit-policy':
                return this.#editPolicy();
            case 'log':
                return this.#showLog(argv);
            case 'policy':
                return this.#showPolicy();
            case 'validate':
                return Validate.run(argv);
            case 'version':
                return this.#showVersion();
            default:
                Logger.writeErr(`secure-npm: unknown command "${command}"\n`);
                return 2;
        }
    }
}
