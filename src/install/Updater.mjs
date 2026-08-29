import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import Logger from '../logs/Logger.mjs';
import Runtime from './Runtime.mjs';
import { APP_SOURCE_DIR } from '../paths.mjs';

export default class Updater {
    static #hasYesFlag = () => new Set(process.argv.slice(2)).has('-y');

    /** @returns {{ ok: true, output: string } | { ok: false, error: string }} **/
    static #git(args, cwd = undefined) {
        try {
            const output = execFileSync('git', args, { encoding: 'utf8', cwd, stdio: ['ignore', 'pipe', 'pipe'] });
            return { ok: true, output: output.trim() };
        } catch (error) {
            const detail = error.stderr?.toString().trim() || error.message;
            return { ok: false, error: detail.split('\n')[0] };
        }
    }

    static newerVersion(remote, installed) {
        const parse = version =>
            /^\d+(\.\d+)*$/.test(String(version ?? '').trim()) ? String(version).trim().split('.').map(Number) : null;

        const [a, b] = [parse(remote), parse(installed)];
        if (!a || !b) return false;

        for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
            const [left, right] = [a[index] ?? 0, b[index] ?? 0];
            if (left !== right) return left > right;
        }
        return false;
    }

    static #materialiseSource(repository) {
        if (fs.existsSync(path.join(APP_SOURCE_DIR, '.git'))) {
            const pulled = this.#git(['-C', APP_SOURCE_DIR, 'pull', '--ff-only']);
            if (pulled.ok) return { ok: true };
            fs.rmSync(APP_SOURCE_DIR, { recursive: true, force: true });
        }

        fs.mkdirSync(path.dirname(APP_SOURCE_DIR), { recursive: true });
        const cloned = this.#git(['clone', repository, APP_SOURCE_DIR]);
        return cloned.ok ? { ok: true } : cloned;
    }

    /** @returns {Promise<number>} **/
    static async run() {
        const { dim, bold } = Logger.styles;
        const stamp = Runtime.readStamp();

        if (!stamp) {
            Logger.writeErr('secure-npm: nothing is installed - run "node installer.mjs" from a clone first\n');
            return 1;
        }

        const repository = stamp.repository;
        if (!repository) {
            Logger.writeErr('secure-npm: the stamp names no repository - re-install once from a git clone\n');
            return 1;
        }

        if (!this.#git(['--version']).ok) {
            Logger.writeErr('secure-npm: git is required to update\n');
            return 1;
        }

        Logger.write(`\n${bold('secure-npm updater')}\n\n`);
        Logger.write(`${Logger.styles.columns([
            { label: 'installed', value: `${stamp.version} ${dim(`(${stamp.commit?.slice(0, 7) ?? 'unknown commit'})`)}` },
            { label: 'repository', value: repository },
        ]).join('\n')}\n\n`);

        const remote = this.#git(['ls-remote', repository, 'HEAD']);
        if (!remote.ok) {
            Logger.writeErr(`secure-npm: could not reach ${repository} - ${remote.error}\n`);
            return 1;
        }

        const remoteCommit = remote.output.split(/\s/)[0];
        if (stamp.commit && remoteCommit === stamp.commit) {
            Logger.write(`  already up to date ${dim(`(${remoteCommit.slice(0, 7)})`)}\n\n`);
            return 0;
        }

        const source = this.#materialiseSource(repository);
        if (!source.ok) {
            Logger.writeErr(`secure-npm: could not fetch the repository - ${source.error}\n`);
            return 1;
        }

        const { version } = JSON.parse(fs.readFileSync(path.join(APP_SOURCE_DIR, 'package.json'), 'utf8'));
        if (!this.newerVersion(version, stamp.version) && stamp.commit) {
            Logger.write(`  ${version} on ${remoteCommit.slice(0, 7)} is not newer than the installed ${stamp.version} - nothing to do\n\n`);
            return 0;
        }

        Logger.write(`  ${bold(version)} is available ${dim(`(${remoteCommit.slice(0, 7)})`)}\n\n`);

        if (!this.#hasYesFlag()) {
            const answer = await Logger.ask(`  install it? ${dim('[y/N]')} `);
            if (!/^y(es)?$/i.test(answer.trim())) {
                Logger.write(`\n  aborted - nothing was changed\n\n`);
                return 1;
            }
            Logger.write('\n');
        }

        // The new version installs itself: its installer, its rules.
        const child = spawnSync(process.execPath, [path.join(APP_SOURCE_DIR, 'installer.mjs'), '-y'], {
            stdio: 'inherit',
        });
        return child.status ?? 1;
    }
}
