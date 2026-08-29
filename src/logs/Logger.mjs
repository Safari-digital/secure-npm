import fs from 'node:fs';
import { stdin, stdout, stderr } from 'node:process';
import { columns, styleFor } from "./style.mjs";
import readline from "node:readline";
import { APP_AUDIT_LOG_FILE, APP_LOG_DIR } from "../paths.mjs";

export default class Logger {
    static styles = { ...styleFor(stdout), columns };

    static #stylesErr               = styleFor(stderr);
    static #TAG                     = 'secure-npm';
    static #GUTTER                  = ' '.repeat(this.#TAG.length + 4);
    static #PRUNE_THRESHOLD_BYTES   = 5 * 1024 * 1024;

    /** @param {string} str **/
    static write = (str) => stdout.write(str);
    /** @param {string} str **/
    static writeErr = (str) => stderr.write(str);

    static ask = (question) => new Promise(resolve => {
        const prompt = readline.createInterface({ input: stdin, output: stdout });
        prompt.question(question, answer => { resolve(answer); prompt.close(); });
        prompt.on('close', () => resolve(''));
    });

    /** One field line, gutter-aligned and newline-terminated, ready to write. **/
    static #field(label, value) {
        const { dim } = this.#stylesErr;
        return `${dim(`${this.#GUTTER}${label.padEnd(9)}`)}${value}\n`;
    }

    /** @param {{ command: string, policyFiles: string[], hookFile?: string, action?: string, extras?: Object }} _ **/
    static banner({ command, policyFiles, hookFile, action = 'Securely running', extras = {} }) {
        const { dim, bold, green } = this.#stylesErr;
        this.writeErr(`${green('▸')} ${bold(this.#TAG)}  ${action} ${bold(command)}\n`);
        this.writeErr(this.#field('policy', policyFiles.join(dim(' + '))));
        if (hookFile) this.writeErr(this.#field('hook', hookFile));
        for (const [label, value] of Object.entries(extras)) this.writeErr(this.#field(label, value));
        this.writeErr(this.#field('audit', APP_AUDIT_LOG_FILE));
    }

    /** @param {{ rule: string, subject: string, reason: string, hint?: string }} _ **/
    static reportBlock({ rule, subject, reason, hint }) {
        const { bold, red } = this.#stylesErr;
        this.writeErr(`\n${red('✖')} ${bold(this.#TAG)}  ${red(bold('BLOCKED'))}  ${subject}\n`);
        this.writeErr(this.#field('rule', rule));
        this.writeErr(this.#field('reason', reason));
        if (hint) this.writeErr(this.#field('hint', hint));
        this.writeErr('\n');
    }

    /** @param {{ rule: string, title: string, entries: string[], hint?: string }} _ **/
    static reportBlocks({ rule, title, entries, hint }) {
        const { bold, red } = this.#stylesErr;
        this.writeErr(`\n${red('✖')} ${bold(this.#TAG)}  ${red(bold('BLOCKED'))}  ${title}\n`);
        this.writeErr(this.#field('rule', rule));
        for (const entry of entries) this.writeErr(this.#field('', entry));
        if (hint) this.writeErr(this.#field('hint', hint));
        this.writeErr('\n');
    }

    /** @param {string} message **/
    static warn(message) {
        const { bold, yellow } = this.#stylesErr;
        this.writeErr(`${yellow('!')} ${bold(this.#TAG)}  ${message}\n`);
    }

    /** @param {string} message **/
    static info(message) {
        const { dim, bold } = this.#stylesErr;
        this.writeErr(`${dim('·')} ${bold(this.#TAG)}  ${dim(message)}\n`);
    }

    /** @param {string} message **/
    static checked(message) {
        const { bold, green } = this.#stylesErr;
        this.writeErr(`${green('✓')} ${bold(this.#TAG)}  ${message}\n`);
    }

    /** @param {Object} entry **/
    static audit(entry) {
        try {
            fs.mkdirSync(APP_LOG_DIR, { recursive: true });
            const record = { ts: new Date().toISOString(), pid: process.pid, ...entry };
            fs.appendFileSync(APP_AUDIT_LOG_FILE, `${JSON.stringify(record)}\n`, 'utf8');
        } catch (error) {
            this.warn(`could not write the audit log: ${error.message}`);
        }
    }

    /** @param {number} retentionDays **/
    static maybePruneAuditLog(retentionDays) {
        try {
            if (fs.statSync(APP_AUDIT_LOG_FILE).size < this.#PRUNE_THRESHOLD_BYTES) return;
        } catch {
            return;
        }
        this.pruneAuditLog(retentionDays);
    }

    /** @param {number} retentionDays **/
    static pruneAuditLog(retentionDays) {
        try {
            if (!fs.existsSync(APP_AUDIT_LOG_FILE)) return;
            const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
            const kept = fs
                .readFileSync(APP_AUDIT_LOG_FILE, 'utf8')
                .split('\n')
                .filter(line => {
                    if (line.trim() === '') return false;
                    const stamp = Date.parse(JSON.parse(line).ts);
                    return Number.isNaN(stamp) || stamp >= cutoff;
                });
            fs.writeFileSync(APP_AUDIT_LOG_FILE, kept.length ? `${kept.join('\n')}\n` : '', 'utf8');
        } catch {
            // Retention is housekeeping; failing to prune is not worth a message.
        }
    }
}