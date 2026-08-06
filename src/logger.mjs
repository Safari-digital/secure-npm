/**
 * Console output and the audit trail.
 *
 * Everything the tool prints goes to stderr: `npm view --json | jq` and friends
 * must keep working, so stdout stays the wrapped command's alone.
 */

import fs from 'node:fs';
import { auditLogFile, logDir } from './paths.mjs';

const COLOR_ENABLED = process.stderr.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

const ESC = '\u001b[';
const paint = (code, text) => (COLOR_ENABLED ? `${ESC}${code}m${text}${ESC}0m` : text);
const dim = text => paint('2', text);
const bold = text => paint('1', text);
const red = text => paint('31', text);
const green = text => paint('32', text);
const yellow = text => paint('33', text);

const TAG = 'secure-npm';
// Lines up with the "<glyph> secure-npm  " prefix of the headline above them.
const GUTTER = ' '.repeat(TAG.length + 4);

function field(label, value) {
    return `${dim(`${GUTTER}${label.padEnd(9)}`)}${value}`;
}

function emit(line) {
    process.stderr.write(`${line}\n`);
}

/**
 * Printed before the wrapped command starts, so it is always visible which
 * policy an install ran under — including when it ran under none.
 */
export function banner({ command, policyFiles, hookFile, extras = {} }) {
    emit(`${green('▸')} ${bold(TAG)}  Securely running ${bold(command)}`);
    emit(field('policy', policyFiles.join(dim(' + '))));
    if (hookFile) emit(field('hook', hookFile));
    for (const [label, value] of Object.entries(extras)) emit(field(label, value));
    emit(field('audit', auditLogFile));
}

/** A rule fired. Reported in full, then written to the audit log. */
export function reportBlock({ rule, subject, reason, hint }) {
    emit('');
    emit(`${red('✖')} ${bold(TAG)}  ${red(bold('BLOCKED'))}  ${subject}`);
    emit(field('rule', rule));
    emit(field('reason', reason));
    if (hint) emit(field('hint', hint));
    emit('');
}

/** Several rules fired at once — one call keeps the report readable. */
export function reportBlocks({ rule, title, entries, hint }) {
    emit('');
    emit(`${red('✖')} ${bold(TAG)}  ${red(bold('BLOCKED'))}  ${title}`);
    emit(field('rule', rule));
    for (const entry of entries) emit(field('', entry));
    if (hint) emit(field('hint', hint));
    emit('');
}

export function warn(message) {
    emit(`${yellow('!')} ${bold(TAG)}  ${message}`);
}

export function info(message) {
    emit(`${dim('·')} ${bold(TAG)}  ${dim(message)}`);
}

export function checked(message) {
    emit(`${green('✓')} ${bold(TAG)}  ${message}`);
}

/**
 * One JSON object per line. Append-only and best-effort: a broken audit file
 * must never be the reason an install fails.
 */
export function audit(entry) {
    try {
        fs.mkdirSync(logDir, { recursive: true });
        const record = { ts: new Date().toISOString(), pid: process.pid, ...entry };
        fs.appendFileSync(auditLogFile, `${JSON.stringify(record)}\n`, 'utf8');
    } catch (error) {
        emit(`${yellow('!')} ${bold(TAG)}  could not write the audit log: ${error.message}`);
    }
}

const PRUNE_THRESHOLD_BYTES = 5 * 1024 * 1024;

/** Rewriting the log on every command would be wasteful; size is the trigger. */
export function maybePruneAuditLog(retentionDays) {
    try {
        if (fs.statSync(auditLogFile).size < PRUNE_THRESHOLD_BYTES) return;
    } catch {
        return;
    }
    pruneAuditLog(retentionDays);
}

/** Drops audit lines older than the retention window. Cheap enough to run inline. */
export function pruneAuditLog(retentionDays) {
    try {
        if (!fs.existsSync(auditLogFile)) return;
        const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
        const kept = fs
            .readFileSync(auditLogFile, 'utf8')
            .split('\n')
            .filter(line => {
                if (line.trim() === '') return false;
                const stamp = Date.parse(JSON.parse(line).ts);
                return Number.isNaN(stamp) || stamp >= cutoff;
            });
        fs.writeFileSync(auditLogFile, kept.length ? `${kept.join('\n')}\n` : '', 'utf8');
    } catch {
        // Retention is housekeeping; failing to prune is not worth a message.
    }
}
