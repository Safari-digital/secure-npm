/** @typedef {function(string): string} Paint **/
/** @typedef {{dim: Paint, bold: Paint, red: Paint, green: Paint, yellow: Paint}} Style **/

const ESC = '[';

/** @returns {Style} **/
export function styleFor(stream) {
    const enabled = Boolean(stream.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
    const paint = (code, text) => (enabled ? `${ESC}${code}m${text}${ESC}0m` : text);
    return {
        dim: text => paint('2', text),
        bold: text => paint('1', text),
        red: text => paint('31', text),
        green: text => paint('32', text),
        yellow: text => paint('33', text),
    };
}

/**
 * Build Label/value rows in one aligned column.
 *
 * @param {{ label: string, value?: string, depth?: number }[]} rows
 * @param {Paint} [paintLabel]
 */
export function columns(rows, paintLabel = text => text) {
    const width = Math.max(0, ...rows.map(({ label, depth = 0 }) => depth * 2 + label.length));

    return rows.map(({ label, value = '', depth = 0 }) => {
        const indent = ' '.repeat(depth * 2);
        return `  ${indent}${paintLabel(label.padEnd(width - depth * 2))}  ${value}`.trimEnd();
    });
}
