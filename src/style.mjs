/**
 * Terminal styling, shared by everything that prints.
 *
 * Colour is decided per stream rather than once for the process: the wrapper
 * reports on stderr so stdout stays the wrapped command's, while the installers
 * report on stdout. Asking `process.stdout.isTTY` on behalf of stderr is how
 * output ends up with escape codes in a pipe.
 */

const ESC = '[';

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
 * Label/value rows in one aligned column.
 *
 * The column is measured from the longest label instead of being padded by hand
 * at each call site, so adding a label can no longer knock the ones around it
 * out of line. `depth` indents a row without breaking that alignment: the value
 * column stays put and only the label moves right.
 *
 * Padding happens before painting — an escape sequence is invisible on screen
 * but very much counted by padEnd.
 *
 * @param {{ label: string, value?: string, depth?: number }[]} rows
 */
export function columns(rows, paintLabel = text => text) {
    const width = Math.max(0, ...rows.map(({ label, depth = 0 }) => depth * 2 + label.length));

    return rows.map(({ label, value = '', depth = 0 }) => {
        const indent = ' '.repeat(depth * 2);
        return `  ${indent}${paintLabel(label.padEnd(width - depth * 2))}  ${value}`.trimEnd();
    });
}
