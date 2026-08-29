#!/usr/bin/env node
/**
 * Usage: node installer.mjs [-u | --uninstall] [-y]
 *
 *   -u, --uninstall   remove everything the installer put in place
 *   -y                answer yes to the confirmation prompt
 */

import Installer from './src/install/Installer.mjs';

const flags = new Set(process.argv.slice(2));


if (flags.has('-u') || flags.has('--uninstall')) await Installer.uninstall();
else await Installer.install();
