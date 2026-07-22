#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Override scrubbing config before loading the module
const args = process.argv.slice(2);
const replace = args.includes('--replace');

const levelIdx = args.indexOf('--level');
if (levelIdx !== -1 && args[levelIdx + 1]) {
  process.env.SCRUBBING_LEVEL = args[levelIdx + 1];
}

const saltIdx = args.indexOf('--salt');
if (saltIdx !== -1 && args[saltIdx + 1]) {
  process.env.SCRUBBING_IP_SALT = args[saltIdx + 1];
}

process.env.SCRUBBING_ENABLED = 'true';

const scrubber = require('../lib/data-scrubber');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_FILES = ['access.log', 'blocked-requests.log'];

function scrubFile(filename) {
  const filePath = path.join(LOG_DIR, filename);

  if (!fs.existsSync(filePath)) {
    console.log(`  Skipping ${filename} (not found)`);
    return { lines: 0, skipped: true };
  }

  const data = fs.readFileSync(filePath, 'utf8');
  const lines = data.split('\n');
  const scrubbed = lines.map(line => {
    if (!line.trim()) return line;
    return scrubber.scrubLogEntry(line);
  });

  const outPath = replace
    ? filePath
    : filePath + '.scrubbed';

  if (replace) {
    const bakPath = filePath + '.bak';
    fs.copyFileSync(filePath, bakPath);
    console.log(`  Backed up to ${filename}.bak`);
  }

  fs.writeFileSync(outPath, scrubbed.join('\n'), 'utf8');

  const nonEmpty = lines.filter(l => l.trim().length > 0).length;
  console.log(`  ${replace ? 'Replaced' : 'Wrote'} ${path.basename(outPath)}: ${nonEmpty} lines scrubbed`);
  return { lines: nonEmpty, skipped: false };
}

console.log(`\nLog Scrubber — level: ${process.env.SCRUBBING_LEVEL || 'partial'}`);
if (!process.env.SCRUBBING_IP_SALT) {
  console.log('  WARNING: No --salt provided. Using random salt — hashes will not correlate with runtime data.');
}
console.log(`  Mode: ${replace ? 'replace (originals backed up to .bak)' : 'write .scrubbed files'}\n`);

let totalLines = 0;
for (const file of LOG_FILES) {
  console.log(`Processing ${file}...`);
  const result = scrubFile(file);
  totalLines += result.lines;
}

console.log(`\nDone. ${totalLines} total lines processed.`);
