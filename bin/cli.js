#!/usr/bin/env node

const { run } = require('../lib/index.js');

run().catch((err) => {
  console.error('\n❌ Error:', err.message);
  process.exit(1);
});

