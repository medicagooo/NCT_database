import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

function printUsageAndExit() {
  console.error('Usage: npm run key:derive-public -- <private-key.pem>');
  process.exit(1);
}

const inputPath = process.argv[2];
if (!inputPath) {
  printUsageAndExit();
}

let privateKeyPem;
try {
  privateKeyPem = readFileSync(inputPath, 'utf8');
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to read private key: ${message}`);
  process.exit(1);
}

try {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKeyPem = createPublicKey(privateKey).export({
    format: 'pem',
    type: 'spki',
  });
  process.stdout.write(String(publicKeyPem).trimEnd() + '\n');
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to derive public key: ${message}`);
  process.exit(1);
}
