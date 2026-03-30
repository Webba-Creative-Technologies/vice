import os from 'os';
import path from 'path';
import fs from 'fs';

export function getViceDataDir() {
  const dir = path.join(os.homedir(), '.vice');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
