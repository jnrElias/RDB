/* Genera los hashes de acceso para YT Studio.
 *
 * Uso:
 *   node scripts/gen-credentials.js "tu@correo.com" "TuContraseña"
 *
 * Copia los tres valores (saltVer, saltKey, verifier) dentro del objeto CFG
 * en app.js. La contraseña NUNCA se guarda, solo su hash irreversible.
 */
const crypto = require('crypto');

const email = process.argv[2];
const password = process.argv[3];
const ITER = 310000;

if (!email || !password) {
  console.error('Uso: node scripts/gen-credentials.js "correo" "contraseña"');
  process.exit(1);
}

const saltVer = crypto.randomBytes(16);
const saltKey = crypto.randomBytes(16);
const input = Buffer.from(email + ' ' + password, 'utf8');
const verifier = crypto.pbkdf2Sync(input, saltVer, ITER, 32, 'sha256');

console.log('\nPega esto en el objeto CFG de app.js:\n');
console.log('const CFG = {');
console.log('  iter: ' + ITER + ',');
console.log("  saltVer: '" + saltVer.toString('hex') + "',");
console.log("  saltKey: '" + saltKey.toString('hex') + "',");
console.log("  verifier: '" + verifier.toString('hex') + "',");
console.log('};\n');
