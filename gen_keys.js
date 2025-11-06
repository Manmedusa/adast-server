const { writeFileSync } = require('fs');
const { generateKeyPairSync } = require('crypto');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

writeFileSync('jwt_private.pem', privateKey);
writeFileSync('jwt_public.pem', publicKey);

console.log('✅ Generated jwt_private.pem and jwt_public.pem');