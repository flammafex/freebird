// sdk/js/debug-crypto.ts
import { p256 } from '@noble/curves/p256';

console.log('--- Debugging p256 export ---');
console.log('Type:', typeof p256);
console.log('Keys:', Object.keys(p256));
console.log('Has hashToCurve?', typeof p256.hashToCurve);
console.log('Has ProjectivePoint?', !!p256.ProjectivePoint);