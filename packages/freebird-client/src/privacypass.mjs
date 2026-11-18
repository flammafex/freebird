// The only module that imports the peer dependency. Consumers install
// @cloudflare/privacypass-ts 0.9.0 themselves so that their bundler resolves a
// single copy shared with the rest of the application.
export { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
