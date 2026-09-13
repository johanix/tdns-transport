/*
Package hpke is the HPKE primitive layer: X25519 + HKDF-SHA256 + AES-256-GCM
through Cloudflare CIRCL, in base and auth mode, with key generation and
derivation and zero-key rejection.

It has no caller yet. It is kept for the planned COSE-HPKE work, where HPKE
is the recipient algorithm inside a COSE envelope (the COSE backend of
crypto.Backend, not a backend of its own): what that work seals and opens
with is exactly Encrypt, Decrypt, EncryptAuth and DecryptAuth here. The
earlier design that wrapped these functions, a crypto.Backend that
misdescribed itself, an EDNS0 option carrying the ephemeral key, KMREQ query
names and their enums, was removed in the 2026-09 transport cleanup (step
7); git history keeps it.
*/
package hpke
