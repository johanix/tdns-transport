// Package distrib splits a payload into CHUNK records and reassembles it:
// a manifest record (sequence 0, with the payload inline when it fits)
// followed by numbered data records. The DNS mechanism uses it in query
// mode, where the receiver fetches the records instead of reading the
// payload from the NOTIFY's EDNS0 option.
//
// The distribution lifecycle, tracker and store interfaces, the JWT
// manifest and the JWS(JWE) transport encoder that once lived here had no
// caller and were removed in the 2026-09 transport cleanup (step 7); the
// transport's own PayloadCrypto is the one place a payload is wrapped.
package distrib
