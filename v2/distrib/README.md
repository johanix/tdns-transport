# distrib: CHUNK manifests

Splits a payload into CHUNK records (a manifest at sequence 0, with the
payload inline when it fits, then numbered data records) and reassembles
it. The DNS mechanism uses it in query mode. See `doc.go`.
