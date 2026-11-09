# DTLS transport findings

Observed from the unpacked `iptunctrl_plugin.dll` (static evidence, not a live gateway capture):

- `analysis/focused/1800b77a0.c` creates an OpenSSL DTLS context. The minimum version is `0xfeff` (DTLS 1.0); the maximum is `0xfefd` (DTLS 1.2) when the advertised version text contains `dtls1.2`, otherwise DTLS 1.0.
- `analysis/focused/1800b78f0.c` accepts a 16-byte secret and copies it to `DAT_18036f390`.
- `analysis/dtls/1800b6ea0.c` is the SSL info callback. At state 2 (`DTLS_ST_CR_HELLO_VERIFY_REQUEST`), it reads the DTLS cookie, computes HMAC using that secret, and replaces the cookie only when the digest length equals the original cookie length. The native state map in `dtls-cookie-review/1800059b0.c` binds state2 to "Hello Verify Request" and state12 to "Client Hello"; `1802309d0.c` reads the actual state. The earlier ClientHello label for state2 was incorrect.
- `analysis/dtls_detail/180231ca0.c` and `180231cd0.c` read/write the DTLS1_STATE cookie buffer at `ssl+0xb0`, length field at `cookie+0x100`.
- `analysis/dtls_detail/1801408d0.c` returns descriptor `DAT_1802a66d0`. The descriptor at PE file offset `0x2a56d0` begins `40000000 41000000 14000000 08000000`: digest NID 64 (SHA-1), output length 20. `180142af0.c` is the HMAC routine, with its `crypto\hmac\hmac.c` source references.
- Therefore the observed custom response is `HMAC-SHA1(secret16, server_cookie20)`. Empty initial cookies and cookies of lengths other than 20 are unchanged. This 16-byte secret is not the 48-byte TLS master secret.
- The application session ID (32 bytes) is passed to TunnelService after the DTLS handshake (`analysis/plugin/1800cbc60.c`, calls to `FUN_1800e1e50`). It is not installed as a DTLS resumed session.

Implementation uses pinned Pion DTLS v3.1.15's `ClientHelloMessageHook`. The hook is applied to first and subsequent ClientHello messages and the modified bytes enter its handshake transcript cache. The Config API is used so an explicit cipher policy containing only the custom suite can retain an empty built-in list; the functional-options API rejects an explicitly empty list. No fork, original executable, native DLL, or virtual network interface is used.

Primary dependency source:

- https://github.com/pion/dtls/blob/v3.1.15/options.go (`WithClientHelloMessageHook`)
- https://github.com/pion/dtls/blob/v3.1.15/flight1handler.go (initial ClientHello)
- https://github.com/pion/dtls/blob/v3.1.15/flight3handler.go (HelloVerifyRequest and transcript handling)
- https://github.com/pion/dtls/blob/v3.1.15/session.go (48-byte authenticated TLS session resumption requirements)

Verification in `internal/dtlstransport/dtls_test.go` includes a raw UDP HelloVerifyRequest peer that checks the exact outgoing authenticated cookie, a standard Pion DTLS 1.2 loopback server that performs an encrypted echo with CA validation, and certificate pin failure/cancellation cases. These tests do not establish compatibility with a real Ruijie gateway.

## Live gateway verification, 2026-11-09

The gateway sent a 20-byte HVR Cookie. With the authenticated response, an
independent OpenSSL4.1 client (MTU1472) completed DTLS1.2 with certificate
verification and selected `ECDHE-RSA-AES256-SHA384` (0xc028). Pion's default suite
set did not contain that suite; the initial Pion attempt had failed with alert40.
The second same-sequence HVR alone did not establish a Cookie failure.

`cipher_sha384.go` supplies 0xc028 using Pion's public CBC record cipher and PRF:
SHA384 PRF, 48-byte MAC keys, 32-byte AES keys and 16-byte IVs. Independent
OpenSSL key-expansion and authenticated-record vectors, including a bad MAC
with valid padding, cover this adapter. A local OpenSSL server restricted to
this suite also completed a DTLS handshake and bidirectional encrypted data
exchange. The Go client then completed the real
DTLS handshake, reliable-control configuration and SOCKS5 TCP exchange with
the user-specified internal SSH endpoint. Temporary packet diagnostics and
the OpenSSL comparison helper were removed from the deliverable.

Remaining limitation: Pion v3.1.15 supports DTLS 1.2 only. Its parser rejects DTLS 1.0 ServerHello and its PRF implementation is TLS 1.2-specific. Changing only the advertised version cannot add DTLS 1.0 support.
