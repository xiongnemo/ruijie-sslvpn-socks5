# Native tunnel framing review

Static evidence from `iptunctrl_plugin.dll`, bound by `artifact-hashes.json`.
The review did not change `internal/tunnel/link.go`.

## Confirmed protocol corrections

1. **Control sequences start at 1 in each direction.**
   `sequence/180068e70.c` resets the little-endian DWORD at object offset
   `0x3ea` to `0x00010000`: send counter is zero and expected receive sequence
   at `0x3ec` is one. `focused/180074ff0.c:109` increments the send counter
   before encoding it into the outgoing control header. First client request
   is therefore sequence 1, configuration request sequence 2; first server
   configuration is expected at sequence 1.

2. **Heartbeat fields are hold timeout and send interval, both seconds.**
   `plugin/180072300.c:143` reads hold time, then interval. Its strings identify
   the fields as `nHoldTime` and `nInterval`. Line159 sets a receive deadline
   to current time plus hold time plus ten seconds. Reset defaults in
   `sequence/180068e70.c` are hold180 and interval30. In
   `plugin/1800dd300.c:564` the timer reads the interval; lines964-971 schedule
   the next ping at current time plus that interval. Multiplying the fields
   or sending at the hold period does not match native behavior.

The root agent applied both corrections and added tests while this review
was running.

## Other established differences

- Reset sets next ping time to current time, so the native timer sends the
  first heartbeat immediately (`sequence/180068e70.c:60`,
  `plugin/1800dd300.c:797`). Subsequent pings use the interval.
- The native hold deadline is refreshed by a heartbeat. When that deadline
  expires, `plugin/1800dd300.c:568` also checks whether its received packet
  counter changed since the previous ping; active IP traffic can postpone
  disconnection. A heartbeat-only failure deadline is stricter.
- Extended heartbeat format is selected by the separate `bUseDtlsV2` client
  capability, rather than LZO or the TLS version. `plugin/1800cb2b0.c` stores
  its sixth argument at object offset `0xa1`; `plugin/1800cbc60.c` transfers
  this flag to transport parameter offset `0x68`; `dtls_detail/18006df00.c`
  transfers it to protocol state offset `0x3e8`. The auth agent separately
  proved this capability is `s_funcset1 & 0x08`.
- The native successful send counter includes all application frames,
  including reliable-control retries; the receive counter increments for
  every application frame (`plugin/180074340.c:107`). Extended heartbeat
  sequence increments after a successful send (`plugin/180075a50.c:583`).

Outgoing extended heartbeat from `focused/1800718e0.c`:

| Outer-frame bytes | Value |
| --- | --- |
| 0 | 20 |
| 1:3 | BE16 hold seconds |
| 3:5 | BE16 interval seconds |
| 5:7 | BE16 ping sequence, initial0 |
| 7:15 | BE64 successful local sends plus this ping |
| 15:23 | BE64 local application-frame receive count |
| 23:31 | BE64 saved peer counter, native state offset0x88 |
| 31:39 | BE64 saved loss, native state offset0x98 |

For an incoming extended heartbeat, `plugin/180072300.c:338` reads the ping
sequence, skips the first eight-byte counter, sets saved loss from
`BE64(frame[15:23]) - localReceiveCount`, then saves
`BE64(frame[23:31])` as the peer counter. The local wire reproduction should
use these actual offsets; native counter log labels are inconsistent.
Static evidence does not establish that gateways reject zero counters.

## Confirmed matching layout

- Outer type2 and control header of eight bytes: version1, flag0=request or
  flag1=ACK, BE16 payload length, BE16 sequence, BE16 acknowledgement.
- Session authentication payload is TLV `[1,32]` followed by the exact32-byte
  application session ID; configuration request payload is `[2,0]`.
- Configuration TLVs use an eight-bit type and eight-bit payload length.
- Virtual address TLV0x81 contains exactly the IPv4 address and IPv4 mask
  (eight payload bytes), confirmed by `focused/180078180.c`.
- DNS TLV0x82 contains IPv4 slots. `sequence/18006d5d0.c` consumes nonzero
  addresses at offsets0,4,8 when payload length is at least4,8,12. The Go
  parser handles these layouts. Native ignores further slots; accepting
  additional complete slots in Go has no framing effect.
- TLV0x8d is `IPTUN_TLV_TYPE_CFG_OVER`, confirmed by
  `plugin/180069370.c:736`.
- Outer type1 carries the complete raw IPv4 datagram after one type byte.
- Native LZO compresses the entire application frame before passing it to
  DTLS (`focused/1800b6de0.c`).

The new Ghidra exports are `sequence/` and `tunnel-timer/`; both headless jobs
completed and closed the project. Logs are `ghidra-sequence.log` and
`ghidra-tunnel-timer.log`.

## Implementation follow-up

The root implementation subsequently addressed the listed differences:
`Session.ExtendedHeartbeat` propagates capability bit0x08 into tunnel options;
the first timer tick sends a heartbeat; every successful application send and
every application receive updates the counters; extended ping sequence advances
after a successful send. Incoming counters use the exact offsets above, including
unsigned subtraction. The timeout also checks whether frames arrived since the
preceding ping. Compressed and uncompressed datagram tests cover negotiation,
first ping, send ordering, receive totals and both saved counter slots.
