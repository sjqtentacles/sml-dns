# sml-dns

[![CI](https://github.com/sjqtentacles/sml-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-dns/actions/workflows/ci.yml)

A pure Standard ML codec for **DNS messages** on the wire ([RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)).
`decode`/`encode` move bytes between a structured `message` and its on-wire
`Word8Vector.vector` form — **no sockets, no FFI, no I/O** — so the codec is
trivially testable and runs byte-identically under
[MLton](http://mlton.org/) and [Poly/ML](https://www.polyml.org/).
Basis-library only, no dependencies (Layout A).

The decoder resolves **DNS name compression** (RFC 1035 §4.1.4): an answer
name encoded as a `0xC0` pointer to an earlier offset is followed (with loop
protection) and returned as the full dotted name. The encoder emits plain,
uncompressed names, which are always valid on the wire.

## Status

- 117 assertions, green on MLton and Poly/ML, both printing `117 passed, 0 failed`.
- Basis-library only; deterministic across compilers.
- Includes a **real captured response packet** (`test/fixtures/example-com-response.bin`,
  an `example.com` A-record reply with two compressed names) decoded in the suite.

## Install

With [`smlpkg`](https://github.com/diku-dk/smlpkg):

```
smlpkg add github.com/sjqtentacles/sml-dns
smlpkg sync
```

Include the MLB from your own:

```
local
  $(SML_LIB)/basis/basis.mlb
  lib/github.com/sjqtentacles/sml-dns/src/dns.mlb (via smlpkg)
in
  ...
end
```

This brings `structure Dns` into scope.

## Quick start

```sml
(* Build a standard recursive A-query for example.com. *)
val query : Dns.message =
  { header = { id = 0x1234, qr = false, opcode = 0, aa = false, tc = false,
               rd = true, ra = false, z = 0, rcode = 0 },
    questions = [ { qname = "example.com", qtype = 1, qclass = 1 } ],
    answers = [], authority = [], additional = [] }

val wire = Dns.encode query    (* Word8Vector.vector ready for UDP/53 *)

(* Parse a response datagram (names with 0xC0 pointers are resolved). *)
val msg = Dns.decode responseBytes
val firstAnswer = hd (#answers msg)
(* #name firstAnswer = "example.com", #rdata firstAnswer = Dns.A (104,20,23,154) *)
```

## API (`signature DNS`)

```sml
datatype rdata =
    A     of int * int * int * int                 (* IPv4: 4 octets        *)
  | AAAA  of int list                               (* IPv6: 8 16-bit groups *)
  | CNAME of string
  | NS    of string
  | MX    of { pref : int, exchange : string }
  | TXT   of string list                            (* char-strings          *)
  | SOA   of { mname : string, rname : string,
               serial : Word32.word, refresh : Word32.word,
               retry : Word32.word, expire : Word32.word,
               minimum : Word32.word }
  | UNKNOWN of { rtype : int, data : Word8Vector.vector }  (* any other type *)

type header =
  { id : int, qr : bool, opcode : int, aa : bool, tc : bool,
    rd : bool, ra : bool, z : int, rcode : int }
type question = { qname : string, qtype : int, qclass : int }
type rr = { name : string, class : int, ttl : Word32.word, rdata : rdata }
type message =
  { header : header, questions : question list, answers : rr list,
    authority : rr list, additional : rr list }

exception Dns of string

val rtypeOf    : rdata -> int                        (* wire TYPE code        *)
val encodeName : string -> Word8Vector.vector        (* length-prefixed labels *)
val readName   : Word8Vector.vector * int -> string * int  (* resolve compression *)
val decode     : Word8Vector.vector -> message       (* raises Dns if malformed *)
val encode     : message -> Word8Vector.vector
```

### Semantics

- **Numeric widths.** 16-bit fields (`id`, counts, `qtype`/`qclass`, `pref`,
  IPv6 groups, …) are `int`. The 32-bit fields — record `ttl` and the five SOA
  timers — are `Word32.word`, because the basis default `Int` may be only 31
  bits and MLton's is 32-bit, so an unsigned TTL like `0xFFFFFFFF` would not
  otherwise round-trip.
- **Names.** `encode` emits uncompressed names terminated by the root label
  (`0x00`); a trailing dot is ignored. `decode` resolves `0xC0` compression
  pointers — including chained pointers and pointers inside RDATA (CNAME, NS,
  MX, SOA) — and guards against pointer loops.
- **Sections.** Header counts (QD/AN/NS/AR) are derived from the four record
  lists on `encode` and drive parsing on `decode`; they are not stored
  redundantly.
- **TYPE coverage.** A, AAAA, CNAME, NS, MX, TXT, and SOA are modelled
  structurally; every other record type round-trips byte-exact via `UNKNOWN`.
- `decode` raises `Dns msg` on truncated or malformed input.

## Example

`make example` builds an A-query and parses the committed real-world response
entirely in memory:

```
=== sml-dns: build an A-query, parse a captured response (pure, no sockets) ===

1) Outgoing query for example.com (A, RD set):
   12 34 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
   (29 bytes)

2) Captured response packet (61 bytes from a real resolver):
   12 34 81 80 00 01 00 02 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 01 2c 00 04 68 14 17 9a c0 0c 00 01 00 01 00 00 01 2c 00 04 ac 42 93 f3

   Parsed message:
   header: id=0x1234 qr=true opcode=0 aa=false rd=true ra=true rcode=0
   question section (1):
    example.com  type=1  class=1
   answer section (2, names via 0xC0 compression):
    example.com  ttl=300  A     104.20.23.154
    example.com  ttl=300  A     172.66.147.243

OK -- built a query and parsed a real DNS response with name compression.
```

The two answer names are stored on the wire as the pointer `c0 0c` (→ offset
12, the question's QNAME) and resolved by `decode` to `example.com`.

## Build & test

```
make test        # MLton
make test-poly   # Poly/ML
make all-tests   # both
make example     # build + run examples/demo.sml
make clean
```

Both compilers run the same strict-TDD suite (`test/test.sml`), whose oracle is
RFC 1035 written out as literal bytes. Highlights:

- **Header flags:** golden flag words (`0x0100` query, `0x8180` response,
  `0x9703` mixed) and field-by-field round-trips through opcode/rcode/Z extremes.
- **QNAME:** label encoding (`example.com` → `07 'example' 03 'com' 00`, root → `00`).
- **Compression:** single and chained `0xC0` pointer resolution via `readName`.
- **Round-trips:** a constructed query and an `encode → decode` round-trip for
  every `rdata` variant (incl. a 32-bit SOA serial with the high bit set).
- **Real packet:** decode the captured `example.com` response and assert every
  field, with both compressed answer names recovered.
- **Robustness:** truncated/malformed inputs raise `Dns`.

## License

MIT — see [LICENSE](LICENSE).
