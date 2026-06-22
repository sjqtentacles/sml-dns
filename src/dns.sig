(* dns.sig

   A pure DNS message wire codec (RFC 1035). `decode`/`encode` move bytes
   between a structured `message` and its on-wire `Word8Vector.vector` form --
   no sockets, no FFI, no I/O -- so the codec is trivially testable and runs
   byte-identically under MLton and Poly/ML.

   Layout follows RFC 1035 section 4: a 12-byte header, then the question,
   answer, authority, and additional sections.

   Names. A domain name on the wire is a sequence of length-prefixed labels
   terminated by a zero-length label, e.g. "example.com" is
   `07 e x a m p l e 03 c o m 00`. Responses commonly use *message
   compression* (RFC 1035 section 4.1.4): a label whose two high bits are set
   (`0xC0`) is a 14-bit pointer to an earlier offset in the message. `decode`
   resolves these pointers (with loop protection); `encode` emits plain,
   uncompressed names (always valid on the wire).

   Numeric widths. 16-bit fields (id, counts, type, class, preference, ...)
   are plain `int`. 32-bit fields (TTL and the SOA timers) are `Word32.word`
   because the basis default `Int` is only guaranteed to be 31 bits wide and
   MLton's is 32-bit -- an unsigned 32-bit TTL such as `0xFFFFFFFF` does not
   fit in an `Int31`/`Int32`. Using `Word32.word` keeps the codec correct and
   portable across compilers. *)

signature DNS =
sig
  (* The RDATA of a resource record, by type. The constructor determines the
     wire TYPE code (see `rtypeOf`). `UNKNOWN` preserves any other record's
     raw RDATA bytes verbatim so arbitrary messages round-trip. *)
  datatype rdata =
      A     of int * int * int * int                 (* IPv4: 4 octets        *)
    | AAAA  of int list                               (* IPv6: 8 16-bit groups *)
    | CNAME of string                                 (* canonical name        *)
    | NS    of string                                 (* name server           *)
    | MX    of { pref : int, exchange : string }      (* mail exchange         *)
    | TXT   of string list                            (* char-string list      *)
    | SOA   of { mname   : string, rname   : string,
                 serial  : Word32.word, refresh : Word32.word,
                 retry   : Word32.word, expire  : Word32.word,
                 minimum : Word32.word }
    | UNKNOWN of { rtype : int, data : Word8Vector.vector }

  (* The 16-bit flags word, RFC 1035 section 4.1.1, unpacked. `opcode` is the
     4-bit OPCODE, `z` the 3-bit reserved field, `rcode` the 4-bit RCODE. *)
  type header =
    { id     : int,
      qr     : bool,        (* QR : false = query, true = response *)
      opcode : int,         (* 4-bit OPCODE  *)
      aa     : bool,        (* authoritative answer *)
      tc     : bool,        (* truncation    *)
      rd     : bool,        (* recursion desired   *)
      ra     : bool,        (* recursion available *)
      z      : int,         (* 3-bit reserved (Z)  *)
      rcode  : int }        (* 4-bit RCODE   *)

  type question =
    { qname : string, qtype : int, qclass : int }

  (* A resource record. The wire TYPE is implied by `rdata` (so it is never
     stored redundantly); CLASS is usually 1 (IN). *)
  type rr =
    { name : string, class : int, ttl : Word32.word, rdata : rdata }

  type message =
    { header     : header,
      questions  : question list,
      answers    : rr list,
      authority  : rr list,
      additional : rr list }

  (* Raised by `decode` on a truncated or malformed message. *)
  exception Dns of string

  (* The wire TYPE code for an `rdata` constructor (A=1, NS=2, CNAME=5,
     SOA=6, MX=15, TXT=16, AAAA=28; `UNKNOWN` carries its own). *)
  val rtypeOf : rdata -> int

  (* Encode a domain name to its length-prefixed label form (uncompressed),
     terminated by the zero-length root label. A trailing dot is ignored. *)
  val encodeName : string -> Word8Vector.vector

  (* Read a (possibly compressed) name starting at byte offset `i` of the
     whole message `v`; returns the dotted name and the offset of the first
     byte *after the name in the input stream* (following the 0x00 or the
     2-byte pointer, never the pointer target). *)
  val readName : Word8Vector.vector * int -> string * int

  (* Parse one complete DNS message from a datagram. Raises `Dns` if the
     bytes are truncated or malformed. *)
  val decode : Word8Vector.vector -> message

  (* Serialize a message to its on-wire bytes. Section counts are taken from
     the four record lists; names are emitted uncompressed. *)
  val encode : message -> Word8Vector.vector
end
