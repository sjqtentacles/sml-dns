(* dns.sml

   A pure RFC 1035 DNS message wire codec. No sockets, no FFI, no I/O -- just
   `Word8Vector.vector` in, `Word8Vector.vector` out -- so the same code runs
   identically under MLton and Poly/ML and is trivial to test.

   `decode` resolves message compression (RFC 1035 4.1.4): a label byte whose
   two high bits are set (>= 0xC0) is a 14-bit pointer to an earlier offset in
   the message; pointers may chain, so a jump counter guards against loops.
   `encode` always emits plain, uncompressed names (valid on the wire).

   16-bit fields are `int`; 32-bit fields (TTL, SOA timers) are `Word32.word`
   so an unsigned 32-bit value such as 0xFFFFFFFF survives on compilers whose
   default `Int` is only 31/32 bits wide (e.g. MLton). *)

structure Dns :> DNS =
struct
  datatype rdata =
      A     of int * int * int * int
    | AAAA  of int list
    | CNAME of string
    | NS    of string
    | MX    of { pref : int, exchange : string }
    | TXT   of string list
    | SOA   of { mname   : string, rname   : string,
                 serial  : Word32.word, refresh : Word32.word,
                 retry   : Word32.word, expire  : Word32.word,
                 minimum : Word32.word }
    | UNKNOWN of { rtype : int, data : Word8Vector.vector }

  type header =
    { id : int, qr : bool, opcode : int, aa : bool, tc : bool,
      rd : bool, ra : bool, z : int, rcode : int }
  type question = { qname : string, qtype : int, qclass : int }
  type rr = { name : string, class : int, ttl : Word32.word, rdata : rdata }
  type message =
    { header : header, questions : question list, answers : rr list,
      authority : rr list, additional : rr list }

  exception Dns of string

  (* ---- TYPE codes ---- *)
  fun rtypeOf (A _)               = 1
    | rtypeOf (NS _)              = 2
    | rtypeOf (CNAME _)           = 5
    | rtypeOf (SOA _)             = 6
    | rtypeOf (MX _)              = 15
    | rtypeOf (TXT _)             = 16
    | rtypeOf (AAAA _)            = 28
    | rtypeOf (UNKNOWN {rtype,...}) = rtype

  (* ======================= encoding ======================= *)

  fun w8 n = Word8.fromInt (n mod 256)
  fun u16 n = [w8 (n div 256), w8 n]                      (* big-endian 16-bit *)
  fun u32 (w : Word32.word) =                             (* big-endian 32-bit *)
    let
      fun b sh = Word8.fromInt
                   (Word32.toInt (Word32.andb (Word32.>> (w, sh), 0wxFF)))
    in [b 0w24, b 0w16, b 0w8, b 0w0] end

  fun strBytes s = List.map (fn c => w8 (Char.ord c)) (String.explode s)

  (* labels of a dotted name, dropping empty labels (handles a trailing dot) *)
  fun nameBytes s =
    let
      val labels = List.filter (fn l => l <> "")
                     (String.fields (fn c => c = #".") s)
      fun lab l =
        if size l > 63 then raise Dns "label exceeds 63 bytes"
        else w8 (size l) :: strBytes l
    in List.concat (List.map lab labels) @ [0w0] end

  fun encodeName s = Word8Vector.fromList (nameBytes s)

  (* a char-string: 1-byte length prefix + the bytes *)
  fun charStr s =
    if size s > 255 then raise Dns "TXT char-string exceeds 255 bytes"
    else w8 (size s) :: strBytes s

  fun rdataBytes rd =
    case rd of
        A (a, b, c, d) => List.map w8 [a, b, c, d]
      | AAAA gs =>
          if List.length gs <> 8 then raise Dns "AAAA needs 8 groups"
          else List.concat (List.map u16 gs)
      | CNAME n => nameBytes n
      | NS n => nameBytes n
      | MX {pref, exchange} => u16 pref @ nameBytes exchange
      | TXT ss => List.concat (List.map charStr ss)
      | SOA {mname, rname, serial, refresh, retry, expire, minimum} =>
          nameBytes mname @ nameBytes rname
          @ u32 serial @ u32 refresh @ u32 retry @ u32 expire @ u32 minimum
      | UNKNOWN {data, ...} => Word8Vector.foldr (op ::) [] data

  fun packFlags (h : header) =
    (if #qr h then 0x8000 else 0)
    + (#opcode h) * 0x0800
    + (if #aa h then 0x0400 else 0)
    + (if #tc h then 0x0200 else 0)
    + (if #rd h then 0x0100 else 0)
    + (if #ra h then 0x0080 else 0)
    + (#z h) * 0x0010
    + (#rcode h)

  fun questionBytes (q : question) =
    nameBytes (#qname q) @ u16 (#qtype q) @ u16 (#qclass q)

  fun rrBytes (r : rr) =
    let
      val rdb = rdataBytes (#rdata r)
    in
      nameBytes (#name r)
      @ u16 (rtypeOf (#rdata r))
      @ u16 (#class r)
      @ u32 (#ttl r)
      @ u16 (List.length rdb)
      @ rdb
    end

  fun encode (m : message) =
    let
      val h = #header m
      val hdr =
        u16 (#id h) @ u16 (packFlags h)
        @ u16 (List.length (#questions m))
        @ u16 (List.length (#answers m))
        @ u16 (List.length (#authority m))
        @ u16 (List.length (#additional m))
      val body =
        List.concat (List.map questionBytes (#questions m))
        @ List.concat (List.map rrBytes (#answers m))
        @ List.concat (List.map rrBytes (#authority m))
        @ List.concat (List.map rrBytes (#additional m))
    in
      Word8Vector.fromList (hdr @ body)
    end

  (* ======================= decoding ======================= *)

  fun byteOf v i =
    if i < 0 orelse i >= Word8Vector.length v then raise Dns "unexpected end of message"
    else Word8.toInt (Word8Vector.sub (v, i))

  (* read a (possibly compressed) name; returns the dotted name and the offset
     just past the name in the input stream (after the 0x00 or 2-byte pointer) *)
  fun readName (v, start) =
    let
      val byte = byteOf v
      fun label (pos, len) =
        String.implode (List.tabulate (len, fn k => Char.chr (byte (pos + k))))
      fun go (pos, acc, retOpt, jumps) =
        if jumps > 128 then raise Dns "name compression loop"
        else
          let val len = byte pos
          in
            if len = 0 then
              (String.concatWith "." (List.rev acc),
               case retOpt of SOME r => r | NONE => pos + 1)
            else if len >= 0xC0 then
              let
                val ptr = (len - 0xC0) * 256 + byte (pos + 1)
                val retOpt' = case retOpt of SOME _ => retOpt | NONE => SOME (pos + 2)
              in go (ptr, acc, retOpt', jumps + 1) end
            else if len <= 63 then
              go (pos + 1 + len, label (pos + 1, len) :: acc, retOpt, jumps)
            else raise Dns "illegal label length octet"
          end
    in go (start, [], NONE, 0) end

  fun decode v =
    let
      val n = Word8Vector.length v
      val byte = byteOf v
      fun u16at i = byte i * 256 + byte (i + 1)
      fun u32at i =
        let
          val a = Word32.fromInt (byte i)
          val b = Word32.fromInt (byte (i + 1))
          val c = Word32.fromInt (byte (i + 2))
          val d = Word32.fromInt (byte (i + 3))
        in
          Word32.orb (Word32.<< (a, 0w24),
            Word32.orb (Word32.<< (b, 0w16),
              Word32.orb (Word32.<< (c, 0w8), d)))
        end

      val () = if n < 12 then raise Dns "message shorter than 12-byte header" else ()
      val id = u16at 0
      val flags = u16at 2
      fun bit m = (flags div m) mod 2 = 1
      val header =
        { id = id,
          qr = bit 0x8000,
          opcode = (flags div 0x0800) mod 16,
          aa = bit 0x0400,
          tc = bit 0x0200,
          rd = bit 0x0100,
          ra = bit 0x0080,
          z = (flags div 0x0010) mod 8,
          rcode = flags mod 16 }
      val qdcount = u16at 4
      val ancount = u16at 6
      val nscount = u16at 8
      val arcount = u16at 10

      fun parseQuestion pos =
        let
          val (name, p) = readName (v, pos)
          val qtype = u16at p
          val qclass = u16at (p + 2)
        in ({ qname = name, qtype = qtype, qclass = qclass }, p + 4) end

      fun parseTxt (pos, stop) =
        if pos >= stop then []
        else
          let
            val l = byte pos
            val s = String.implode
                      (List.tabulate (l, fn k => Char.chr (byte (pos + 1 + k))))
          in s :: parseTxt (pos + 1 + l, stop) end

      fun parseRdata (rtype, off, len) =
        case rtype of
            1  => if len <> 4 then raise Dns "bad A rdlength"
                  else A (byte off, byte (off + 1), byte (off + 2), byte (off + 3))
          | 28 => if len <> 16 then raise Dns "bad AAAA rdlength"
                  else AAAA (List.tabulate (8, fn k => u16at (off + 2 * k)))
          | 5  => CNAME (#1 (readName (v, off)))
          | 2  => NS (#1 (readName (v, off)))
          | 15 => MX { pref = u16at off, exchange = #1 (readName (v, off + 2)) }
          | 16 => TXT (parseTxt (off, off + len))
          | 6  =>
              let
                val (mname, p1) = readName (v, off)
                val (rname, p2) = readName (v, p1)
              in
                SOA { mname = mname, rname = rname,
                      serial = u32at p2, refresh = u32at (p2 + 4),
                      retry = u32at (p2 + 8), expire = u32at (p2 + 12),
                      minimum = u32at (p2 + 16) }
              end
          | other =>
              UNKNOWN { rtype = other,
                        data = Word8VectorSlice.vector
                                 (Word8VectorSlice.slice (v, off, SOME len)) }

      fun parseRR pos =
        let
          val (name, p) = readName (v, pos)
          val rtype = u16at p
          val class = u16at (p + 2)
          val ttl = u32at (p + 4)
          val rdlen = u16at (p + 8)
          val rdStart = p + 10
          val rdEnd = rdStart + rdlen
          val () = if rdEnd > n then raise Dns "rdata extends past message" else ()
          val rdata = parseRdata (rtype, rdStart, rdlen)
        in ({ name = name, class = class, ttl = ttl, rdata = rdata }, rdEnd) end

      fun parseQuestions (0, pos, acc) = (List.rev acc, pos)
        | parseQuestions (k, pos, acc) =
            let val (q, pos') = parseQuestion pos
            in parseQuestions (k - 1, pos', q :: acc) end

      fun parseRRs (0, pos, acc) = (List.rev acc, pos)
        | parseRRs (k, pos, acc) =
            let val (r, pos') = parseRR pos
            in parseRRs (k - 1, pos', r :: acc) end

      val (questions, p1) = parseQuestions (qdcount, 12, [])
      val (answers, p2) = parseRRs (ancount, p1, [])
      val (authority, p3) = parseRRs (nscount, p2, [])
      val (additional, _) = parseRRs (arcount, p3, [])
    in
      { header = header, questions = questions, answers = answers,
        authority = authority, additional = additional }
    end
end
