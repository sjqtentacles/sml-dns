(* demo.sml

   A tiny tour of `Dns`, all in pure SML -- no sockets:
     1. build a standard recursive A-query for "example.com" and show its
        wire bytes (this is exactly what a client would send over UDP/53);
     2. read a REAL captured response packet (test/fixtures) and pretty-print
        every parsed field, including the answer names recovered through
        0xC0 compression pointers.

   Build and run with `make example`. *)

structure D = Dns

fun line s = print (s ^ "\n")

(* raw bytes -> spaced lowercase hex, for legible wire dumps *)
fun toHex v =
  String.concatWith " "
    (List.map
       (fn w =>
          let val n = Word8.toInt w
              fun d k = String.sub ("0123456789abcdef", k)
          in String.implode [d (n div 16), d (n mod 16)] end)
       (Word8Vector.foldr (op ::) [] v))

fun readFileBytes path =
  let val s = BinIO.openIn path
      val v = BinIO.inputAll s
  in BinIO.closeIn s; v end

fun rdataStr (D.A (a,b,c,d)) =
      "A     " ^ String.concatWith "." (List.map Int.toString [a,b,c,d])
  | rdataStr (D.AAAA gs) =
      "AAAA  " ^ String.concatWith ":" (List.map Int.toString gs)
  | rdataStr (D.CNAME s) = "CNAME " ^ s
  | rdataStr (D.NS s)    = "NS    " ^ s
  | rdataStr (D.MX {pref, exchange}) =
      "MX    " ^ Int.toString pref ^ " " ^ exchange
  | rdataStr (D.TXT ss)  = "TXT   [" ^ String.concatWith ", " ss ^ "]"
  | rdataStr (D.SOA {mname, rname, serial, ...}) =
      "SOA   " ^ mname ^ " " ^ rname ^ " serial=" ^ Word32.fmt StringCvt.DEC serial
  | rdataStr (D.UNKNOWN {rtype, ...}) = "TYPE" ^ Int.toString rtype

fun showRR (r : D.rr) =
  line ("    " ^ #name r ^ "  ttl=" ^ Word32.fmt StringCvt.DEC (#ttl r)
        ^ "  " ^ rdataStr (#rdata r))

(* ---- 1. build a query --------------------------------------------------- *)
val () = line "=== sml-dns: build an A-query, parse a captured response (pure, no sockets) ==="
val () = line ""

val query : D.message =
  { header = { id = 0x1234, qr = false, opcode = 0, aa = false, tc = false,
               rd = true, ra = false, z = 0, rcode = 0 },
    questions = [ { qname = "example.com", qtype = 1, qclass = 1 } ],
    answers = [], authority = [], additional = [] }

val qbytes = D.encode query
val () = line "1) Outgoing query for example.com (A, RD set):"
val () = line ("   " ^ toHex qbytes)
val () = line ("   (" ^ Int.toString (Word8Vector.length qbytes) ^ " bytes)")
val () = line ""

(* ---- 2. parse the captured response ------------------------------------- *)
val raw = readFileBytes "test/fixtures/example-com-response.bin"
val () = line "2) Captured response packet (61 bytes from a real resolver):"
val () = line ("   " ^ toHex raw)
val () = line ""

val msg = D.decode raw
val h = #header msg

val () = line "   Parsed message:"
val () = line ("   header: id=0x" ^ Int.fmt StringCvt.HEX (#id h)
               ^ " qr=" ^ Bool.toString (#qr h)
               ^ " opcode=" ^ Int.toString (#opcode h)
               ^ " aa=" ^ Bool.toString (#aa h)
               ^ " rd=" ^ Bool.toString (#rd h)
               ^ " ra=" ^ Bool.toString (#ra h)
               ^ " rcode=" ^ Int.toString (#rcode h))

val () = line ("   question section (" ^ Int.toString (List.length (#questions msg)) ^ "):")
val () = List.app
  (fn (q : D.question) =>
     line ("    " ^ #qname q ^ "  type=" ^ Int.toString (#qtype q)
           ^ "  class=" ^ Int.toString (#qclass q)))
  (#questions msg)

val () = line ("   answer section (" ^ Int.toString (List.length (#answers msg))
               ^ ", names via 0xC0 compression):")
val () = List.app showRR (#answers msg)

val () = line ""
val () = line "OK -- built a query and parsed a real DNS response with name compression."
