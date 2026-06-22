(* support.sml -- shared helpers for the sml-dns test suite. *)

structure Support =
struct
  structure D = Dns

  (* build a Word8Vector from a list of ints (0..255) *)
  fun bytes (ns : int list) = Word8Vector.fromList (List.map Word8.fromInt ns)

  (* raw bytes -> lowercase hex, for failure messages / golden checks *)
  fun toHex v =
    String.concat
      (List.map
         (fn w =>
            let val n = Word8.toInt w
                fun d k = String.sub ("0123456789abcdef", k)
            in String.implode [d (n div 16), d (n mod 16)] end)
         (Word8Vector.foldr (op ::) [] v))

  fun checkBytes name (expected, actual) =
    Harness.checkString name (toHex expected, toHex actual)

  (* big-endian readers over a Word8Vector *)
  fun rd8 (v, i) = Word8.toInt (Word8Vector.sub (v, i))
  fun rd16 (v, i) = rd8 (v, i) * 256 + rd8 (v, i + 1)

  (* read a whole file as raw bytes *)
  fun readFileBytes path =
    let
      val s = BinIO.openIn path
      val v = BinIO.inputAll s
    in
      BinIO.closeIn s; v
    end

  (* structural equality on rdata (Word8Vector is not an SML eqtype) *)
  fun rdataEq (D.A a, D.A b) = a = b
    | rdataEq (D.AAAA a, D.AAAA b) = a = b
    | rdataEq (D.CNAME a, D.CNAME b) = a = b
    | rdataEq (D.NS a, D.NS b) = a = b
    | rdataEq (D.MX a, D.MX b) = (#pref a = #pref b andalso #exchange a = #exchange b)
    | rdataEq (D.TXT a, D.TXT b) = a = b
    | rdataEq (D.SOA a, D.SOA b) =
        #mname a = #mname b andalso #rname a = #rname b
        andalso #serial a = #serial b andalso #refresh a = #refresh b
        andalso #retry a = #retry b andalso #expire a = #expire b
        andalso #minimum a = #minimum b
    | rdataEq (D.UNKNOWN a, D.UNKNOWN b) =
        #rtype a = #rtype b andalso toHex (#data a) = toHex (#data b)
    | rdataEq _ = false

  fun rdataStr (D.A (a,b,c,d)) =
        "A " ^ String.concatWith "." (List.map Int.toString [a,b,c,d])
    | rdataStr (D.AAAA gs) = "AAAA " ^ String.concatWith ":" (List.map Int.toString gs)
    | rdataStr (D.CNAME s) = "CNAME " ^ s
    | rdataStr (D.NS s) = "NS " ^ s
    | rdataStr (D.MX {pref, exchange}) = "MX " ^ Int.toString pref ^ " " ^ exchange
    | rdataStr (D.TXT ss) = "TXT [" ^ String.concatWith "," ss ^ "]"
    | rdataStr (D.SOA {mname, rname, ...}) = "SOA " ^ mname ^ " " ^ rname
    | rdataStr (D.UNKNOWN {rtype, data}) =
        "UNKNOWN(" ^ Int.toString rtype ^ ")=" ^ toHex data

  fun checkRdata name (expected, actual) =
    if rdataEq (expected, actual) then Harness.check name true
    else (Harness.check name false; print ("       expected " ^ rdataStr expected
            ^ " got " ^ rdataStr actual ^ "\n"))

  (* equality on a resource record *)
  fun rrEq (a : D.rr, b : D.rr) =
    #name a = #name b andalso #class a = #class b
    andalso #ttl a = #ttl b andalso rdataEq (#rdata a, #rdata b)

  (* a minimal header with all flags clear, used as a template *)
  val baseHeader : D.header =
    { id = 0, qr = false, opcode = 0, aa = false, tc = false,
      rd = false, ra = false, z = 0, rcode = 0 }

  fun emptyMsg (h : D.header) : D.message =
    { header = h, questions = [], answers = [], authority = [], additional = [] }
end
