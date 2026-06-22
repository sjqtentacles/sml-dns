(* test.sml

   Strict-TDD suite for `Dns`, the RFC 1035 message wire codec. DNS is a byte
   protocol, so values are checked with exact structural / byte equality (no
   epsilon): the same bytes must come out of both MLton and Poly/ML.

   Coverage:
     - header flags/opcode/rcode: golden flag words + field round-trips;
     - QNAME label encoding (length-prefixed labels + root) and
       compression-pointer resolution (single + chained 0xC0 pointers);
     - round-trip of a hand-built query message;
     - decode of a REAL captured DNS response packet committed under
       test/fixtures, asserting every parsed field incl. names recovered
       through compression pointers;
     - encode -> decode round-trip for every `rdata` variant, including a
       32-bit SOA serial with the high bit set (proves Word32 handling). *)

structure Tests =
struct
  open Support
  structure D = Dns

  (* ---- header helpers ---- *)
  fun flagsOf h = rd16 (D.encode (emptyMsg h), 2)
  fun idOf h = rd16 (D.encode (emptyMsg h), 0)

  (* sample rdata, one per variant (plus the 32-bit edge) *)
  val rdA   = D.A (192, 0, 2, 1)
  val rdAAAA = D.AAAA [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]
  val rdCNAME = D.CNAME "alias.example.com"
  val rdNS  = D.NS "ns1.example.com"
  val rdMX  = D.MX { pref = 10, exchange = "mail.example.com" }
  val rdTXT = D.TXT ["v=spf1 -all", "hello world"]
  val rdSOA = D.SOA { mname = "ns.example.com", rname = "hostmaster.example.com",
                      serial = 0wxFFFFFFFE, refresh = 0w7200, retry = 0w3600,
                      expire = 0w1209600, minimum = 0w3600 }
  val rdUNK = D.UNKNOWN { rtype = 99, data = bytes [0xDE, 0xAD, 0xBE, 0xEF] }

  fun mkAnswer rd : D.rr =
    { name = "example.com", class = 1, ttl = 0wx7FABCDEF, rdata = rd }

  fun answerMsg rd : D.message =
    { header = { id = 1, qr = true, opcode = 0, aa = false, tc = false,
                 rd = false, ra = false, z = 0, rcode = 0 },
      questions = [], answers = [mkAnswer rd],
      authority = [], additional = [] }

  fun roundTripRdata (label, rd) =
    let
      val msg = answerMsg rd
      val dec = D.decode (D.encode msg)
      val ans = #answers dec
    in
      case ans of
          [a] => (checkRdata (label ^ ": rdata") (rd, #rdata a);
                  Harness.checkString (label ^ ": name") ("example.com", #name a);
                  Harness.check (label ^ ": ttl") (#ttl a = 0wx7FABCDEF);
                  Harness.checkInt (label ^ ": rtypeOf preserved")
                    (D.rtypeOf rd, D.rtypeOf (#rdata a)))
        | _ => Harness.check (label ^ ": exactly one answer") false
    end

  fun runAll () =
    let
      (* ===== header flags / opcode / rcode ===== *)
      val () = Harness.section "header flag word goldens"
      val hQuery : D.header =
        { id = 0x1234, qr = false, opcode = 0, aa = false, tc = false,
          rd = true, ra = false, z = 0, rcode = 0 }
      val () = Harness.checkInt "standard recursive query flags=0x0100"
                 (0x0100, flagsOf hQuery)
      val hResp : D.header =
        { id = 0x1234, qr = true, opcode = 0, aa = false, tc = false,
          rd = true, ra = true, z = 0, rcode = 0 }
      val () = Harness.checkInt "typical response flags=0x8180"
                 (0x8180, flagsOf hResp)
      (* QR=1, opcode=2 (STATUS), AA, TC, RD, RA=0, rcode=3 (NXDOMAIN) *)
      val hMixed : D.header =
        { id = 0x1234, qr = true, opcode = 2, aa = true, tc = true,
          rd = true, ra = false, z = 0, rcode = 3 }
      val () = Harness.checkInt "mixed flags=0x9703" (0x9703, flagsOf hMixed)
      val () = Harness.checkInt "id preserved in bytes 0..1" (0x1234, idOf hMixed)

      val () = Harness.section "header field round-trips (decode . encode)"
      val () =
        let
          fun rt (label, h : D.header) =
            let val h' = #header (D.decode (D.encode (emptyMsg h)))
            in
              Harness.checkInt (label ^ ": id") (#id h, #id h');
              Harness.checkBool (label ^ ": qr") (#qr h, #qr h');
              Harness.checkInt (label ^ ": opcode") (#opcode h, #opcode h');
              Harness.checkBool (label ^ ": aa") (#aa h, #aa h');
              Harness.checkBool (label ^ ": tc") (#tc h, #tc h');
              Harness.checkBool (label ^ ": rd") (#rd h, #rd h');
              Harness.checkBool (label ^ ": ra") (#ra h, #ra h');
              Harness.checkInt (label ^ ": z") (#z h, #z h');
              Harness.checkInt (label ^ ": rcode") (#rcode h, #rcode h')
            end
        in
          rt ("query", hQuery);
          rt ("response", hResp);
          rt ("mixed", hMixed);
          (* boundary: max opcode / rcode / z *)
          rt ("max-fields",
              { id = 0xFFFF, qr = true, opcode = 15, aa = true, tc = true,
                rd = true, ra = true, z = 7, rcode = 15 })
        end

      (* ===== QNAME encoding ===== *)
      val () = Harness.section "QNAME label encoding"
      val () = checkBytes "encode \"example.com\""
                 (bytes [7,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,
                         3,0x63,0x6f,0x6d,0],
                  D.encodeName "example.com")
      val () = checkBytes "encode root \"\" = [0]" (bytes [0], D.encodeName "")
      val () = checkBytes "trailing dot ignored"
                 (D.encodeName "example.com", D.encodeName "example.com.")

      (* ===== compression-pointer resolution ===== *)
      val () = Harness.section "name compression (0xC0 pointers) on decode"
      (* layout: offset 0 holds "example.com\0" (13 bytes), offset 13 holds a
         pointer back to offset 0. *)
      val comp = bytes [7,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,
                        3,0x63,0x6f,0x6d,0,            (* 0..12 *)
                        0xC0, 0x00]                    (* 13..14 : -> offset 0 *)
      val () =
        let val (n, next) = D.readName (comp, 0)
        in Harness.checkString "plain name" ("example.com", n);
           Harness.checkInt "plain name end offset" (13, next)
        end
      val () =
        let val (n, next) = D.readName (comp, 13)
        in Harness.checkString "pointer resolves to target" ("example.com", n);
           Harness.checkInt "pointer end offset (after 2 bytes)" (15, next)
        end
      (* chained: offset 0 = "com\0"; offset 5 = label "example" + ptr->0 *)
      val chain = bytes [3,0x63,0x6f,0x6d,0,           (* 0..4 : "com" *)
                         7,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65, (* 5..12: "example" *)
                         0xC0, 0x00]                   (* 13..14: -> "com" *)
      val () =
        let val (n, next) = D.readName (chain, 5)
        in Harness.checkString "label + pointer -> joined" ("example.com", n);
           Harness.checkInt "chained end offset" (15, next)
        end

      (* ===== constructed query round-trip ===== *)
      val () = Harness.section "constructed query round-trip"
      val query : D.message =
        { header = { id = 0xABCD, qr = false, opcode = 0, aa = false,
                     tc = false, rd = true, ra = false, z = 0, rcode = 0 },
          questions = [{ qname = "www.example.com", qtype = 1, qclass = 1 }],
          answers = [], authority = [], additional = [] }
      val () =
        let val q' = D.decode (D.encode query)
        in
          Harness.checkInt "query id" (0xABCD, #id (#header q'));
          Harness.checkBool "query qr=false" (false, #qr (#header q'));
          Harness.checkBool "query rd=true" (true, #rd (#header q'));
          Harness.checkInt "one question" (1, List.length (#questions q'));
          case #questions q' of
              [qq] => (Harness.checkString "qname" ("www.example.com", #qname qq);
                       Harness.checkInt "qtype A" (1, #qtype qq);
                       Harness.checkInt "qclass IN" (1, #qclass qq))
            | _ => Harness.check "exactly one question" false;
          Harness.checkInt "no answers" (0, List.length (#answers q'))
        end

      (* ===== REAL captured packet fixture ===== *)
      val () = Harness.section "decode REAL captured response (example.com A)"
      val () =
        let
          val raw = readFileBytes "test/fixtures/example-com-response.bin"
          val m = D.decode raw
          val h = #header m
        in
          Harness.checkInt "fixture id" (0x1234, #id h);
          Harness.checkBool "fixture qr (response)" (true, #qr h);
          Harness.checkInt "fixture opcode QUERY" (0, #opcode h);
          Harness.checkBool "fixture rd" (true, #rd h);
          Harness.checkBool "fixture ra" (true, #ra h);
          Harness.checkInt "fixture rcode NOERROR" (0, #rcode h);
          Harness.checkInt "fixture 1 question" (1, List.length (#questions m));
          Harness.checkInt "fixture 2 answers" (2, List.length (#answers m));
          Harness.checkInt "fixture 0 authority" (0, List.length (#authority m));
          Harness.checkInt "fixture 0 additional" (0, List.length (#additional m));
          (case #questions m of
               [q] => (Harness.checkString "fixture qname" ("example.com", #qname q);
                       Harness.checkInt "fixture qtype A" (1, #qtype q);
                       Harness.checkInt "fixture qclass IN" (1, #qclass q))
             | _ => Harness.check "fixture one question" false);
          (case #answers m of
               [a1, a2] =>
                 (Harness.checkString "answer1 name (via compression)"
                    ("example.com", #name a1);
                  Harness.check "answer1 ttl=300" (#ttl a1 = 0w300);
                  checkRdata "answer1 rdata A 104.20.23.154"
                    (D.A (104, 20, 23, 154), #rdata a1);
                  Harness.checkString "answer2 name (via compression)"
                    ("example.com", #name a2);
                  checkRdata "answer2 rdata A 172.66.147.243"
                    (D.A (172, 66, 147, 243), #rdata a2))
             | _ => Harness.check "fixture two answers" false)
        end

      (* ===== per-RR encode -> decode round-trips ===== *)
      val () = Harness.section "encode -> decode round-trip per RR type"
      val () = roundTripRdata ("A", rdA)
      val () = roundTripRdata ("AAAA", rdAAAA)
      val () = roundTripRdata ("CNAME", rdCNAME)
      val () = roundTripRdata ("NS", rdNS)
      val () = roundTripRdata ("MX", rdMX)
      val () = roundTripRdata ("TXT", rdTXT)
      val () = roundTripRdata ("SOA (32-bit serial)", rdSOA)
      val () = roundTripRdata ("UNKNOWN", rdUNK)

      (* a whole multi-section message round-trips intact *)
      val () = Harness.section "full multi-section message round-trip"
      val () =
        let
          val msg : D.message =
            { header = { id = 0x4242, qr = true, opcode = 0, aa = true,
                         tc = false, rd = true, ra = true, z = 0, rcode = 0 },
              questions = [{ qname = "example.com", qtype = 15, qclass = 1 }],
              answers = [ { name = "example.com", class = 1, ttl = 0w300, rdata = rdMX },
                          { name = "example.com", class = 1, ttl = 0w3600, rdata = rdTXT } ],
              authority = [ { name = "example.com", class = 1, ttl = 0w86400, rdata = rdSOA } ],
              additional = [ { name = "ns1.example.com", class = 1, ttl = 0w300, rdata = rdA } ] }
          val m' = D.decode (D.encode msg)
        in
          Harness.checkInt "sections: questions" (1, List.length (#questions m'));
          Harness.checkInt "sections: answers" (2, List.length (#answers m'));
          Harness.checkInt "sections: authority" (1, List.length (#authority m'));
          Harness.checkInt "sections: additional" (1, List.length (#additional m'));
          Harness.check "answers match"
            (ListPair.allEq rrEq (#answers msg, #answers m'));
          Harness.check "authority matches"
            (ListPair.allEq rrEq (#authority msg, #authority m'));
          Harness.check "additional matches"
            (ListPair.allEq rrEq (#additional msg, #additional m'))
        end

      (* ===== malformed input is rejected ===== *)
      val () = Harness.section "malformed / truncated input raises Dns"
      val () = Harness.checkRaises "empty input" (fn () => D.decode (bytes []))
      val () = Harness.checkRaises "header too short"
                 (fn () => D.decode (bytes [0,1,2,3,4]))
      val () = Harness.checkRaises "truncated question"
                 (fn () => D.decode (bytes [0,1, 0,0, 0,1, 0,0, 0,0, 0,0, 3,0x63]))
    in
      ()
    end

  fun run () = (Harness.reset (); runAll (); Harness.run ())
end
