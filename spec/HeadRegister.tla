--------------------------- MODULE HeadRegister ---------------------------
(***************************************************************************)
(* Witness-quorum head register (crates/edge/src/quorum).                  *)
(*                                                                         *)
(* One owner repeatedly crashes and restarts as a new incarnation with a   *)
(* fresh ballot; its log may be lost, so an incarnation knows nothing but  *)
(* what a quorum of witnesses tells it. A claim <<ballot, seq>> names the  *)
(* head an incarnation wants committed (a head is determined by ballot and *)
(* seq: a different incarnation signs a different head for the same seq).  *)
(* A head leaves the process only when a claim for it is CERTIFIED: a      *)
(* quorum of distinct witnesses issued receipts.                           *)
(*                                                                         *)
(* Witnesses: correct ones persist {promised, accepted} before answering;  *)
(* Byzantine ones answer anything the owner could have signed (they may    *)
(* hide an accepted claim, or issue receipts for everything). Claims are   *)
(* unforgeable (signed by the owner), so only proposed claims exist.       *)
(* Messages are delayed, reordered and duplicated: any proposed claim can  *)
(* be delivered to any witness at any time, by an older incarnation too.   *)
(*                                                                         *)
(* Safety: no two different heads are ever certified for the same seq,     *)
(* i.e. an honest owner never produces conclusive self-evidence, however   *)
(* it crashes. Recovery needs a quorum of promises; fewer is the blocked   *)
(* state (the model has no timeout transition at all).                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Witness,        \* the pinned witness set
    ByzW,           \* Byzantine witnesses
    MaxBallot,      \* bounds incarnations
    MaxSeq,         \* bounds log positions
    ReadQuorum,     \* promises an incarnation needs before it may sign
    CertQuorum,     \* receipts that certify a claim
    CheckPromise    \* BOOLEAN a witness refuses a claim below its promise

ASSUME ByzW \subseteq Witness

Honest == Witness \ ByzW
None   == [b |-> 0, s |-> 0]
Claims == [b : 1..MaxBallot, s : 1..MaxSeq]

VARIABLES
    promised,   \* honest witness -> highest ballot promised
    accepted,   \* honest witness -> last accepted claim (None if none)
    ob,         \* current incarnation ballot (0 = never started)
    phase,      \* "idle" | "recovering" | "active"
    got,        \* promises received: set of <<witness, claim>>
    seq,        \* last seq this incarnation proposed (or adopted)
    proposed,   \* every claim ever signed by some incarnation
    receipts,   \* claim -> witnesses that issued a receipt
    certified   \* claims that gathered a quorum of receipts (their heads were released)

vars == <<promised, accepted, ob, phase, got, seq, proposed, receipts, certified>>

Gotten == {x[1] : x \in got}
Better(a, c) == IF a.s >= c.s THEN a ELSE c   \* the claim with the larger seq (ties equal here)

Init ==
    /\ promised = [w \in Honest |-> 0]
    /\ accepted = [w \in Honest |-> None]
    /\ ob = 0 /\ phase = "idle" /\ got = {} /\ seq = 0
    /\ proposed = {}
    /\ receipts = [c \in Claims |-> {}]
    /\ certified = {}

\* The process (re)starts with no memory: a fresh, higher ballot, and asks the witnesses.
Restart ==
    /\ ob < MaxBallot
    /\ ob' = ob + 1 /\ phase' = "recovering" /\ got' = {} /\ seq' = 0
    /\ UNCHANGED <<promised, accepted, proposed, receipts, certified>>

\* A correct witness promises (durably) and reports what it accepted. Requests of earlier
\* incarnations may arrive late: they are promised too, but no longer matter to the owner.
HonestPromise(w) ==
    /\ w \in Honest /\ ob > 0
    /\ \E b \in 1..ob :
        /\ b > promised[w]
        /\ promised' = [promised EXCEPT ![w] = b]
        /\ got' = IF b = ob /\ phase = "recovering" THEN got \cup {<<w, accepted[w]>>} ELSE got
    /\ UNCHANGED <<accepted, ob, phase, seq, proposed, receipts, certified>>

\* A Byzantine witness may report nothing, or any claim that exists.
ByzPromise(w) ==
    /\ w \in ByzW /\ phase = "recovering"
    /\ \E c \in {None} \cup proposed :
        got' = got \cup {<<w, c>>}
    /\ UNCHANGED <<promised, accepted, ob, phase, seq, proposed, receipts, certified>>

\* A quorum of promises: adopt the newest claim reported and start above it.
Adopt ==
    /\ phase = "recovering" /\ Cardinality(Gotten) >= ReadQuorum
    /\ \E base \in {x[2].s : x \in got} :
        /\ \A x \in got : x[2].s <= base
        /\ seq' = base
    /\ phase' = "active"
    /\ UNCHANGED <<promised, accepted, ob, got, proposed, receipts, certified>>

Propose ==
    /\ phase = "active" /\ seq < MaxSeq
    /\ seq' = seq + 1
    /\ proposed' = proposed \cup {[b |-> ob, s |-> seq + 1]}
    /\ UNCHANGED <<promised, accepted, ob, phase, got, receipts, certified>>

\* Delivery of any signed claim (also by a superseded incarnation) to a correct witness.
HonestStore(w, c) ==
    /\ w \in Honest /\ c \in proposed
    /\ (CheckPromise => c.b >= promised[w])
    /\ \/ accepted[w] = None
       \/ c.b /= accepted[w].b
       \/ c.s >= accepted[w].s
    /\ promised' = [promised EXCEPT ![w] = IF c.b > @ THEN c.b ELSE @]
    /\ accepted' = [accepted EXCEPT ![w] = c]
    /\ receipts' = [receipts EXCEPT ![c] = @ \cup {w}]
    /\ UNCHANGED <<ob, phase, got, seq, proposed, certified>>

ByzReceipt(w, c) ==
    /\ w \in ByzW /\ c \in proposed
    /\ receipts' = [receipts EXCEPT ![c] = @ \cup {w}]
    /\ UNCHANGED <<promised, accepted, ob, phase, got, seq, proposed, certified>>

Certify(c) ==
    /\ c \in proposed /\ Cardinality(receipts[c]) >= CertQuorum
    /\ certified' = certified \cup {c}
    /\ UNCHANGED <<promised, accepted, ob, phase, got, seq, proposed, receipts>>

Next ==
    \/ Restart \/ Adopt \/ Propose
    \/ \E w \in Witness : HonestPromise(w) \/ ByzPromise(w)
    \/ \E w \in Witness, c \in Claims : HonestStore(w, c) \/ ByzReceipt(w, c)
    \/ \E c \in Claims : Certify(c)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ ob \in 0..MaxBallot /\ seq \in 0..MaxSeq
    /\ phase \in {"idle", "recovering", "active"}
    /\ proposed \subseteq Claims /\ certified \subseteq proposed

\* No self-evidence: two different released heads for one log position never exist.
NoSelfEquivocation ==
    \A c1, c2 \in certified : c1.s = c2.s => c1 = c2

\* An incarnation signs nothing until a read quorum answered (no timeout path exists).
ActiveHasQuorum == phase = "active" => Cardinality(Gotten) >= ReadQuorum
=========================================================================
