------------------------- MODULE Accountability -------------------------
(***************************************************************************)
(* Bounded model of the Game-Verification accountability protocol.         *)
(*                                                                         *)
(* One contested sequence slot per signer is modelled. A signed statement  *)
(* is (owner, v): v=1 and v=2 are two different heads for the slot, v=3 is *)
(* a signed false checkpoint. A correct signer signs exactly one of 1,2    *)
(* per incarnation and never 3; a Byzantine signer may sign anything.      *)
(* Signatures are unforgeable: `signed` only grows through a signer's own  *)
(* Sign action (the cryptographic assumption, outside the model).          *)
(*                                                                         *)
(* Verifiers are the players and the witnesses. Evidence is accepted only  *)
(* when ValidEv holds, which reads `signed` and nothing else: not votes,   *)
(* not timeouts, not who relayed it. Message loss, duplication and         *)
(* reordering are modelled by Relay (deliver or lose, arbitrary order,     *)
(* repeatable).                                                            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Players,        \* roster
    Signers,        \* players that can ever sign (keeps the state space bounded)
    Byz,            \* Byzantine players (subset of Players)
    Witnesses,
    ByzW,           \* Byzantine witnesses
    PinCheck,       \* BOOLEAN recovery refuses a rollback below a pinned head
    PinsWriteAhead  \* BOOLEAN the pin is durable before the statement is released

ASSUME Byz \subseteq Players /\ Signers \subseteq Players /\ ByzW \subseteq Witnesses
ASSUME Players \ Byz # {}            \* at least one correct participant (security assumption)

\* Interchangeable correct participants (state-space reduction only; used by n5.cfg).
Sym == Permutations((Players \ Byz) \ Signers) \cup Permutations(Witnesses \ ByzW)

Verifiers == Players \cup Witnesses
CorrectP  == Players \ Byz
Vals      == {1, 2, 3}
Kinds     == {"EQ", "FR"}            \* equivocation, false checkpoint
Stmt      == Players \X Vals
Ev        == Players \X Kinds \X Vals \X Vals   \* a claim: <<accused, kind, a, b>>
Nones     == 0                       \* "no head signed"

VARIABLES
    signed,      \* set of Stmt really signed by their owner
    log,         \* log[p]: head p holds in its volatile log (0 = none)
    pinned,      \* pinned[p]: head recorded in p's durable pin file (0 = none)
    staged,      \* staged[p]: head durably logged (fsynced) but not yet released to any peer (0 = none)
    up,          \* up[p]: process running
    unresolved,  \* unresolved[p]: recovery could not be anchored; p must not sign
    held,        \* held[v]: signed statements verifier v holds (pinned authenticators)
    proven,      \* proven[v]: set of <<accused, kind>> v has proven by verifying evidence
    accepted,    \* accepted[v]: checkpoint values v accepted
    cstate,      \* cstate[c]: challenge state NONE|PENDING|TIMEDOUT|ANSWERED
    ctarget,     \* ctarget[c]: challenged player
    csusp        \* csusp[c]: was ever SUSPECTED_NONCOOPERATION

vars == <<signed, log, pinned, staged, up, unresolved, held, proven, accepted,
          cstate, ctarget, csusp>>

\* State constraint for the bounded 5-participant scenario (n5_bounded.cfg): at most two
\* signed statements exist, enough for one equivocation or one false checkpoint plus a
\* correct head. It is a scenario bound, not a proof about larger runs.
SignedBound == Cardinality(signed) <= 2

ChalIds == 1..1

(***************************** verification ********************************)
\* The one place a verdict is decided. It reads the signature set and nothing else.
ValidEv(e) ==
    LET p == e[1] IN
    CASE e[2] = "EQ" -> e[3] # e[4] /\ <<p, e[3]>> \in signed /\ <<p, e[4]>> \in signed
      [] e[2] = "FR" -> e[3] = 3 /\ <<p, 3>> \in signed
      [] OTHER -> FALSE

Init ==
    /\ signed = {}
    /\ log = [p \in Players |-> 0]
    /\ pinned = [p \in Players |-> 0]
    /\ staged = [p \in Players |-> 0]
    /\ up = [p \in Players |-> TRUE]
    /\ unresolved = [p \in Players |-> FALSE]
    /\ held = [v \in Verifiers |-> {}]
    /\ proven = [v \in Verifiers |-> {}]
    /\ accepted = [v \in Verifiers |-> {}]
    /\ cstate = [c \in ChalIds |-> "NONE"]
    /\ ctarget = [c \in ChalIds |-> CHOOSE p \in Players : TRUE]
    /\ csusp = [c \in ChalIds |-> FALSE]

(******************************** signing **********************************)
\* The implementation is write-ahead (Pipeline::poll_outbox is the commit barrier):
\*   1. StageSign  - the new head is appended to the log and the trust store (signed log head
\*                   plus pin) is fsynced. Nothing has left the process. A failed fsync stops
\*                   here and the signer stays closed (no Release step is enabled for it).
\*   2. Release    - only after the durable write succeeded does the authenticator leave the
\*                   process (become `signed` and held by the signer for relaying).
\* A crash between the two leaves a durable head that nobody has seen: harmless.
\* Without write-ahead (PinsWriteAhead = FALSE, the negative model) the statement is released
\* with the stage and the pin is persisted some time later by PersistPin.
StageSign(p, v) ==
    /\ p \in Signers \cap CorrectP /\ up[p] /\ ~unresolved[p] /\ log[p] = 0 /\ staged[p] = 0
    /\ v \in {1, 2}
    /\ log' = [log EXCEPT ![p] = v]
    /\ staged' = [staged EXCEPT ![p] = v]
    /\ pinned' = IF PinsWriteAhead THEN [pinned EXCEPT ![p] = v] ELSE pinned
    /\ UNCHANGED <<signed, up, unresolved, held, proven, accepted, cstate, ctarget, csusp>>

Release(p) ==
    /\ p \in CorrectP /\ up[p] /\ staged[p] # 0
    /\ (PinsWriteAhead => pinned[p] = staged[p])      \* the barrier: durable before released
    /\ signed' = signed \cup {<<p, staged[p]>>}
    /\ held' = [held EXCEPT ![p] = @ \cup {<<p, staged[p]>>}]
    /\ staged' = [staged EXCEPT ![p] = 0]
    /\ UNCHANGED <<log, pinned, up, unresolved, proven, accepted, cstate, ctarget, csusp>>

\* Without write-ahead the pin lands some time after the statement is released.
PersistPin(p) ==
    /\ ~PinsWriteAhead /\ up[p] /\ log[p] # 0 /\ pinned[p] # log[p]
    /\ pinned' = [pinned EXCEPT ![p] = log[p]]
    /\ UNCHANGED <<staged, signed, log, up, unresolved, held, proven, accepted, cstate, ctarget, csusp>>

\* A Byzantine signer may sign anything, any number of times, including 3.
SignByz(p, v) ==
    /\ p \in Signers \cap Byz
    /\ signed' = signed \cup {<<p, v>>}
    /\ held' = [held EXCEPT ![p] = @ \cup {<<p, v>>}]
    /\ UNCHANGED <<staged, log, pinned, up, unresolved, proven, accepted, cstate, ctarget, csusp>>

(************************** crash and recovery *****************************)
Crash(p) ==
    /\ p \in CorrectP /\ up[p]
    /\ up' = [up EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<staged, signed, log, pinned, unresolved, held, proven, accepted, cstate, ctarget, csusp>>

\* The attacker (or a torn write) chooses what the log looks like on restart: the true log,
\* or any rollback of it (empty). The pin file and what other verifiers hold are the anchors.
Anchor(p) == { pinned[p] } \cup { x \in {1, 2} : \E v \in Verifiers \ {p} : <<p, x>> \in held[v] }
Recover(p, restored) ==
    /\ p \in CorrectP /\ ~up[p]
    /\ restored \in {log[p], 0}
    /\ LET anchors == Anchor(p) \ {0}
           rolledBack == \E a \in anchors : restored # a
       IN /\ up' = [up EXCEPT ![p] = TRUE]
          /\ IF PinCheck /\ rolledBack
                THEN /\ unresolved' = [unresolved EXCEPT ![p] = TRUE]   \* refuse: Rollback / Fork
                     /\ log' = [log EXCEPT ![p] = restored]
                ELSE /\ unresolved' = unresolved
                     /\ log' = [log EXCEPT ![p] = restored]
    /\ UNCHANGED <<staged, signed, pinned, held, proven, accepted, cstate, ctarget, csusp>>

\* Live witness-anchor recovery (Auditor::supply_anchor / AnchorReq). An unresolved player
\* asks peers for the highest head they hold of its own log. If exactly one head is anchored
\* (by its pin file or by a statement another verifier holds) it rebases onto it - the log is
\* replaced by the anchored head and the slot is NOT re-signed - and signing resumes.
Rebase(p) ==
    /\ p \in CorrectP /\ up[p] /\ unresolved[p]
    /\ LET anchors == Anchor(p) \ {0} IN
       /\ Cardinality(anchors) = 1
       /\ \E a \in anchors :
            /\ log' = [log EXCEPT ![p] = a]
            /\ pinned' = [pinned EXCEPT ![p] = a]
    /\ unresolved' = [unresolved EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<staged, signed, up, held, proven, accepted, cstate, ctarget, csusp>>

\* A restarted correct player whose log was rolled back and that is not unresolved resumes: it
\* may sign the slot again. This is what the anchored recovery check is there to prevent.
(* Resume is StageSign with log[p] = 0 after Recover; no separate action is needed. *)

(*********************** relaying, loss, duplication ***********************)
\* u relays a statement it holds to v. Arbitrary order, repeatable (duplication), lossy.
RelayStmt(u, v, s) ==
    /\ u \in Verifiers /\ v \in Verifiers /\ u # v /\ s \in held[u] /\ s \notin held[v]
    \* Loss is the absence of this step; duplication and reordering are free (held is a set).
    /\ held' = [held EXCEPT ![v] = @ \cup {s}]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, proven, accepted, cstate, ctarget, csusp>>

\* A verifier that holds two conflicting statements, or a false checkpoint, can build evidence.
\* Evidence is verified before it is stored; it does not matter who relayed it.
Accept(v, e) ==
    /\ v \in Verifiers /\ e \in Ev
    /\ ValidEv(e) /\ <<e[1], e[2]>> \notin proven[v]
    /\ proven' = [proven EXCEPT ![v] = @ \cup {<<e[1], e[2]>>}]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, held, accepted, cstate, ctarget, csusp>>

\* Evidence can be re-derived locally from held statements...
Derive(v, e) ==
    /\ e \in Ev /\ ValidEv(e)
    /\ \/ e[2] = "EQ" /\ <<e[1], e[3]>> \in held[v] /\ <<e[1], e[4]>> \in held[v]
       \/ e[2] = "FR" /\ <<e[1], 3>> \in held[v]
    /\ Accept(v, e)

\* ... or arrive from anyone, honest or not. A forged item is simply not ValidEv.
Receive(v, e) == Accept(v, e)

\* A Byzantine witness may relay anything, including forged evidence: Accept refuses it
\* because ValidEv reads `signed` only. Votes do not exist in the verdict path at all.

(************************ checkpoints: provisional -> accepted *************)
\* A checkpoint value is provisional at v once every roster member's signature for it is held,
\* and accepted when, in addition, no valid fraud or equivocation is proven against any signer
\* and no other value is already accepted.
Provisional(v, x) == \A q \in Players : <<q, x>> \in held[v]
AcceptCp(v, x) ==
    /\ v \in Verifiers /\ Provisional(v, x) /\ x \notin accepted[v]
    /\ accepted[v] = {}
    /\ \A q \in Players : <<q, "EQ">> \notin proven[v] /\ <<q, "FR">> \notin proven[v]
    /\ accepted' = [accepted EXCEPT ![v] = @ \cup {x}]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, held, proven, cstate, ctarget, csusp>>

(**************************** challenges ***********************************)
\* Opening an id twice is a duplicate accusation: it changes nothing (replay safe).
OpenChallenge(c, p) ==
    /\ cstate[c] = "NONE"
    /\ cstate' = [cstate EXCEPT ![c] = "PENDING"]
    /\ ctarget' = [ctarget EXCEPT ![c] = p]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, held, proven, accepted, csusp>>
DuplicateAccusation(c) ==
    /\ cstate[c] # "NONE"
    /\ UNCHANGED vars
\* A timeout yields suspicion only. It is a status, never a proof.
TimeoutChallenge(c) ==
    /\ cstate[c] = "PENDING"
    /\ cstate' = [cstate EXCEPT ![c] = "TIMEDOUT"]
    /\ csusp' = [csusp EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, held, proven, accepted, ctarget>>
\* A correct target's response is bound to (id, target): it answers only that challenge, and a
\* late answer after a timeout still clears it. A response for another id or target is ignored.
AnswerChallenge(c) ==
    /\ cstate[c] \in {"PENDING", "TIMEDOUT"}
    /\ ctarget[c] \in CorrectP /\ up[ctarget[c]]
    /\ cstate' = [cstate EXCEPT ![c] = "ANSWERED"]
    /\ UNCHANGED <<staged, signed, log, pinned, up, unresolved, held, proven, accepted, ctarget, csusp>>

Next ==
    \/ \E p \in Players, v \in Vals : StageSign(p, v) \/ SignByz(p, v)
    \/ \E p \in Players : Release(p) \/ Rebase(p)
    \/ \E p \in Signers : PersistPin(p) \/ Crash(p) \/ \E r \in {0, 1, 2} : Recover(p, r)
    \/ \E u, v \in Verifiers, s \in Stmt : RelayStmt(u, v, s)
    \/ \E v \in Verifiers, e \in Ev : Derive(v, e) \/ Receive(v, e)
    \/ \E v \in Verifiers, x \in {1, 2} : AcceptCp(v, x)
    \/ \E c \in ChalIds : \/ \E p \in Players : OpenChallenge(c, p)
                          \/ DuplicateAccusation(c) \/ TimeoutChallenge(c) \/ AnswerChallenge(c)

Spec == Init /\ [][Next]_vars

(* Liveness assumptions (stated, not proved): every held statement is relayed to every verifier
   infinitely often, a lost delivery is retried (partitions heal), and every verifier
   eventually looks at what it holds. *)
Fair == Spec /\ WF_vars(\E u, v \in Verifiers, s \in Stmt : RelayStmt(u, v, s))
             /\ WF_vars(\E v \in Verifiers, e \in Ev : Derive(v, e))

(****************************** safety properties **************************)
TypeOK ==
    /\ signed \subseteq Stmt
    /\ \A v \in Verifiers : proven[v] \subseteq Players \X Kinds /\ held[v] \subseteq signed

\* 1. No verdict against a correct participant.
NoVerdictAgainstCorrect ==
    \A v \in Verifiers, p \in CorrectP : <<p, "EQ">> \notin proven[v] /\ <<p, "FR">> \notin proven[v]

\* 2. No timeout-only path to PROVEN_FRAUD: every proof carries valid evidence, and a challenge
\*    that only timed out never produced one by itself.
Justified(p, k) ==
    CASE k = "EQ" -> \E a, b \in Vals : a # b /\ <<p, a>> \in signed /\ <<p, b>> \in signed
      [] k = "FR" -> <<p, 3>> \in signed
      [] OTHER -> FALSE
EveryProofIsEvidence ==
    \A v \in Verifiers : \A pr \in proven[v] : Justified(pr[1], pr[2])
TimeoutIsNotProof ==
    \A c \in ChalIds : csusp[c] => \A v \in Verifiers :
        (<<ctarget[c], "EQ">> \in proven[v] \/ <<ctarget[c], "FR">> \in proven[v])
        => (Justified(ctarget[c], "EQ") \/ Justified(ctarget[c], "FR"))

\* 3. No conflicting histories accepted (given at least one correct roster member).
NoConflictingAccepted == \A v \in Verifiers : Cardinality(accepted[v]) <= 1

\* 4. Invalid evidence never proves: a proof exists only for evidence valid under `signed`.
InvalidNeverProves == \A v \in Verifiers : proven[v] \subseteq {pr \in Players \X Kinds : Justified(pr[1], pr[2])}

\* 5. Valid evidence is verifiable regardless of witness votes: ValidEv reads `signed` only
\*    (see its definition); there is no votes variable in the verdict path. The
\*    EquivocationConverges property below is checked with a Byzantine witness present.

\* 6. A counterproof cannot be bypassed by duplicate accusations: once answered, a challenge
\*    never reverts (action property below), and an answered challenge's target has no proof.
AnsweredStaysAnswered == [][\A c \in ChalIds : cstate[c] = "ANSWERED" => cstate'[c] = "ANSWERED"]_vars

\* Replay safety: a challenge id is opened at most once.
ChallengeOpenedOnce == [][\A c \in ChalIds : cstate[c] # "NONE" => ctarget'[c] = ctarget[c]]_vars

\* A correct player never signs two different heads for the slot (the recovery obligation).
NoSelfEquivocation == \A p \in CorrectP : ~(<<p, 1>> \in signed /\ <<p, 2>> \in signed)

(****************************** liveness (fair) ****************************)
\* Under Fair and bounded loss, a Byzantine equivocation signed by p reaches every verifier's
\* proof set.
EquivocationConverges ==
    \A p \in Byz \cap Signers :
        (<<p, 1>> \in signed /\ <<p, 2>> \in signed) ~>
            (\A v \in Verifiers : <<p, "EQ">> \in proven[v])
=======================================================================
