---------------------------- MODULE Berths ----------------------------
\* Berth allocation for Saltmere Harbour.
EXTENDS Naturals, FiniteSets

CONSTANTS Vessels, MaxBerths
VARIABLES moored

TypeOK == moored \subseteq Vessels
Init == moored = {}
Arrive(v) == /\ Cardinality(moored) < MaxBerths
             /\ moored' = moored \cup {v}
Next == \E v \in Vessels : Arrive(v)

THEOREM Safety == TypeOK
=============================================================================
