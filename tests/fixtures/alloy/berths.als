-- Berth allocation for Saltmere Harbour.
module harbour/berths
open util/ordering[Time]

sig Time {}
abstract sig Berth {}
one sig Inner, Outer extends Berth {}
sig Vessel { berth: Berth one -> Time }

fact oneVesselPerBerth { all t: Time | all b: Berth | lone berth.t.b }
pred moored[v: Vessel, t: Time] { some v.berth.t }
assert noClash { all t: Time | all b: Berth | lone berth.t.b }
check noClash for 4
