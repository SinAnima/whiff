⍝ Tide model for Saltmere Harbour (levels in cm).
:Namespace Tides
    amplitude←150
    HighWater←{⍵+amplitude}
    ⍝ Mean of a day's readings
    Mean←{(+/⍵)÷≢⍵}
:EndNamespace
