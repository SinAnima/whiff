/-! Tide arithmetic for Saltmere Harbour. -/
import Mathlib.Data.Real.Basic

namespace Tides

/-- A gauge reading in centimetres. -/
structure Reading where
  level : Nat

def highWater (r : Reading) : Nat := r.level + 150

theorem highWater_gt (r : Reading) : r.level < highWater r := by
  unfold highWater; omega

end Tides
