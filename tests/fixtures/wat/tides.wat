;; Tide model for the harbour web map.
(module $tides
  (import "env" "sin" (func $sin (param f64) (result f64)))
  (memory $mem 1)
  (global $amplitude f64 (f64.const 1.5))
  (; high water from a base level ;)
  (func $high_water (export "high_water") (param $base f64) (result f64)
    local.get $base
    global.get $amplitude
    f64.add))
