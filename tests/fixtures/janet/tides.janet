# Tide model for Saltmere Harbour.
(import ./gauges)

(def amplitude 1.5)

(defn high-water
  "High water from a base level."
  [base]
  (+ base amplitude))

(defmacro report [x] ~(print ,x))

(report (high-water 2.0))
