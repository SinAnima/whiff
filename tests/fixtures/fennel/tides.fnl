;; Tide model for Saltmere Harbour.
(local gauges (require :gauges))

(local amplitude 1.5)

(fn high-water [base]
  "High water from a base level."
  (+ base amplitude))

(print (high-water 2.0))
