;; Tide model for Saltmere Harbour.
(import math)

(defclass Gauge []
  (defn __init__ [self level] (setv self.level level)))

(defn high-water [g]
  "High water from a gauge."
  (+ g.level (* 1.5 (math.sin (/ math.pi 6)))))

(print (high-water (Gauge 2.0)))
