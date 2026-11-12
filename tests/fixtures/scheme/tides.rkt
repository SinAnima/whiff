#lang racket
;; Tide model for Saltmere Harbour.
(require racket/math)

(struct gauge (name level))

(define (high-water g)
  (+ (gauge-level g) (* 1.5 (sin (/ pi 6)))))

#| Example:
   (high-water (gauge "north" 2.0)) |#
(define-syntax-rule (report e) (displayln e))

(report (high-water (gauge "north" 2.0)))
