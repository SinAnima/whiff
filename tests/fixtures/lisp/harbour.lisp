;;;; Berth allocation for Saltmere Harbour.
(defpackage :saltmere
  (:use :cl)
  (:export #:allocate))
(in-package :saltmere)

(defparameter *berths* 12 "Berths in the inner basin.")

#| Berths are numbered
   from the harbour mouth. |#
(defstruct vessel name length)

(defun allocate (vessel)
  "Return a berth for VESSEL."
  (if (> (vessel-length vessel) 30) 1 2))

(defmacro with-harbour (&body body)
  `(progn ,@body))
