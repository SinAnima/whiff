;;; harbour-mode.el --- Saltmere Harbour notes  -*- lexical-binding: t -*-
(require 'cl-lib)

(defcustom harbour-berths 12
  "Number of berths."
  :type 'integer)

(defun harbour-tide ()
  "Show the next tide."
  (interactive)
  (message "High water at 14:20"))

(provide 'harbour-mode)
;;; harbour-mode.el ends here
