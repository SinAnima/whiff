-- Tide arithmetic for Saltmere Harbour.
module Tides where

open import Data.Nat using (ℕ; _+_)

record Reading : Set where
  field level : ℕ

highWater : Reading → ℕ
highWater r = Reading.level r + 150
