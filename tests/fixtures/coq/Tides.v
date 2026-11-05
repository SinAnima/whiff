(* Tide arithmetic for Saltmere Harbour. *)
Require Import Arith.

Definition high_water (base : nat) : nat := base + 150.

Lemma high_water_gt : forall b, b < high_water b.
Proof.
  intros b. unfold high_water. lia.
Qed.
