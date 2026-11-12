(* Tide arithmetic for Saltmere Harbour. *)
theory Tides
  imports Main
begin

definition high_water :: "nat \<Rightarrow> nat" where
  "high_water b = b + 150"

lemma high_water_gt: "b < high_water b"
  by (simp add: high_water_def)

end
