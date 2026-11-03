# R fixtures for whiff (fst, qs, qs2), run by scripts/fixtures/columnar.sh in
# the `whiff-columnar-r` container:  Rscript craft_columnar.R OUT_DIR
# Saltmere Harbour tide readings, CC0-1.0.
args <- commandArgs(trailingOnly = TRUE)
out <- args[1]
for (d in c("fst", "qs")) dir.create(file.path(out, d), recursive = TRUE, showWarnings = FALSE)
n <- 120
tides <- data.frame(
  station = factor(rep(c("Saltmere Pier", "North Mole", "Lock Gate"), length.out = n)),
  at = as.POSIXct("2025-09-01 06:00:00", tz = "UTC") + 600 * (seq_len(n) - 1),
  height_m = round(2.5 + 1.8 * sin(seq_len(n) / 12), 3),
  gauge = sprintf("G%d", 7 + (seq_len(n) %% 3)),
  ok = seq_len(n) %% 11 != 0
)
fst::write_fst(tides, file.path(out, "fst", "tides.fst"), compress = 50)
fst::write_fst(tides[1:30, ], file.path(out, "fst", "tides-uncompressed.fst"), compress = 0)
qs::qsave(tides, file.path(out, "qs", "tides.qs"))
qs2::qs_save(tides, file.path(out, "qs", "tides.qs2"))
