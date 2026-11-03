# R fixtures for whiff (rds, RData, SAS sas7bdat), run by scripts/fixtures/science.sh in
# the `whiff-science-r` container:  Rscript craft_science.R OUT_DIR
# Saltmere Harbour tide readings, CC0-1.0.
args <- commandArgs(trailingOnly = TRUE)
out <- args[1]
for (d in c("rds", "rdata", "sas7bdat")) dir.create(file.path(out, d), recursive = TRUE, showWarnings = FALSE)
tides <- data.frame(gauge = c("G7", "G8", "G9"), height_m = c(2.41, 3.05, 1.98), ok = c(TRUE, TRUE, FALSE))
attr(tides, "comment") <- "Saltmere tide readings"
saveRDS(tides, file.path(out, "rds", "tides.rds"))
saveRDS(tides, file.path(out, "rds", "tides-xz.rds"), compress = "xz")
saveRDS(tides, file.path(out, "rds", "tides-ascii.rds"), ascii = TRUE, compress = FALSE)
station <- "Saltmere Pier"
readings <- tides$height_m
save(tides, station, readings, file = file.path(out, "rdata", "harbour.RData"))
haven::write_sas(tides, file.path(out, "sas7bdat", "tides.sas7bdat"))
