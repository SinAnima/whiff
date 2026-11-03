# R's own facts for the .rds / .rda files of science2_oracle.py's corpus,
# described the way whiff describes them: the explicit class (or the
# type), with "(r rows, c columns)" for a data frame or "[n]" for a
# vector. Adds a sample of R's own library files to the corpus first.
#
#     Rscript science_oracle.R OUT_DIR    (in `whiff-science-r`)
#
# Writes OUT_DIR/expected-r.tsv: path, object name ("" for an .rds) and
# description.

args <- commandArgs(trailingOnly = TRUE)
out <- args[1]
corpus <- file.path(out, "corpus")

set.seed(7)
lib <- list.files(.Library, pattern = "\\.(rds|rda)$", recursive = TRUE, full.names = TRUE, ignore.case = TRUE)
for (p in sample(lib, min(300, length(lib)))) {
    file.copy(p, file.path(corpus, paste0("Rlib__", gsub("/", "__", substring(p, nchar(.Library) + 2)))))
}

vectors <- c("logical", "integer", "double", "complex", "character", "list", "raw", "expression")
describe <- function(x) {
    cls <- attr(x, "class", exact = TRUE)
    k <- if (is.null(cls)) typeof(x) else paste(cls, collapse = "/")
    rn <- attr(x, "row.names", exact = TRUE)
    if (typeof(x) == "list" && !is.null(rn) && length(x) > 0) {
        sprintf("%s (%d rows, %d columns)", k, .row_names_info(x, 2L), length(x))
    } else if (typeof(x) %in% vectors && length(x) > 0) {
        sprintf("%s [%d]", k, length(x))
    } else {
        k
    }
}

rows <- character()
for (name in sort(list.files(corpus, pattern = "\\.(rds|rda|rdata)$", ignore.case = TRUE))) {
    p <- file.path(corpus, name)
    rel <- file.path("corpus", name)
    res <- tryCatch({
        if (grepl("\\.rds$", name, ignore.case = TRUE)) {
            paste(rel, "", describe(readRDS(p)), sep = "\t")
        } else {
            e <- new.env()
            objs <- load(p, envir = e)
            vapply(objs, function(o) paste(rel, o, describe(get(o, envir = e)), sep = "\t"), "")
        }
    }, error = function(err) character())
    rows <- c(rows, res)
}
writeLines(rows, file.path(out, "expected-r.tsv"), useBytes = TRUE)
cat(length(rows), "facts written to", file.path(out, "expected-r.tsv"), "\n")
