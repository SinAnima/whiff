// Finds Saltmere Harbour tide tables in a document store.
import "pe"

rule saltmere_tide_table : harbour docs
{
    meta:
        description = "Tide table exported by the harbour office"
    strings:
        $title = "Saltmere Harbour tide table"
    condition:
        $title
}

private rule harbour_header
{
    strings:
        $h = "SALTMERE"
    condition:
        $h at 0
}
