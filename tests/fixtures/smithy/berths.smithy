$version: "2"

namespace harbour.berths

use aws.protocols#restJson1

/// Berth bookings for Saltmere Harbour.
@restJson1
service BerthService {
    version: "2026-01-01"
    operations: [GetBerth]
}

@readonly
operation GetBerth {
    input := { @required number: Integer }
    output := { vessel: String }
}

structure Berth {
    number: Integer
}
