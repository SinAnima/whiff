// Berth registry for Saltmere Harbour.
module saltmere::berths {
    use std::string::String;
    use sui::table::Table;

    /// A berth and its vessel.
    public struct Berth has store {
        number: u64,
        vessel: String,
    }

    public fun number(b: &Berth): u64 {
        b.number
    }
}
