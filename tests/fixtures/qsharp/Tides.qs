// Quantum coin for picking a berth (a teaching example).
namespace Saltmere.Tides {
    open Microsoft.Quantum.Measurement;

    /// Returns a random berth side.
    operation PickSide() : Result {
        use q = Qubit();
        H(q);
        return MResetZ(q);
    }

    function Berths() : Int {
        return 12;
    }
}
