/**
 * Berth bookings for Saltmere Harbour.
 */
public with sharing class BerthService {
    // Berths in the inner basin.
    private static final Integer BERTHS = 12;

    public static Integer freeBerths(Integer booked) {
        return BERTHS - booked;
    }
}
