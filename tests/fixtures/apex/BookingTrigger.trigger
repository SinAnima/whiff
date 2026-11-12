// Keep berth counts current.
trigger BookingTrigger on Booking__c (after insert) {
    System.debug(BerthService.freeBerths(Trigger.new.size()));
}
