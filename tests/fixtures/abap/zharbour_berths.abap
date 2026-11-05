*&---------------------------------------------------------------------*
*& Report ZHARBOUR_BERTHS: berth fees for Saltmere Harbour
*&---------------------------------------------------------------------*
REPORT zharbour_berths.

INCLUDE zharbour_fees.

CLASS lcl_berth DEFINITION.
  PUBLIC SECTION.
    METHODS fee IMPORTING iv_length TYPE i RETURNING VALUE(rv_fee) TYPE i.
ENDCLASS.

CLASS lcl_berth IMPLEMENTATION.
  METHOD fee.
    rv_fee = iv_length * 8. " eight per metre
  ENDMETHOD.
ENDCLASS.

START-OF-SELECTION.
  WRITE / NEW lcl_berth( )->fee( 12 ).
