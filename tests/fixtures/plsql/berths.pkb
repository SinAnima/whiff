-- Berth fees for Saltmere Harbour.
CREATE OR REPLACE PACKAGE BODY berths AS
  /* Fee per metre of length. */
  FUNCTION fee(p_length IN NUMBER) RETURN NUMBER IS
  BEGIN
    RETURN p_length * 8;
  END fee;

  PROCEDURE book(p_vessel IN VARCHAR2) IS
  BEGIN
    INSERT INTO bookings (vessel) VALUES (p_vessel);
  END book;
END berths;
/
