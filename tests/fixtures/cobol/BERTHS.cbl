      * Berth fees for Saltmere Harbour.
       IDENTIFICATION DIVISION.
       PROGRAM-ID. BERTHS.
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       COPY FEES.
       01 WS-LENGTH PIC 9(3) VALUE 12.
       01 WS-FEE    PIC 9(5) VALUE 0.
       PROCEDURE DIVISION.
       MAIN-PARA.
           COMPUTE WS-FEE = WS-LENGTH * 8
           DISPLAY "FEE: " WS-FEE
           STOP RUN.
