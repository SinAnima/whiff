{ Tide tables for Saltmere Harbour. }
unit Tides;

interface

uses
  SysUtils,
  Math;

type
  TGauge = record
    Name: string;
    Level: Double;
  end;

function HighWater(const G: TGauge): Double;

implementation

// Simple harmonic model.
function HighWater(const G: TGauge): Double;
begin
  Result := G.Level + 1.5 * Sin(Pi / 6);
end;

end.
