! Tide model for Saltmere Harbour.
module tides
  implicit none
contains
  ! High water from a base level.
  pure real function high_water(base)
    real, intent(in) :: base
    high_water = base + 1.5 * sin(3.14159 / 6.0)
  end function high_water
end module tides

program harbour
  use tides
  implicit none
  print *, high_water(2.0)
end program harbour
