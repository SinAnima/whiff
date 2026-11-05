# pragma version ^0.4.0
"""
@title Berth registry for Saltmere Harbour
"""
from ethereum.ercs import IERC20

struct Berth:
    number: uint256
    vessel: String[32]

event Assigned:
    number: uint256

berths: public(HashMap[uint256, Berth])

@external
def assign(n: uint256, vessel: String[32]):
    self.berths[n] = Berth(number=n, vessel=vessel)
    log Assigned(n)
