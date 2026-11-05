// Berth counter for Saltmere Harbour.
use core::num::traits::Zero;

#[derive(Drop)]
struct Berth {
    number: u32,
}

trait BerthTrait {
    fn is_inner(self: @Berth) -> bool;
}

fn main() {
    let b = Berth { number: 3 };
    println!("{}", b.number);
}
