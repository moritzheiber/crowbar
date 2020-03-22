extern crate crowbar;

use crowbar::exit;
use crowbar::run;

fn main() -> () {
    exit::ok_or_exit(run())
}
