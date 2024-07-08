//! # An integration test crate

// Lints:
#![warn(clippy::pedantic)]
#![warn(deprecated_in_future)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

#[test]
fn it_works() {
    let result = template_rust::add(2, 2);
    assert_eq!(result, 4);
}
