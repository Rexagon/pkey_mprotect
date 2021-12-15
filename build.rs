extern crate cc;

fn main() {
    cc::Build::new().file("src/pkey.c").compile("pkey-sys");
}
