## pkey_mprotect
Typed `pkey_mprotect` wrapper.

> Only works on Linux on CPUs with Memory Protection Keys support

**MSRV: 1.59 (due to const panics and `asm!` macro)**

### Example
```rust
use pkey_mprotect::*;

struct Keys {
    my_key: [u8; 32],
}

fn main() {
    // Protection keys instance is needed to create regions.
    // NOTE: You probably should always reuse it because there
    // are only 15 available keys in system
    let pkey = ProtectionKeys::new(true).unwrap();

    // Protected region is a thread-safe wrapper around mmaped
    // memory which was secured with `pkey_mprotect`
    let region = pkey.make_region(Keys {
        my_key: [42; 32],
    }).unwrap();

    // To read the data you must lock the region. Access is 
    // granted only for the duration of the guards lifetime
    {
        let region = region.lock();
        println!("{:?}", region.my_key);
    }
}
```
