#![doc = include_str!("../README.md")]

use std::ops::Deref;
use std::sync::Arc;

#[cfg(all(target_arch = "x86", not(target_env = "sgx"), target_feature = "sse"))]
use ::core::arch::x86 as arch;
#[cfg(all(target_arch = "x86_64", not(target_env = "sgx")))]
use ::core::arch::x86_64 as arch;

/// Protection keys instance which is needed to create regions.
///
/// NOTE: You probably should always reuse it for creating regions
/// because there are only 15 available keys in system
#[derive(Default)]
pub struct ProtectionKeys {
    handle: Option<libc::c_int>,
}

impl ProtectionKeys {
    /// Checks whether protection keys are supported.
    ///
    /// See https://www.felixcloutier.com/x86/wrpkru
    pub fn is_supported() -> bool {
        is_ospke_supported()
    }

    /// Creates protection keys instance.
    ///
    /// Requirements to successfully create keys:
    ///
    /// On failure will create a keys stub if `require_protected` is `false`,
    /// returns an error otherwise.
    pub fn new(require_protected: bool) -> Result<Arc<Self>, ProtectionError> {
        #[inline(always)]
        fn stub(require_protected: bool) -> Result<Arc<ProtectionKeys>, ProtectionError> {
            if require_protected {
                // Return an error
                Err(ProtectionError::Unsupported)
            } else {
                // Return an empty handle if protection keys are not supported
                log::error!(
                    "Protection keys are not supported by this CPU or OS. \
                    Skipping keystore memory protection"
                );
                Ok(Arc::new(ProtectionKeys { handle: None }))
            }
        }

        #[cfg(not(target_os = "linux"))]
        #[allow(clippy::needless_return)]
        return stub(require_protected);

        #[cfg(target_os = "linux")]
        {
            // Check if protection keys are supported
            if !is_ospke_supported() {
                return stub(require_protected);
            }

            // SAFETY: syscall will either return -1 if SYS_pkey_alloc is not supported
            // or return result according to https://man7.org/linux/man-pages/man2/pkey_alloc.2.html
            let pkey = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0usize, PKEY_DISABLE_ACCESS) };

            if pkey < 0 && !require_protected {
                // Return an empty handle if no protection keys left
                log::error!("Protection keys allocation failed");
                Ok(Arc::new(Self { handle: None }))
            } else if pkey < 0 {
                // Return an error if no protection keys left
                Err(ProtectionError::PkeyAllocationFailed(
                    std::io::Error::last_os_error(),
                ))
            } else {
                // There are available protection keys
                Ok(Arc::new(Self {
                    handle: Some(pkey as libc::c_int),
                }))
            }
        }
    }

    /// Creates protected region.
    ///
    /// Arc with protected keys is cloned so it is safe to keep only the region.
    pub fn make_region<T>(
        self: &Arc<Self>,
        initial: T,
    ) -> Result<Arc<ProtectedRegion<T>>, ProtectionError>
    where
        T: Sized,
    {
        ProtectedRegion::new(self, initial)
    }

    /// Whether protection keys were allocated
    pub fn is_empty(&self) -> bool {
        self.handle.is_none()
    }

    fn set(&self, rights: usize) {
        #[cfg(not(target_os = "linux"))]
        let _unused = rights;

        #[cfg(target_os = "linux")]
        if let Some(handle) = self.handle {
            // SAFETY: handle will only be Some if `WRPKRU` command is supported
            unsafe {
                let eax = (rights << (2 * handle as usize)) as u32;

                std::arch::asm!(
                    ".byte 0x0f, 0x01, 0xef",
                    in("eax") eax,
                    in("ecx") 0,
                    in("edx") 0,
                    options(nomem, preserves_flags, nostack)
                )
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProtectionKeys {
    fn drop(&mut self) {
        let handle = match self.handle {
            Some(handle) => handle as usize,
            None => return,
        };

        // SAFETY: syscall will either return -1 if SYS_pkey_free is not supported
        // or return result according to https://man7.org/linux/man-pages/man2/pkey_alloc.2.html
        //
        // All protected regions contain pkey as Arc so it will only be destroyed
        // if there are no regions left.
        if unsafe { libc::syscall(libc::SYS_pkey_free, handle) } < 0 {
            log::error!("failed to free pkey: {}", std::io::Error::last_os_error());
        }
    }
}

/// Protected memory page with typed access to its data
pub struct ProtectedRegion<T> {
    pkey: Arc<ProtectionKeys>,
    ptr: *mut libc::c_void,
    _marker: std::marker::PhantomData<T>,
}

impl<T> ProtectedRegion<T> {
    const _ASSERT: () = assert!(std::mem::size_of::<T>() <= PAGE_SIZE);

    fn new(pkey: &Arc<ProtectionKeys>, initial: T) -> Result<Arc<Self>, ProtectionError>
    where
        T: Sized,
    {
        // SAFETY: all parameters are passed according to
        // https://man7.org/linux/man-pages/man2/mmap.2.html
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ProtectionError::MMapFailed(std::io::Error::last_os_error()));
        }

        #[cfg(not(target_os = "linux"))]
        {
            let res = unsafe { libc::mprotect(ptr, PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE) };
            if res < 0 {
                return Err(ProtectionError::MProtectFailed(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        #[cfg(target_os = "linux")]
        {
            // SAFETY: it is called with backward capability with mprotect
            // https://man7.org/linux/man-pages/man2/mprotect.2.html
            let res = unsafe {
                libc::syscall(
                    libc::SYS_pkey_mprotect,
                    ptr as usize,
                    PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    pkey.handle.unwrap_or(-1),
                )
            };
            if res < 0 {
                return Err(ProtectionError::MProtectFailed(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        // Enable memory access
        pkey.set(0);

        // SAFETY: ptr is always aligned to PAGE_SIZE (4KB) and not null
        unsafe { (ptr as *mut T).write(initial) };

        // Disable memory access
        pkey.set(PKEY_DISABLE_ACCESS);

        Ok(Arc::new(Self {
            pkey: pkey.clone(),
            ptr,
            _marker: std::marker::PhantomData::default(),
        }))
    }

    /// Creates region guard with read-only access to the data
    pub fn lock(&'_ self) -> ProtectedRegionGuard<'_, T> {
        ProtectedRegionGuard::new(self)
    }
}

impl<T> Drop for ProtectedRegion<T> {
    fn drop(&mut self) {
        // Enable memory access to run destructor
        self.pkey.set(0);

        // SAFETY: region still exists, properly aligned and accessible to read/write
        unsafe { std::ptr::drop_in_place(self.ptr as *mut T) };

        // Disable memory access
        self.pkey.set(PKEY_DISABLE_ACCESS);

        // SAFETY: region still exists, ptr and length were initialized once on creation
        if unsafe { libc::munmap(self.ptr, PAGE_SIZE) } < 0 {
            log::error!("failed to unmap file: {}", std::io::Error::last_os_error());
        }
    }
}

unsafe impl<T: Sync> Sync for ProtectedRegion<T> {}
unsafe impl<T> Send for ProtectedRegion<T> {}

/// See [`ProtectedRegion::lock()`]
pub struct ProtectedRegionGuard<'a, T> {
    region: &'a ProtectedRegion<T>,
    _marker: std::marker::PhantomData<*const u8>,
}

impl<'a, T> ProtectedRegionGuard<'a, T> {
    fn new(region: &'a ProtectedRegion<T>) -> Self {
        region.pkey.set(0);
        Self {
            region,
            _marker: Default::default(),
        }
    }
}

impl<T> Deref for ProtectedRegionGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: ptr always points to the allocated page
        unsafe { &*(self.region.ptr as *const T) }
    }
}

impl<T> Drop for ProtectedRegionGuard<'_, T> {
    fn drop(&mut self) {
        self.region.pkey.set(PKEY_DISABLE_ACCESS);
    }
}

/// See https://www.felixcloutier.com/x86/wrpkru
fn is_ospke_supported() -> bool {
    const EAX_VENDOR_INFO: u32 = 0x0;
    const EAX_STRUCTURED_EXTENDED_FEATURE_INFO: u32 = 0x7;
    const OSPKE_BIT: u32 = 0b10000;

    // Check if extended feature info leaf is supported
    let vendor_leaf = cpuid_count(EAX_VENDOR_INFO, 0);
    if vendor_leaf.eax < EAX_STRUCTURED_EXTENDED_FEATURE_INFO {
        return false;
    }

    // Check if CR4.PKE=1
    let info = cpuid_count(EAX_STRUCTURED_EXTENDED_FEATURE_INFO, 0);
    info.ecx & OSPKE_BIT == OSPKE_BIT
}

struct CpuIdResult {
    eax: u32,
    ecx: u32,
}

fn cpuid_count(eax: u32, ecx: u32) -> CpuIdResult {
    // Safety: CPUID is supported on all x86_64 CPUs and all x86 CPUs with
    // SSE, but not by SGX.
    let result = unsafe { self::arch::__cpuid_count(eax, ecx) };
    CpuIdResult {
        eax: result.eax,
        ecx: result.ecx,
    }
}

const PKEY_DISABLE_ACCESS: usize = 1;

const PAGE_SIZE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum ProtectionError {
    #[error("Protection keys are not supported by this CPU")]
    Unsupported,
    #[error("Failed to allocate protection keys")]
    PkeyAllocationFailed(#[source] std::io::Error),
    #[error("Failed to map memory")]
    MMapFailed(#[source] std::io::Error),
    #[error("Failed to protect memory")]
    MProtectFailed(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStruct {
        test: bool,
        value: u32,
    }

    impl Drop for TestStruct {
        fn drop(&mut self) {
            println!("dropped {}", self.value);
        }
    }

    #[test]
    fn test_protected_region() {
        let pkey = ProtectionKeys::new(false).unwrap();

        {
            let region = pkey
                .make_region(TestStruct {
                    test: true,
                    value: 123,
                })
                .unwrap();

            let guard = region.lock();
            println!("{}, {}", guard.test, guard.value);
        }
    }
}
