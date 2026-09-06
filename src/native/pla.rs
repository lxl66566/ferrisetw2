//! Native API - Performance Logs and Alerts COM
//!
//! The `pla` module is an abstraction layer for the Windows evntrace library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `evntrace` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API to interact
//! with the crate
use windows::core::BSTR;
use windows::Win32::System::Variant::VARIANT;
use windows::{
    core::GUID,
    Win32::System::{
        Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED},
        Performance::{ITraceDataProviderCollection, TraceDataProviderCollection},
    },
};

/// Pla native module errors
#[derive(Debug, PartialEq, Eq)]
pub enum PlaError {
    /// Represents a Provider not found Error
    NotFound,
    /// Represents an HRESULT common error
    ComError(windows::core::Error),
}

impl From<windows::core::Error> for PlaError {
    fn from(val: windows::core::Error) -> PlaError {
        PlaError::ComError(val)
    }
}

pub(crate) type ProvidersComResult<T> = Result<T, PlaError>;

// https://github.com/microsoft/krabsetw/blob/31679cf84bc85360158672699f2f68a821e8a6d0/krabs/krabs/provider.hpp#L487
pub(crate) unsafe fn get_provider_guid(name: &str) -> ProvidersComResult<GUID> {
    // CoUninitialize must be called once for every successful CoInitializeEx
    // (including when it returns S_FALSE, i.e. COM was already initialized on
    // this thread), so pair the calls even on the early-return paths
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;

    let result = find_provider_guid(name);

    unsafe { CoUninitialize() };
    result
}

/// Enumerates the registered providers to find `name`'s GUID.
///
/// # Safety
///
/// COM must be initialized on the current thread (see [`get_provider_guid`])
unsafe fn find_provider_guid(name: &str) -> ProvidersComResult<GUID> {
    let all_providers: ITraceDataProviderCollection =
        unsafe { CoCreateInstance(&TraceDataProviderCollection, None, CLSCTX_ALL) }?;

    all_providers.GetTraceDataProviders(&BSTR::default())?;

    let count = all_providers.Count()? as u32;

    let mut index = 0u32;
    let mut guid = None;

    while index < count as u32 {
        let provider = all_providers.get_Item(&VARIANT::from(index))?;
        let raw_name = provider.DisplayName()?;

        let prov_name = String::from_utf16_lossy(&raw_name);

        index += 1;
        // check if matches, if it does get guid and break
        if prov_name.eq(name) {
            guid = Some(provider.Guid()?);
            break;
        }
    }

    if index == count as u32 {
        return Err(PlaError::NotFound);
    }

    Ok(guid.unwrap())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn test_get_provider() {
        unsafe {
            let guid =
                get_provider_guid("Microsoft-Windows-Kernel-Process").expect("Error Getting GUID");

            assert_eq!(
                GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716),
                guid
            );
        }
    }

    #[test]
    pub fn test_provider_not_found() {
        unsafe {
            let err = get_provider_guid("Not-A-Real-Provider");

            assert_eq!(err, Err(PlaError::NotFound));
        }
    }

    #[test]
    pub fn test_repeated_lookups_keep_com_balanced() {
        // Both the success and the early-return paths must balance
        // CoInitializeEx with CoUninitialize, or COM resources leak away
        unsafe {
            for _ in 0..3 {
                get_provider_guid("Not-A-Real-Provider").unwrap_err();
            }
            for _ in 0..3 {
                get_provider_guid("Microsoft-Windows-Kernel-Process").unwrap();
            }
        }
    }
}
