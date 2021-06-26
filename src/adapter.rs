
use crate::wintun_raw;

struct Adapter {
    handle: wintun_raw::WINTUN_ADAPTER_HANDLE;
}

struct CreateData {
    adapter: Adapter,
    reboot_required: bool,
}

impl Adapter {
    //TODO: Call get last error for error information on failure
    
    /// Creates a new wintun adapter
    pub create(pool: &str, name: &str, guid: Option<u128>) -> Result<CreateData, ()> {
        let pool_utf16 = pool

    }

}

