use crate::wintun_raw::WCHAR;
use std::{io, mem};
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

pub fn luid_to_alias(luid: &NET_LUID_LH) -> io::Result<Vec<WCHAR>> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = vec![0; 257];

    match unsafe { ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len()) } {
        0 => Ok(alias),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn alias_to_luid(alias: &[WCHAR]) -> io::Result<NET_LUID_LH> {
    let mut luid = unsafe { mem::zeroed() };

    match unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } {
        0 => Ok(luid),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}
pub fn luid_to_index(luid: &NET_LUID_LH) -> io::Result<u32> {
    let mut index = 0;

    match unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) } {
        0 => Ok(index),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> io::Result<GUID> {
    let mut guid = unsafe { mem::zeroed() };

    match unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) } {
        0 => Ok(guid),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}
