use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

pub const PAGE_SIZE_4K: u64 = 0x1000;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressErrorDetail {
    ZeroLength = 1,
    StartMisaligned = 2,
    LengthMisaligned = 3,
    EndOverflow = 4,
    BeyondAperture = 5,
    HostMisaligned = 6,
    HostIntervalTooWide = 7,
    WriteWithoutRead = 8,
    ExecuteOnlyUnsupported = 9,
    InvalidPhysicalWidth = 10,
    InvalidPageOffset = 11,
}

fn address_error(code: ErrorCode, detail: AddressErrorDetail) -> MonadError {
    MonadError::new(ErrorPhase::EptBuild, code, detail as u64)
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuestPhysicalAddress(u64);

impl GuestPhysicalAddress {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn from_page_aligned(value: u64) -> MonadResult<Self> {
        if value & (PAGE_SIZE_4K - 1) != 0 {
            return Err(address_error(
                ErrorCode::MisalignedAddress,
                AddressErrorDetail::StartMisaligned,
            ));
        }
        Ok(Self(value))
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostPhysicalAddress(u64);

impl HostPhysicalAddress {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn for_mapping(
        value: u64,
        length: u64,
        leaf_size: u64,
        max_physical_bits: u8,
    ) -> MonadResult<Self> {
        if max_physical_bits == 0 || max_physical_bits >= 64 {
            return Err(address_error(
                ErrorCode::PhysicalAddressTooWide,
                AddressErrorDetail::InvalidPhysicalWidth,
            ));
        }
        if length == 0 {
            return Err(address_error(
                ErrorCode::InvalidRange,
                AddressErrorDetail::ZeroLength,
            ));
        }
        if length & (PAGE_SIZE_4K - 1) != 0 {
            return Err(address_error(
                ErrorCode::MisalignedAddress,
                AddressErrorDetail::LengthMisaligned,
            ));
        }
        if leaf_size < PAGE_SIZE_4K || !leaf_size.is_power_of_two() || value & (leaf_size - 1) != 0
        {
            return Err(address_error(
                ErrorCode::MisalignedAddress,
                AddressErrorDetail::HostMisaligned,
            ));
        }
        let end = value.checked_add(length).ok_or_else(|| {
            address_error(ErrorCode::AddressOverflow, AddressErrorDetail::EndOverflow)
        })?;
        let width_end = 1u64
            .checked_shl(u32::from(max_physical_bits))
            .ok_or_else(|| {
                address_error(
                    ErrorCode::PhysicalAddressTooWide,
                    AddressErrorDetail::InvalidPhysicalWidth,
                )
            })?;
        if end > width_end {
            return Err(address_error(
                ErrorCode::PhysicalAddressTooWide,
                AddressErrorDetail::HostIntervalTooWide,
            ));
        }
        Ok(Self(value))
    }

    pub(super) const fn from_validated(value: u64) -> Self {
        Self(value)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageCount(u64);

impl PageCount {
    pub fn new(value: u64) -> MonadResult<Self> {
        if value == 0 {
            return Err(address_error(
                ErrorCode::InvalidRange,
                AddressErrorDetail::ZeroLength,
            ));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageOffset(u32);

impl PageOffset {
    pub fn new(value: u32) -> MonadResult<Self> {
        if value >= PAGE_SIZE_4K as u32 {
            return Err(address_error(
                ErrorCode::InvalidRange,
                AddressErrorDetail::InvalidPageOffset,
            ));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpaRange {
    start: GuestPhysicalAddress,
    length: u64,
}

impl GpaRange {
    pub fn new(start: u64, length: u64, aperture_end: u64) -> MonadResult<Self> {
        let start = GuestPhysicalAddress::from_page_aligned(start)?;
        if length == 0 {
            return Err(address_error(
                ErrorCode::InvalidRange,
                AddressErrorDetail::ZeroLength,
            ));
        }
        if length & (PAGE_SIZE_4K - 1) != 0 {
            return Err(address_error(
                ErrorCode::MisalignedAddress,
                AddressErrorDetail::LengthMisaligned,
            ));
        }
        let end = start.get().checked_add(length).ok_or_else(|| {
            address_error(ErrorCode::AddressOverflow, AddressErrorDetail::EndOverflow)
        })?;
        if end > aperture_end {
            return Err(address_error(
                ErrorCode::InvalidRange,
                AddressErrorDetail::BeyondAperture,
            ));
        }
        Ok(Self { start, length })
    }

    pub fn end(self) -> MonadResult<u64> {
        self.start.get().checked_add(self.length).ok_or_else(|| {
            address_error(ErrorCode::AddressOverflow, AddressErrorDetail::EndOverflow)
        })
    }

    pub const fn start(self) -> GuestPhysicalAddress {
        self.start
    }

    pub const fn length(self) -> u64 {
        self.length
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptPermissions {
    read: bool,
    write: bool,
    execute: bool,
}

impl EptPermissions {
    pub fn new(
        read: bool,
        write: bool,
        execute: bool,
        execute_only_supported: bool,
    ) -> MonadResult<Self> {
        if write && !read {
            return Err(address_error(
                ErrorCode::UnsupportedPermissionCombination,
                AddressErrorDetail::WriteWithoutRead,
            ));
        }
        if execute && !read && !execute_only_supported {
            return Err(address_error(
                ErrorCode::UnsupportedPermissionCombination,
                AddressErrorDetail::ExecuteOnlyUnsupported,
            ));
        }
        Ok(Self {
            read,
            write,
            execute,
        })
    }

    pub const fn is_present(self) -> bool {
        self.read || self.write || self.execute
    }

    pub const fn read(self) -> bool {
        self.read
    }

    pub const fn write(self) -> bool {
        self.write
    }

    pub const fn execute(self) -> bool {
        self.execute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code<T>(result: MonadResult<T>) -> ErrorCode {
        match result {
            Ok(_) => panic!("fixture unexpectedly succeeded"),
            Err(error) => error.code,
        }
    }

    #[test]
    fn address_range_boundaries() {
        let aperture = 0x20_000;
        assert_eq!(code(GpaRange::new(0, 0, aperture)), ErrorCode::InvalidRange);
        assert_eq!(
            code(GpaRange::new(1, PAGE_SIZE_4K, aperture)),
            ErrorCode::MisalignedAddress
        );
        assert_eq!(
            code(GpaRange::new(0, PAGE_SIZE_4K - 1, aperture)),
            ErrorCode::MisalignedAddress
        );
        assert_eq!(
            code(GpaRange::new(!(PAGE_SIZE_4K - 1), PAGE_SIZE_4K, u64::MAX)),
            ErrorCode::AddressOverflow
        );
        assert!(GpaRange::new(aperture - PAGE_SIZE_4K, PAGE_SIZE_4K, aperture).is_ok());
        assert_eq!(
            code(GpaRange::new(aperture, PAGE_SIZE_4K, aperture)),
            ErrorCode::InvalidRange
        );

        let last_48_bit_page = (1u64 << 48) - PAGE_SIZE_4K;
        assert!(
            HostPhysicalAddress::for_mapping(last_48_bit_page, PAGE_SIZE_4K, PAGE_SIZE_4K, 48)
                .is_ok()
        );
        assert_eq!(
            code(HostPhysicalAddress::for_mapping(
                1u64 << 48,
                PAGE_SIZE_4K,
                PAGE_SIZE_4K,
                48
            )),
            ErrorCode::PhysicalAddressTooWide
        );
        assert_eq!(
            code(HostPhysicalAddress::for_mapping(
                0,
                PAGE_SIZE_4K - 1,
                PAGE_SIZE_4K,
                48
            )),
            ErrorCode::MisalignedAddress
        );
        assert_eq!(
            code(HostPhysicalAddress::for_mapping(
                0,
                PAGE_SIZE_4K,
                PAGE_SIZE_4K,
                0
            )),
            ErrorCode::PhysicalAddressTooWide
        );
        assert_eq!(
            code(EptPermissions::new(false, true, false, false)),
            ErrorCode::UnsupportedPermissionCombination
        );
        assert!(!EptPermissions::new(false, false, false, false)
            .expect("no-access is a valid not-present mapping")
            .is_present());
    }
}
