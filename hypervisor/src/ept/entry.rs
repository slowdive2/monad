use core::mem::size_of;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{EptPermissions, HostPhysicalAddress};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptMemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

impl TryFrom<u8> for EptMemoryType {
    type Error = EptEntryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Uncacheable),
            1 => Ok(Self::WriteCombining),
            4 => Ok(Self::WriteThrough),
            5 => Ok(Self::WriteProtected),
            6 => Ok(Self::WriteBack),
            _ => Err(EptEntryError::InvalidMemoryType),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptLevel {
    Pml4 = 4,
    Pdpt = 3,
    Pd = 2,
    Pt = 1,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptLeafSize {
    Size4K = 0x1000,
    Size2M = 0x20_0000,
    Size1G = 0x4000_0000,
}

impl EptLeafSize {
    pub const fn bytes(self) -> u64 {
        self as u64
    }
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptEntryError {
    InvalidPhysicalWidth = 1,
    PhysicalAddressTooWide = 2,
    MisalignedAddress = 3,
    UnsupportedPermissions = 4,
    ReservedBits = 5,
    IllegalLargeLeaf = 6,
    InvalidMemoryType = 7,
    NonzeroNotPresent = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecodedEptEntry {
    NotPresent,
    Table {
        hpa: HostPhysicalAddress,
        permissions: EptPermissions,
    },
    Leaf {
        hpa: HostPhysicalAddress,
        size: EptLeafSize,
        permissions: EptPermissions,
        memory_type: EptMemoryType,
    },
}

fn entry_error(detail: EptEntryError) -> MonadError {
    let code = match detail {
        EptEntryError::PhysicalAddressTooWide => ErrorCode::PhysicalAddressTooWide,
        EptEntryError::MisalignedAddress => ErrorCode::MisalignedAddress,
        EptEntryError::UnsupportedPermissions => ErrorCode::UnsupportedPermissionCombination,
        _ => ErrorCode::EptVerificationFailure,
    };
    MonadError::new(ErrorPhase::EptBuild, code, detail as u64)
}

fn physical_mask(max_physical_bits: u8) -> MonadResult<u64> {
    if !(12..=48).contains(&max_physical_bits) {
        return Err(entry_error(EptEntryError::InvalidPhysicalWidth));
    }
    let limit = 1u64
        .checked_shl(u32::from(max_physical_bits))
        .ok_or_else(|| entry_error(EptEntryError::InvalidPhysicalWidth))?;
    Ok((limit - 1) & !0xfff)
}

fn encode_table(hpa: HostPhysicalAddress, max_physical_bits: u8) -> MonadResult<u64> {
    let mask = physical_mask(max_physical_bits)?;
    let address = hpa.get();
    if address & 0xfff != 0 {
        return Err(entry_error(EptEntryError::MisalignedAddress));
    }
    if address & !mask != 0 {
        return Err(entry_error(EptEntryError::PhysicalAddressTooWide));
    }
    Ok(address | 0x7)
}

fn encode_leaf(
    hpa: HostPhysicalAddress,
    size: EptLeafSize,
    permissions: EptPermissions,
    memory_type: EptMemoryType,
    max_physical_bits: u8,
) -> MonadResult<u64> {
    if permissions.write() && !permissions.read() {
        return Err(entry_error(EptEntryError::UnsupportedPermissions));
    }
    let address = hpa.get();
    if address & (size.bytes() - 1) != 0 {
        return Err(entry_error(EptEntryError::MisalignedAddress));
    }
    let mask = physical_mask(max_physical_bits)?;
    let end = address
        .checked_add(size.bytes())
        .ok_or_else(|| entry_error(EptEntryError::PhysicalAddressTooWide))?;
    let limit = 1u64 << max_physical_bits;
    if address & !mask != 0 || end > limit {
        return Err(entry_error(EptEntryError::PhysicalAddressTooWide));
    }
    if !permissions.is_present() {
        return Ok(0);
    }
    let mut raw = u64::from(permissions.read())
        | (u64::from(permissions.write()) << 1)
        | (u64::from(permissions.execute()) << 2)
        | ((memory_type as u64) << 3)
        | address;
    if size != EptLeafSize::Size4K {
        raw |= 1 << 7;
    }
    Ok(raw)
}

macro_rules! table_entry {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(u64);

        impl $name {
            pub fn new_table(hpa: HostPhysicalAddress, max_physical_bits: u8) -> MonadResult<Self> {
                encode_table(hpa, max_physical_bits).map(Self)
            }

            pub const fn not_present() -> Self {
                Self(0)
            }

            pub const fn is_present(self) -> bool {
                self.0 & 0x7 != 0
            }

            pub(super) const fn raw(self) -> u64 {
                self.0
            }
        }
    };
}

table_entry!(EptPml4Entry);
table_entry!(EptPdptEntry);
table_entry!(EptPdEntry);

impl EptPdptEntry {
    pub fn new_1g_leaf(
        hpa: HostPhysicalAddress,
        permissions: EptPermissions,
        memory_type: EptMemoryType,
        max_physical_bits: u8,
    ) -> MonadResult<Self> {
        encode_leaf(
            hpa,
            EptLeafSize::Size1G,
            permissions,
            memory_type,
            max_physical_bits,
        )
        .map(Self)
    }
}

impl EptPdEntry {
    pub fn new_2m_leaf(
        hpa: HostPhysicalAddress,
        permissions: EptPermissions,
        memory_type: EptMemoryType,
        max_physical_bits: u8,
    ) -> MonadResult<Self> {
        encode_leaf(
            hpa,
            EptLeafSize::Size2M,
            permissions,
            memory_type,
            max_physical_bits,
        )
        .map(Self)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptPtEntry(u64);

impl EptPtEntry {
    pub fn new_4k_leaf(
        hpa: HostPhysicalAddress,
        permissions: EptPermissions,
        memory_type: EptMemoryType,
        max_physical_bits: u8,
    ) -> MonadResult<Self> {
        encode_leaf(
            hpa,
            EptLeafSize::Size4K,
            permissions,
            memory_type,
            max_physical_bits,
        )
        .map(Self)
    }

    pub const fn not_present() -> Self {
        Self(0)
    }

    pub const fn is_present(self) -> bool {
        self.0 & 0x7 != 0
    }

    pub(super) const fn raw(self) -> u64 {
        self.0
    }
}

pub(super) fn decode_entry(
    level: EptLevel,
    raw: u64,
    max_physical_bits: u8,
    execute_only_supported: bool,
) -> Result<DecodedEptEntry, EptEntryError> {
    let mask = physical_mask(max_physical_bits).map_err(|_| EptEntryError::InvalidPhysicalWidth)?;
    let permission_bits = raw & 0x7;
    if permission_bits == 0 {
        return if raw == 0 {
            Ok(DecodedEptEntry::NotPresent)
        } else {
            Err(EptEntryError::NonzeroNotPresent)
        };
    }

    let permissions = EptPermissions::new(
        permission_bits & 1 != 0,
        permission_bits & 2 != 0,
        permission_bits & 4 != 0,
        execute_only_supported,
    )
    .map_err(|_| EptEntryError::UnsupportedPermissions)?;
    let large = raw & (1 << 7) != 0;
    let leaf_size = match (level, large) {
        (EptLevel::Pml4, true) | (EptLevel::Pt, true) => {
            return Err(EptEntryError::IllegalLargeLeaf)
        }
        (EptLevel::Pdpt, true) => Some(EptLeafSize::Size1G),
        (EptLevel::Pd, true) => Some(EptLeafSize::Size2M),
        (EptLevel::Pt, false) => Some(EptLeafSize::Size4K),
        _ => None,
    };

    let address = raw & 0x000f_ffff_ffff_f000;
    if address & !mask != 0 {
        return Err(EptEntryError::PhysicalAddressTooWide);
    }

    if let Some(size) = leaf_size {
        let allowed = 0x7 | (0x7 << 3) | address | u64::from(size != EptLeafSize::Size4K) << 7;
        if raw & !allowed != 0 {
            return Err(EptEntryError::ReservedBits);
        }
        if address & (size.bytes() - 1) != 0 {
            return Err(EptEntryError::MisalignedAddress);
        }
        let limit = 1u64 << max_physical_bits;
        if address
            .checked_add(size.bytes())
            .is_none_or(|end| end > limit)
        {
            return Err(EptEntryError::PhysicalAddressTooWide);
        }
        let memory_type = EptMemoryType::try_from(((raw >> 3) & 0x7) as u8)
            .map_err(|_| EptEntryError::InvalidMemoryType)?;
        Ok(DecodedEptEntry::Leaf {
            hpa: HostPhysicalAddress::from_validated(address),
            size,
            permissions,
            memory_type,
        })
    } else {
        let allowed = 0x7 | address;
        if raw & !allowed != 0 {
            return Err(EptEntryError::ReservedBits);
        }
        if address & 0xfff != 0 {
            return Err(EptEntryError::MisalignedAddress);
        }
        Ok(DecodedEptEntry::Table {
            hpa: HostPhysicalAddress::from_validated(address),
            permissions,
        })
    }
}

// layout checks
const _: () = {
    assert!(size_of::<EptPml4Entry>() == size_of::<u64>());
    assert!(size_of::<EptPdptEntry>() == size_of::<u64>());
    assert!(size_of::<EptPdEntry>() == size_of::<u64>());
    assert!(size_of::<EptPtEntry>() == size_of::<u64>());
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ept::PAGE_SIZE_4K;

    fn hpa(value: u64, size: EptLeafSize) -> HostPhysicalAddress {
        HostPhysicalAddress::for_mapping(value, size.bytes(), size.bytes(), 48)
            .expect("valid fixture hpa")
    }

    #[test]
    fn entry_encoding_table() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let all = EptPermissions::new(true, true, true, false).expect("rwx");
        let read = EptPermissions::new(true, false, false, false).expect("read");
        let execute = EptPermissions::new(false, false, true, true).expect("execute-only");
        let none = EptPermissions::new(false, false, false, false).expect("not present");

        let table =
            EptPml4Entry::new_table(hpa(0x2000, EptLeafSize::Size4K), 48).expect("table entry");
        assert_eq!(table.raw(), 0x2007);
        assert!(!EptPml4Entry::not_present().is_present());
        for level in [EptLevel::Pml4, EptLevel::Pdpt, EptLevel::Pd] {
            assert!(matches!(
                decode_entry(level, table.raw(), 48, false),
                Ok(DecodedEptEntry::Table { .. })
            ));
        }

        let cases = [
            (
                EptLevel::Pdpt,
                EptPdptEntry::new_1g_leaf(
                    hpa(0x4000_0000, EptLeafSize::Size1G),
                    all,
                    EptMemoryType::WriteBack,
                    48,
                )
                .expect("1g leaf")
                .raw(),
                EptLeafSize::Size1G,
            ),
            (
                EptLevel::Pd,
                EptPdEntry::new_2m_leaf(
                    hpa(0x20_0000, EptLeafSize::Size2M),
                    read,
                    EptMemoryType::Uncacheable,
                    48,
                )
                .expect("2m leaf")
                .raw(),
                EptLeafSize::Size2M,
            ),
            (
                EptLevel::Pt,
                EptPtEntry::new_4k_leaf(
                    hpa(0x3000, EptLeafSize::Size4K),
                    execute,
                    EptMemoryType::WriteThrough,
                    48,
                )
                .expect("4k leaf")
                .raw(),
                EptLeafSize::Size4K,
            ),
        ];
        for (level, raw, expected_size) in cases {
            match decode_entry(level, raw, 48, true).expect("valid leaf") {
                DecodedEptEntry::Leaf { size, .. } => assert_eq!(size, expected_size),
                other => panic!("expected leaf, got {other:?}"),
            }
        }

        assert_eq!(
            EptPtEntry::new_4k_leaf(
                hpa(0x3000, EptLeafSize::Size4K),
                none,
                EptMemoryType::WriteBack,
                48,
            )
            .expect("not present")
            .raw(),
            0
        );
        for bits in 0u8..8 {
            let read = bits & 1 != 0;
            let write = bits & 2 != 0;
            let execute = bits & 4 != 0;
            let expected_without_execute_only = (!write || read) && (!execute || read);
            assert_eq!(
                EptPermissions::new(read, write, execute, false).is_ok(),
                expected_without_execute_only,
                "permissions {bits:#x}"
            );
            assert_eq!(
                EptPermissions::new(read, write, execute, true).is_ok(),
                !write || read,
                "execute-only permissions {bits:#x}"
            );
            let Ok(permissions) = EptPermissions::new(read, write, execute, true) else {
                continue;
            };
            let leaves = [
                (
                    EptLevel::Pdpt,
                    EptPdptEntry::new_1g_leaf(
                        hpa(0, EptLeafSize::Size1G),
                        permissions,
                        EptMemoryType::WriteBack,
                        48,
                    )
                    .expect("1g permission case")
                    .raw(),
                ),
                (
                    EptLevel::Pd,
                    EptPdEntry::new_2m_leaf(
                        hpa(0, EptLeafSize::Size2M),
                        permissions,
                        EptMemoryType::WriteBack,
                        48,
                    )
                    .expect("2m permission case")
                    .raw(),
                ),
                (
                    EptLevel::Pt,
                    EptPtEntry::new_4k_leaf(
                        hpa(0, EptLeafSize::Size4K),
                        permissions,
                        EptMemoryType::WriteBack,
                        48,
                    )
                    .expect("4k permission case")
                    .raw(),
                ),
            ];
            for (level, raw) in leaves {
                match decode_entry(level, raw, 48, true).expect("permission case") {
                    DecodedEptEntry::NotPresent if bits == 0 => {}
                    DecodedEptEntry::Leaf {
                        permissions: decoded,
                        ..
                    } => assert_eq!(decoded, permissions, "leaf permissions {bits:#x}"),
                    other => panic!("bad leaf permissions {bits:#x}: {other:?}"),
                }
            }
        }
        assert!(decode_entry(EptLevel::Pt, 0x3004, 48, false).is_err());
        assert!(decode_entry(EptLevel::Pml4, 0x2087, 48, false).is_err());
        assert!(decode_entry(EptLevel::Pt, 0x3087, 48, false).is_err());
        assert!(decode_entry(EptLevel::Pt, 0x301f, 48, false).is_err());
        assert!(decode_entry(EptLevel::Pt, 0x3007 | (1 << 8), 48, false).is_err());
        assert!(decode_entry(EptLevel::Pt, 0x3007 | (1 << 52), 48, false).is_err());
        assert!(EptPdEntry::new_2m_leaf(
            HostPhysicalAddress::from_validated(0x1000),
            all,
            EptMemoryType::WriteBack,
            48,
        )
        .is_err());
        assert!(EptPdptEntry::new_1g_leaf(
            HostPhysicalAddress::from_validated(PAGE_SIZE_4K),
            all,
            EptMemoryType::WriteBack,
            48,
        )
        .is_err());
        assert!(EptPtEntry::new_4k_leaf(
            HostPhysicalAddress::from_validated(1),
            all,
            EptMemoryType::WriteBack,
            48,
        )
        .is_err());
        assert!(EptPtEntry::new_4k_leaf(
            HostPhysicalAddress::from_validated(1 << 48),
            all,
            EptMemoryType::WriteBack,
            48,
        )
        .is_err());
        assert!(EptPtEntry::new_4k_leaf(
            HostPhysicalAddress::from_validated(1),
            none,
            EptMemoryType::WriteBack,
            48,
        )
        .is_err());
        assert!(EptPtEntry::new_4k_leaf(
            HostPhysicalAddress::from_validated((1 << 48) - PAGE_SIZE_4K),
            all,
            EptMemoryType::WriteBack,
            48,
        )
        .is_ok());
        assert_eq!(
            decode_entry(
                EptLevel::Pd,
                (1 << 21) | 0x80 | 0x7 | ((EptMemoryType::WriteBack as u64) << 3),
                21,
                false,
            ),
            Err(EptEntryError::PhysicalAddressTooWide)
        );
    }
}
