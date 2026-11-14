//! RM controls whose parameters carry a pointer RM dereferences.

pub mod v535_129_03;
pub mod v580_178_04;
pub mod v595_104_02;
pub mod v595_71_05;
pub mod v610_57_04;
pub mod v615_71_09;
pub mod v615_78_08;

use crate::version::DriverVersion;

/// The most bytes one embedded pointer may address.
pub const MAX_EMBEDDED_BYTES: usize = 1 << 20;

/// How many elements an embedded pointer addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Count {
    /// A constant, from the call site in RM.
    Fixed(u64),
    /// Read from a field of the parameter block.
    Field { offset: usize, width: usize },
    /// Read from a field and squared: `NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS` addresses a `gpuCount` x `gpuCount` matrix.
    Squared { offset: usize, width: usize },
}

impl Count {
    /// The element count for one call, read out of its parameter block.
    pub fn elements(self, params: &[u8]) -> Option<u64> {
        let read = |offset: usize, width: usize| -> Option<u64> {
            let end = offset.checked_add(width)?;
            let b = params.get(offset..end)?;
            Some(match width {
                1 => b[0] as u64,
                2 => u16::from_le_bytes(b.try_into().ok()?) as u64,
                4 => u32::from_le_bytes(b.try_into().ok()?) as u64,
                8 => u64::from_le_bytes(b.try_into().ok()?),
                _ => return None,
            })
        };
        match self {
            Count::Fixed(n) => Some(n),
            Count::Field { offset, width } => read(offset, width),
            Count::Squared { offset, width } => {
                let n = read(offset, width)?;
                n.checked_mul(n)
            }
        }
    }
}

/// One pointer inside a control's parameter block.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedPtr {
    /// Where the `NvP64` sits in the parameter block.
    pub ptr_offset: usize,
    pub count: Count,
    pub elem_size: usize,
    /// RM reads the caller's buffer before the control runs.
    pub copy_in: bool,
    /// RM writes it back afterwards.
    pub copy_out: bool,
}

impl EmbeddedPtr {
    /// How many bytes this pointer addresses for one call.
    pub fn bytes(&self, params: &[u8]) -> Option<usize> {
        let n = self.count.elements(params)?;
        let bytes = n.checked_mul(self.elem_size as u64)?;
        let bytes = usize::try_from(bytes).ok()?;
        (bytes <= MAX_EMBEDDED_BYTES).then_some(bytes)
    }
}

/// One control, as one driver release lays it out.
pub struct RmCtrlEntry {
    /// The `NVXXXX_CTRL_CMD_*` value, as it arrives in `NVOS54.cmd`.
    pub cmd: u32,
    /// `sizeof` the parameter struct.
    pub params_size: usize,
    pub ptrs: &'static [EmbeddedPtr],
    /// The generator could not describe this control.
    pub refuse: bool,
}

struct Profile {
    version: DriverVersion,
    /// A function rather than the slice itself, as in `versions`: a static read in another static's initializer is const-evaluated, and the generated table can end up copied per use rather than shared.
    table: fn() -> &'static [RmCtrlEntry],
}

/// Profiles in ascending version order.
static PROFILES: &[Profile] = &[
    Profile {
        version: DriverVersion::new(535, 129, 3),
        table: || v535_129_03::TABLE,
    },
    Profile {
        version: DriverVersion::new(580, 178, 4),
        table: || v580_178_04::TABLE,
    },
    Profile {
        version: DriverVersion::new(595, 71, 5),
        table: || v595_71_05::TABLE,
    },
    Profile {
        version: DriverVersion::new(595, 104, 2),
        table: || v595_104_02::TABLE,
    },
    Profile {
        version: DriverVersion::new(610, 57, 4),
        table: || v610_57_04::TABLE,
    },
    Profile {
        version: DriverVersion::new(615, 71, 9),
        table: || v615_71_09::TABLE,
    },
    Profile {
        version: DriverVersion::new(615, 78, 8),
        table: || v615_78_08::TABLE,
    },
];

/// A table, and whether it is the host release's own.
#[derive(Clone, Copy)]
pub struct Selected {
    pub table: &'static [RmCtrlEntry],
    /// The host release has a table of its own.
    pub exact: bool,
}

/// The table for a host driver version: its own, or the nearest older one.
pub fn select(v: DriverVersion) -> Option<Selected> {
    PROFILES
        .iter()
        .rev()
        .find(|p| p.version <= v)
        .map(|p| Selected {
            table: (p.table)(),
            exact: p.version == v,
        })
}

/// As [`select`], for callers that only want the table.
pub fn table_for(v: DriverVersion) -> Option<&'static [RmCtrlEntry]> {
    select(v).map(|s| s.table)
}

/// Whether any release here describes this control as carrying a pointer.
pub fn in_any_table(cmd: u32) -> bool {
    PROFILES.iter().any(|p| lookup((p.table)(), cmd).is_some())
}

/// Look up one control.
pub fn lookup(table: &'static [RmCtrlEntry], cmd: u32) -> Option<&'static RmCtrlEntry> {
    table
        .binary_search_by_key(&cmd, |e| e.cmd)
        .ok()
        .map(|i| &table[i])
}

/// The versions with a table of their own, ascending.
pub fn supported_versions() -> impl Iterator<Item = DriverVersion> {
    PROFILES.iter().map(|p| p.version)
}

#[cfg(test)]
#[path = "../../tests/unit/rmctrl/mod.rs"]
mod tests;
