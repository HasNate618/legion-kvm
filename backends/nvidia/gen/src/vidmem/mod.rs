//! What a video memory limit needs to know about each RM release.

pub mod v535_129_03;
pub mod v580_178_04;
pub mod v595_104_02;
pub mod v595_71_05;
pub mod v610_57_04;
pub mod v615_71_09;
pub mod v615_78_08;

use crate::version::DriverVersion;

/// What an FB_INFO index reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// How much video memory there is.
    Total,
    /// How much of it is free.
    Free,
    /// A carve-out RM keeps out of the heap.
    Reserved,
    /// Where something is, not how much.
    Position,
    /// The CPU's window onto video memory, not video memory.
    Bar1,
}

/// One FB_INFO index that reports video memory, or a window onto it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FbIndex {
    pub name: &'static str,
    pub index: u32,
    pub role: Role,
}

/// A parameter block that carries a list of `NV2080_CTRL_FB_INFO`: its size, and where the count and the list (a pointer for V1, inline for V2) are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct List {
    pub size: u32,
    pub count: u32,
    pub list: u32,
}

/// Where an allocation's fields are in its parameter block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alloc {
    pub h_memory: u32,
    pub flags: u32,
    pub attr: u32,
    pub size: u32,
    pub limit: u32,
}

/// One release's numbers.
#[derive(Debug)]
pub struct Layout {
    /// Every memory-reporting index this release has, classified.
    pub fb_info: &'static [FbIndex],
    /// Indices the generator classifies that this release does not have.
    pub fb_absent: &'static [&'static str],
    pub cmd_fb_get_info: u32,
    pub cmd_fb_get_info_v2: u32,
    pub fb_info_max_list: u32,
    pub fb_info_entry_size: u32,
    pub fb_info_entry_index: u32,
    pub fb_info_entry_data: u32,
    pub fb_get_info_v1: List,
    pub fb_get_info_v2: List,
    pub nvos32_size: u32,
    pub nvos32_function: u32,
    pub nvos32_status: u32,
    /// `INFO`'s answer: the heap's total and free bytes.
    pub nvos32_total: u32,
    pub nvos32_free: u32,
    /// `INFO`'s block: the attributes asked about, and the largest free region's offset and size, and the heap's base.
    pub nvos32_info_attr: u32,
    pub nvos32_info_offset: u32,
    pub nvos32_info_size: u32,
    pub nvos32_info_base: u32,
    pub nvos32_fn_alloc_size: u32,
    pub nvos32_fn_alloc_tiled_pitch_height: u32,
    pub nvos32_fn_alloc_size_range: u32,
    pub nvos32_fn_free: u32,
    pub nvos32_fn_info: u32,
    pub nvos32_fn_hw_alloc: u32,
    pub nvos32_fn_hw_free: u32,
    pub nvos32_alloc_size: Alloc,
    pub nvos32_alloc_tiled_pitch_height: Alloc,
    pub nvos32_alloc_size_range: Alloc,
    /// `sizeof(NV_MEMORY_ALLOCATION_PARAMS)`, and its fields.
    pub mem_alloc_size: u32,
    pub mem_alloc: Alloc,
    /// `NVOS32_ATTR_LOCATION` as (low bit, high bit) of `attr`, and the value that means video memory.
    pub attr_location: (u32, u32),
    pub attr_location_vidmem: u32,
    pub alloc_flags_virtual: u32,
}

impl Layout {
    /// Whether an allocation's `attr` and `flags` take video memory: located in video memory, and not a virtual allocation with no backing.
    pub fn takes_vidmem(&self, attr: u32, flags: u32) -> bool {
        let (lo, hi) = self.attr_location;
        let width = hi - lo + 1;
        let loc = (attr >> lo) & ((1u32 << width) - 1);
        loc == self.attr_location_vidmem && flags & self.alloc_flags_virtual == 0
    }

    /// The index for `name`, if this release has it.
    pub fn index(&self, name: &str) -> Option<u32> {
        self.fb_info
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.index)
    }

    /// The role of FB_INFO index `index`, if it reports memory.
    pub fn role(&self, index: u32) -> Option<Role> {
        self.fb_info
            .iter()
            .find(|i| i.index == index)
            .map(|i| i.role)
    }
}

/// The layout for a host release, and whether it is that release's own.
#[derive(Clone, Copy, Debug)]
pub struct Selected {
    pub layout: &'static Layout,
    pub exact: bool,
}

/// Profiles in ascending version order.
static PROFILES: &[(DriverVersion, &Layout)] = &[
    (DriverVersion::new(535, 129, 3), &v535_129_03::LAYOUT),
    (DriverVersion::new(580, 178, 4), &v580_178_04::LAYOUT),
    (DriverVersion::new(595, 71, 5), &v595_71_05::LAYOUT),
    (DriverVersion::new(595, 104, 2), &v595_104_02::LAYOUT),
    (DriverVersion::new(610, 57, 4), &v610_57_04::LAYOUT),
    (DriverVersion::new(615, 71, 9), &v615_71_09::LAYOUT),
    (DriverVersion::new(615, 78, 8), &v615_78_08::LAYOUT),
];

/// The layout for `v`: its own, or the nearest older release's.
pub fn select(v: DriverVersion) -> Option<Selected> {
    PROFILES
        .iter()
        .rev()
        .find(|(pv, _)| *pv <= v)
        .map(|(pv, l)| Selected {
            layout: l,
            exact: *pv == v,
        })
}

#[cfg(test)]
#[path = "../../tests/unit/vidmem/mod.rs"]
mod tests;
