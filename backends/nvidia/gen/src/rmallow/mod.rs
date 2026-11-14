//! The RM controls and classes a guest may ask for.

pub mod v535_129_03;
pub mod v580_178_04;
pub mod v595_104_02;
pub mod v595_71_05;
pub mod v610_57_04;
pub mod v615_71_09;
pub mod v615_78_08;

use crate::version::DriverVersion;

/// One control RM exports to an unprivileged caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowCtrl {
    pub cmd: u32,
    /// `sizeof` the parameter struct, from a probe compiled against the release's headers.
    pub params_size: u32,
}

impl AllowCtrl {
    pub const fn new(cmd: u32, params_size: u32) -> Self {
        Self { cmd, params_size }
    }
}

/// One class RM lets an unprivileged caller allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowClass {
    pub class_id: u32,
    /// `sizeof` the allocation parameter struct; zero for `RS_NONE`.
    pub params_size: u32,
    /// `RS_REQUIRED` rather than `RS_OPTIONAL`: the allocation parameters have to be there.
    pub params_required: bool,
}

impl AllowClass {
    pub const fn new(class_id: u32, params_size: u32, params_required: bool) -> Self {
        Self {
            class_id,
            params_size,
            params_required,
        }
    }
}

/// One command RM rewrites into a modern one before anything else sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeprecCtrl {
    pub cmd: u32,
    pub params_size: u32,
    pub allowed: bool,
}

impl DeprecCtrl {
    pub const fn new(cmd: u32, params_size: u32, allowed: bool) -> Self {
        Self {
            cmd,
            params_size,
            allowed,
        }
    }
}

/// A class whose control entry point forwards whatever it is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowRange {
    pub class_id: u32,
}

impl AllowRange {
    pub const fn new(class_id: u32) -> Self {
        Self { class_id }
    }

    /// Commands are numbered with their class in the high half.
    pub const fn holds(&self, cmd: u32) -> bool {
        cmd >> 16 == self.class_id
    }
}

/// RM's rule for the commands it no longer implements and forwards to GSP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GssRule {
    pub mask: u32,
    pub privileged: u32,
    pub max_params: u32,
}

impl GssRule {
    pub const fn new(mask: u32, privileged: u32, max_params: u32) -> Self {
        Self {
            mask,
            privileged,
            max_params,
        }
    }

    /// Whether RM takes the GSP branch for this command at all.
    pub const fn holds(&self, cmd: u32) -> bool {
        cmd & self.mask != 0
    }

    /// RM's own test, copied: the privileged bits set in full means root.
    pub const fn needs_root(&self, cmd: u32) -> bool {
        cmd & self.privileged == self.privileged
    }
}

/// What the rule says about a command, when it says yes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtrlAllow {
    /// RM sizes this from its own descriptor, so the block must be exact.
    Exact(u32),
    /// RM forwards this without reading it and only caps it.
    UpTo(u32),
}

/// Controls refused under every cap, whatever RM says about them.
pub static DENY: &[(u32, &str)] = &[
    // The host's process list, through the GPU.
    (0x2080018d, "NV2080_CTRL_CMD_GPU_GET_PIDS"),
    (0x2080018e, "NV2080_CTRL_CMD_GPU_GET_PID_INFO"),
    // GPU accounting: whether it is on, which pids it has recorded, and what it recorded about them.
    (0x00000b02, "NV0000_CTRL_CMD_GPUACCT_GET_ACCOUNTING_STATE"),
    (
        0x00000b03,
        "NV0000_CTRL_CMD_GPUACCT_GET_PROC_ACCOUNTING_INFO",
    ),
    (0x00000b04, "NV0000_CTRL_CMD_GPUACCT_GET_ACCOUNTING_PIDS"),
    (
        0x00000b06,
        "NV0000_CTRL_CMD_GPUACCT_GET_PROC_ACCOUNTING_INFO_V2",
    ),
    // Sub-process identity.
    (0x00000901, "NV0000_CTRL_CMD_SET_SUB_PROCESS_ID"),
    (
        0x00000902,
        "NV0000_CTRL_CMD_DISABLE_SUB_PROCESS_USERD_ISOLATION",
    ),
];

/// Whether this control is refused regardless of table and cap.
pub fn denied(cmd: u32) -> Option<&'static str> {
    DENY.iter().find(|(c, _)| *c == cmd).map(|(_, n)| *n)
}

struct Profile {
    version: DriverVersion,
    /// Functions rather than the slices themselves, for the reason given in [`crate::rmctrl`]: a static read in another static's initializer is const-evaluated and the table can end up copied per use.
    ctrl: fn() -> &'static [AllowCtrl],
    class: fn() -> &'static [AllowClass],
    deprec: fn() -> &'static [DeprecCtrl],
    catch_all: fn() -> &'static [AllowRange],
    gss: fn() -> GssRule,
}

/// Profiles in ascending version order.
static PROFILES: &[Profile] = &[
    Profile {
        version: DriverVersion::new(535, 129, 3),
        ctrl: || v535_129_03::CTRL,
        class: || v535_129_03::CLASS,
        deprec: || v535_129_03::DEPREC,
        catch_all: || v535_129_03::CATCH_ALL,
        gss: || v535_129_03::GSS,
    },
    Profile {
        version: DriverVersion::new(580, 178, 4),
        ctrl: || v580_178_04::CTRL,
        class: || v580_178_04::CLASS,
        deprec: || v580_178_04::DEPREC,
        catch_all: || v580_178_04::CATCH_ALL,
        gss: || v580_178_04::GSS,
    },
    Profile {
        version: DriverVersion::new(595, 71, 5),
        ctrl: || v595_71_05::CTRL,
        class: || v595_71_05::CLASS,
        deprec: || v595_71_05::DEPREC,
        catch_all: || v595_71_05::CATCH_ALL,
        gss: || v595_71_05::GSS,
    },
    Profile {
        version: DriverVersion::new(595, 104, 2),
        ctrl: || v595_104_02::CTRL,
        class: || v595_104_02::CLASS,
        deprec: || v595_104_02::DEPREC,
        catch_all: || v595_104_02::CATCH_ALL,
        gss: || v595_104_02::GSS,
    },
    Profile {
        version: DriverVersion::new(610, 57, 4),
        ctrl: || v610_57_04::CTRL,
        class: || v610_57_04::CLASS,
        deprec: || v610_57_04::DEPREC,
        catch_all: || v610_57_04::CATCH_ALL,
        gss: || v610_57_04::GSS,
    },
    Profile {
        version: DriverVersion::new(615, 71, 9),
        ctrl: || v615_71_09::CTRL,
        class: || v615_71_09::CLASS,
        deprec: || v615_71_09::DEPREC,
        catch_all: || v615_71_09::CATCH_ALL,
        gss: || v615_71_09::GSS,
    },
    Profile {
        version: DriverVersion::new(615, 78, 8),
        ctrl: || v615_78_08::CTRL,
        class: || v615_78_08::CLASS,
        deprec: || v615_78_08::DEPREC,
        catch_all: || v615_78_08::CATCH_ALL,
        gss: || v615_78_08::GSS,
    },
];

/// The allowlist for one host release.
#[derive(Clone, Copy)]
pub struct Selected {
    pub ctrl: &'static [AllowCtrl],
    pub class: &'static [AllowClass],
    pub deprec: &'static [DeprecCtrl],
    pub catch_all: &'static [AllowRange],
    pub gss: GssRule,
    /// The host release has tables of its own.
    pub exact: bool,
}

/// The tables for a host driver version: its own, or the nearest older ones.
pub fn select(v: DriverVersion) -> Option<Selected> {
    PROFILES
        .iter()
        .rev()
        .find(|p| p.version <= v)
        .map(|p| Selected {
            ctrl: (p.ctrl)(),
            class: (p.class)(),
            deprec: (p.deprec)(),
            catch_all: (p.catch_all)(),
            gss: (p.gss)(),
            exact: p.version == v,
        })
}

fn find_ctrl(table: &'static [AllowCtrl], cmd: u32) -> Option<&'static AllowCtrl> {
    table
        .binary_search_by_key(&cmd, |e| e.cmd)
        .ok()
        .map(|i| &table[i])
}

fn find_deprec(table: &'static [DeprecCtrl], cmd: u32) -> Option<&'static DeprecCtrl> {
    table
        .binary_search_by_key(&cmd, |e| e.cmd)
        .ok()
        .map(|i| &table[i])
}

fn find_class(table: &'static [AllowClass], class_id: u32) -> Option<&'static AllowClass> {
    table
        .binary_search_by_key(&class_id, |e| e.class_id)
        .ok()
        .map(|i| &table[i])
}

impl Selected {
    /// What the rule says about this control, in the order RM asks.
    pub fn ctrl_rule(&self, cmd: u32) -> Option<CtrlAllow> {
        if denied(cmd).is_some() {
            return None;
        }
        if let Some(e) = find_deprec(self.deprec, cmd) {
            if !e.allowed || !self.agreed(|p| find_deprec((p.deprec)(), cmd) == Some(e)) {
                return None;
            }
            return Some(CtrlAllow::Exact(e.params_size));
        }
        if self.gss.holds(cmd) {
            // Only the privilege bits have to agree.
            let same = |p: &Profile| {
                let g = (p.gss)();
                g.mask == self.gss.mask && g.privileged == self.gss.privileged
            };
            if self.gss.needs_root(cmd) || !self.agreed(same) {
                return None;
            }
            return Some(CtrlAllow::UpTo(self.max_params()));
        }
        if let Some(e) = find_ctrl(self.ctrl, cmd) {
            if !self.agreed(|p| {
                find_ctrl((p.ctrl)(), cmd).is_some_and(|o| o.params_size == e.params_size)
            }) {
                return None;
            }
            return Some(CtrlAllow::Exact(e.params_size));
        }
        // No exported-method entry anywhere.
        let r = self.catch_all.iter().find(|r| r.holds(cmd))?;
        if !self.agreed(|p| (p.catch_all)().contains(r)) {
            return None;
        }
        Some(CtrlAllow::UpTo(self.max_params()))
    }

    /// The largest parameter block RM will copy for an unprivileged caller: this release's own number, or the smallest any release gives when the tables are not the host's. 535.129.03 enforces no ceiling on the GSP path at all.
    pub fn max_params(&self) -> u32 {
        if self.exact {
            return self.gss.max_params;
        }
        PROFILES
            .iter()
            .map(|p| (p.gss)().max_params)
            .min()
            .unwrap_or(self.gss.max_params)
    }

    /// True if the host release has its own tables, or every release agrees.
    fn agreed(&self, f: impl Fn(&Profile) -> bool) -> bool {
        self.exact || PROFILES.iter().all(f)
    }

    /// The entry permitting this class, under the same rule.
    pub fn class_entry(&self, class_id: u32) -> Option<&'static AllowClass> {
        let e = find_class(self.class, class_id)?;
        self.agreed(|p| find_class((p.class)(), class_id).is_some_and(|o| o == e))
            .then_some(e)
    }
}

/// The versions with tables of their own, ascending.
pub fn supported_versions() -> impl Iterator<Item = DriverVersion> {
    PROFILES.iter().map(|p| p.version)
}

#[cfg(test)]
#[path = "../../tests/unit/rmallow/mod.rs"]
mod tests;
