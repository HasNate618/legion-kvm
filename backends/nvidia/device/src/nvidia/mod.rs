//! The backend: one guest's view of the host NVIDIA driver.
use protocol::messages::*;
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::error::{DeviceError, Result};
use crate::handle_table::HandleTable;
use crate::shm::{ShmAllocator, ZoneConfig};

// ============================================================ Device path helpers ============================================================

const MAX_GPU: u8 = 8;

/// Field offsets in NVOS54_PARAMETERS, the struct RM_CONTROL carries.
const DEEP_BUF_FLOOR: usize = 64 * 1024;

/// `NVOS64_PARAMETERS.status`, where RM writes its answer to an allocation.
const NVOS64_STATUS: usize = 40;
/// RM_ALLOC classes that make a client rather than an object in one.
const ROOT_CLASSES: [u32; 3] = [0x0, 0x1, 0x41];

const NVOS54_CMD: usize = 8;
const NVOS54_PARAMS_SIZE: usize = 24;
const NVOS54_STATUS: usize = 28;
const NVOS54_TOTAL: usize = 32;

/// `NV_OK`.
const NV_OK: u32 = 0;

/// Resolve a host path and optional DRM render node.
fn device_path_with(device_type: u32, dri: &[DriDevice]) -> Result<CString> {
    let kind = DeviceKind::from_device_type(device_type)
        .ok_or(DeviceError::InvalidDeviceKind(device_type))?;
    let path = match kind {
        DeviceKind::Gpu(n) => {
            if n >= MAX_GPU as u32 {
                return Err(DeviceError::GpuIndexOutOfRange(n));
            }
            format!("/dev/nvidia{n}")
        }
        DeviceKind::Ctl => "/dev/nvidiactl".to_string(),
        DeviceKind::Uvm => "/dev/nvidia-uvm".to_string(),
        DeviceKind::UvmTools => "/dev/nvidia-uvm-tools".to_string(),
        DeviceKind::Modeset => "/dev/nvidia-modeset".to_string(),
        DeviceKind::Dri(n) => {
            let d = dri
                .get(n as usize)
                .ok_or(DeviceError::InvalidDeviceKind(device_type))?;
            format!("/dev/dri/{}", d.name)
        }
    };
    Ok(CString::new(path).expect("a device path has no interior NUL"))
}

/// Backend-side result codes, mapped to the errno the guest driver sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    InvalidMsgType,
    InvalidDevice,
    OpenFailed,
    BadHandle,
    IoctlFailed,
    BufferTooSmall,
}

impl Status {
    fn errno(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::InvalidMsgType => libc::EPROTO,
            Self::InvalidDevice => libc::ENODEV,
            Self::OpenFailed => libc::EIO,
            Self::BadHandle => libc::EBADF,
            Self::IoctlFailed => libc::EIO,
            Self::BufferTooSmall => libc::ENOSPC,
        }
    }
}

/// A DRM render node the host owns, as the guest is told about it.
#[derive(Clone)]
struct DriDevice {
    name: String,
    major: u32,
    minor: u32,
    /// Which GPU slot it belongs to.
    slot_index: u32,
    /// `DRM_NVIDIA_GET_DEV_INFO` as the host's own node answers it, passed through rather than reconstructed.
    dev_info: [u32; NV_DEV_INFO_WORDS],
}

/// `struct drm_nvidia_get_dev_info_params` is nine `u32`s.
const NV_DEV_INFO_WORDS: usize = 9;

/// `_IOWR('d', DRM_COMMAND_BASE + DRM_NVIDIA_GET_DEV_INFO, params)`, i.e. direction read|write, 36 bytes, type 'd', nr 0x43.
const DRM_IOCTL_NVIDIA_GET_DEV_INFO: libc::Ioctl = 0xC024_6443_u32 as libc::Ioctl;

/// Ask a host render node what it is.
fn host_dev_info(path: &str) -> Option<[u32; NV_DEV_INFO_WORDS]> {
    let c_path = CString::new(path).ok()?;
    // SAFETY: a NUL-terminated path, and the fd is closed below.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        log::warn!(
            "{path}: cannot open to ask what it is ({})",
            std::io::Error::last_os_error()
        );
        return None;
    }
    let mut params = [0u32; NV_DEV_INFO_WORDS];
    // SAFETY: `params` is exactly the 36 bytes the ioctl's size field declares.
    let rc = unsafe {
        libc::ioctl(
            fd,
            DRM_IOCTL_NVIDIA_GET_DEV_INFO,
            params.as_mut_ptr() as *mut libc::c_void,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: fd came from open() above and is not used again.
    unsafe { libc::close(fd) };
    if rc != 0 {
        log::warn!("{path}: GET_DEV_INFO refused ({err})");
        return None;
    }
    Some(params)
}

// ============================================================ NvidiaBackend ============================================================

pub struct NvidiaBackend {
    /// The message being served, so a response can echo its type, and the handle it named, so handlers need not thread either through.
    current_msg: MsgType,
    current_handle: u32,
    /// Top-level parameter length of the ioctl being served.
    current_data_len: u32,
    handles: HandleTable,
    shm: ShmAllocator,
    /// Active RM_MAP_MEMORY mappings, keyed by SHM offset.
    active_maps: crate::mmap::MmapContext,
    /// Which device each open handle names, for mappings made without one.
    handle_kinds: std::collections::HashMap<u64, DeviceKind>,
    /// Host driver version, learned from the first successful `NV_ESC_CHECK_VERSION_STR`.
    driver: Option<abi::version::DriverVersion>,
    /// ABI profile selected for `driver`, if one exists.
    abi: Option<&'static [abi::versions::IoctlEntry]>,
    /// The RM controls whose parameters carry a pointer RM dereferences, for `driver`, and whether the table is this release's own.
    rmctrl: Option<abi::rmctrl::Selected>,
    /// The controls and classes RM exports to an unprivileged caller, for `driver`, and whether the tables are this release's own.
    rmallow: Option<abi::rmallow::Selected>,
    /// The UVM commands the host release defines, their sizes, and where the descriptors sit in them.
    uvm: Option<abi::uvm::Selected>,
    /// Where the host release keeps the CPU address on each of the three routes that let a caller name memory by one.
    osdesc: Option<abi::osdesc::OsDesc>,
    /// Where an allocation's size is and what tells the guest how much video memory there is, for this release.
    vidmem: Option<abi::vidmem::Selected>,
    /// NVOS32 FREE calls seen.
    vidmem_untracked_frees: u64,
    /// Guest RAM, as something to map from.
    guest_ram: Option<Box<dyn crate::guestmem::GuestRam>>,
    /// How many registrations by address were served, and how many bytes they covered at their peak.
    registrations_served: u64,
    registrations_peak: usize,
    /// Guest memory registered with RM by address, by the client and object handle that own it.
    registrations: std::collections::HashMap<(u32, u32), (u64, crate::guestmem::Stitched)>,
    /// UVM files whose VA space was found to allow pageable access on a release with no flag to forbid it.
    uvm_denied: std::collections::HashSet<u64>,
    /// Controls and classes refused by the RM allowlist, by what was asked for and why.
    allow_refused: std::collections::BTreeMap<String, u64>,
    /// Where device memory is placed so the guest can address it.
    window: Option<Box<dyn crate::shm::WindowPlacer>>,
    legion_display: Option<legion_display::Display>,
    legion_fences: legion_fence::Fences,
    /// Window placements made for a DRM object, keyed by the node handle and the object's mmap offset on the host.
    dri_maps: std::collections::HashMap<(u64, u64), u32>,
    /// The render nodes the guest was told of, by the index it opens them by.
    dri_given: std::cell::RefCell<Option<Vec<DriDevice>>>,
    /// UVM semaphore pools placed in the aperture.
    aperture: aperture::Aperture,
    /// Every message this backend has served, by kind.
    msg_counts: std::collections::BTreeMap<&'static str, u64>,
    /// Every live placement, by the id the guest quotes to take it back.
    live_maps: std::collections::HashMap<u32, LiveMap>,
    /// Guarded buffers for parameter blocks, reused across calls.
    guards: std::cell::RefCell<crate::guarded::GuardPool>,
    /// What this guest is served.
    caps: crate::caps::Caps,
    /// Opens and allocations refused because their capability is off, by what was asked for.
    caps_refused: std::collections::BTreeMap<String, u64>,
    /// Every `RM_ALLOC` class and `RM_CONTROL` command a workload asked for, and how often.
    rm_classes: std::collections::BTreeMap<u32, u64>,
    rm_controls: std::collections::BTreeMap<u32, u64>,
    /// Every ioctl forwarded, by namespace and number.
    ioctls_by_ns: std::collections::BTreeMap<(char, u32), u64>,
    /// Escapes that failed the check, and how often, so a run can say what a workload actually needed.
    abi_refused: std::collections::BTreeMap<u32, u64>,
    /// Descriptors opened and closed since a transport last asked, so it can keep a poll set in step with them.
    watch_added: Vec<(u32, RawFd)>,
    watch_removed: Vec<u32>,
    memory_cache: legion_memory_cache::CachedObjects,
    next_mapping_id: u32,
    /// Where forwarded ioctls go.
    host: Box<dyn HostDriver>,
    /// Video memory charged to this guest, against its limit.
    vram: crate::vram::Vram,
}

/// A placement the guest can hand back, and everything needed to undo it.
struct LiveMap {
    key: (u64, u64),
    region: crate::shm::ShmRegion,
    length: u64,
}

/// `NvKmsIoctlCommand::NVKMS_IOCTL_REGISTER_SURFACE`, the one that names the memory it registers by a file descriptor.
const NVKMS_REGISTER_SURFACE: u32 = 17;
/// Byte offset of `planes[0].u` inside `NvKmsRegisterSurfaceRequest`.
const NVKMS_SURFACE_FD_OFFSET: usize = 16;

/// The result of checking one guest ioctl against the host's ABI profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiCheck {
    /// The escape is known and the guest's parameter size matches.
    Ok,
    /// No profile yet -- CHECK_VERSION_STR has not been seen.
    NoProfile,
    /// The escape is not in this driver's table.
    UnknownEscape,
    /// The escape is variable length; there is no size to check.
    VariableLength,
    /// The guest disagrees with the host ABI about this struct's size.
    SizeMismatch { expected: u32, actual: u32 },
}
impl NvidiaBackend {
    /// Create a backend with a custom SHM zone config.
    pub fn new(cfg: ZoneConfig) -> Self {
        // RM_MAP_MEMORY returns this window offset as a non-null pointer cookie.
        let first_kind = if cfg.uc_size != 0 {
            crate::shm::PgprotKind::Uncached
        } else if cfg.wc_size != 0 {
            crate::shm::PgprotKind::WriteCombine
        } else {
            crate::shm::PgprotKind::WriteBack
        };
        let mut shm = ShmAllocator::new(cfg);
        let null_cookie = shm
            .alloc(4096, first_kind)
            .expect("nonempty page-aligned window has a first page");
        debug_assert_eq!(null_cookie.offset, 0);
        Self {
            window: None,
            legion_display: None,
            legion_fences: Default::default(),
            dri_maps: std::collections::HashMap::new(),
            aperture: Default::default(),
            dri_given: Default::default(),
            msg_counts: std::collections::BTreeMap::new(),
            live_maps: std::collections::HashMap::new(),
            guards: Default::default(),
            rmctrl: None,
            caps: crate::caps::Caps::DEFAULT,
            caps_refused: std::collections::BTreeMap::new(),
            vram: crate::vram::Vram::new(None),
            rmallow: None,
            uvm: None,
            osdesc: None,
            vidmem: None,
            vidmem_untracked_frees: 0,
            guest_ram: None,
            registrations: std::collections::HashMap::new(),
            registrations_served: 0,
            registrations_peak: 0,
            uvm_denied: std::collections::HashSet::new(),
            allow_refused: std::collections::BTreeMap::new(),
            abi_refused: std::collections::BTreeMap::new(),
            rm_classes: std::collections::BTreeMap::new(),
            rm_controls: std::collections::BTreeMap::new(),
            ioctls_by_ns: std::collections::BTreeMap::new(),
            watch_added: Vec::new(),
            watch_removed: Vec::new(),
            memory_cache: legion_memory_cache::CachedObjects::default(),
            next_mapping_id: 1,
            current_msg: MsgType::Ioctl,
            current_handle: 0,
            current_data_len: 0,
            handles: HandleTable::new(),
            shm,
            active_maps: crate::mmap::MmapContext::new(),
            handle_kinds: std::collections::HashMap::new(),
            driver: None,
            abi: None,
            host: Box::new(RealHost),
        }
    }

    /// Send every forwarded ioctl to `host` instead of the host driver.
    pub fn set_host(&mut self, host: Box<dyn HostDriver>) {
        self.host = host;
    }

    /// Create a backend with the default 256 MiB zone split.
    pub fn with_default_zones() -> Self {
        Self::new(ZoneConfig::default_1gib())
    }

    /// Total SHM BAR size (for VMM config space).
    pub fn shm_total_size(&self) -> u64 {
        self.shm.total_size()
    }

    /// Raw memfd fd (for KVM memslot creation).
    pub fn shm_memfd_raw(&self) -> i32 {
        self.shm.memfd_raw()
    }

    /// Choose what this guest is served.
    pub fn set_caps(&mut self, caps: crate::caps::Caps) {
        self.caps = caps;
    }

    pub fn caps(&self) -> crate::caps::Caps {
        self.caps
    }

    /// Set the guest's video-memory budget.
    pub fn set_vram_limit_mib(&mut self, mib: Option<u64>) -> std::result::Result<(), String> {
        if mib.is_some() && !self.vidmem.is_some_and(|s| s.exact) {
            return Err(match self.driver {
                Some(v) => format!(
                    "--vram-limit-mib: host driver {v} has no video-memory table of its own"
                ),
                None => "--vram-limit-mib: the host driver release is not known yet".to_string(),
            });
        }
        self.vram = crate::vram::Vram::new(mib);
        Ok(())
    }

    /// The budget this backend enforces, in MiB; 0 when there is none.
    pub fn vram_limit_mib(&self) -> u64 {
        self.vram.limit_mib()
    }

    /// Count a refusal for want of a capability, and say which one once.
    fn refuse_for_caps(&mut self, what: String, needs: &str) {
        let n = self.caps_refused.entry(what.clone()).or_insert(0);
        if *n == 0 {
            log::warn!(
                "{what} refused: needs --caps {needs} (serving {})",
                self.caps
            );
        }
        *n += 1;
    }

    /// The host driver's release, from the host itself: the ABI profile is chosen from it before the first guest message, so no guest ioctl is ever served without one.
    pub fn set_host_driver_version(
        &mut self,
        v: abi::version::DriverVersion,
    ) -> std::result::Result<(), String> {
        let Some(t) = abi::versions::table_for(v) else {
            return Err(format!("host driver {v} is older than every ABI profile"));
        };
        self.driver = Some(v);
        self.abi = Some(t);
        // Without a table nothing can be said about which controls carry a pointer RM dereferences, and the backend would forward all of them.
        let Some(sel) = abi::rmctrl::select(v) else {
            return Err(format!("host driver {v} has no RM pointer table"));
        };
        self.rmctrl = Some(sel);
        // Likewise for the allowlist: without it the backend would forward every control RM is willing to run for a service account, which is most of them.
        let Some(allow) = abi::rmallow::select(v) else {
            return Err(format!("host driver {v} has no RM allowlist"));
        };
        self.rmallow = Some(allow);
        // And for UVM.
        let Some(uvm) = abi::uvm::select(v) else {
            return Err(format!("host driver {v} has no UVM command table"));
        };
        self.uvm = Some(uvm);
        // And the routes that name memory by a CPU address, so they can be recognised and refused.
        let Some(osdesc) = abi::osdesc::select(v) else {
            return Err(format!("host driver {v} has no OS-descriptor table"));
        };
        self.osdesc = Some(osdesc);
        self.vidmem = abi::vidmem::select(v);
        log::info!(
            "host driver {v}: {} RM controls carry a pointer RM dereferences",
            sel.table.len()
        );
        log::info!(
            "host driver {v}: RM exports {} controls and {} classes to an unprivileged caller, \
             less {} refused under every cap",
            allow.ctrl.len(),
            allow.class.len(),
            abi::rmallow::DENY.len()
        );
        if !sel.exact {
            // The table is an older release's.
            log::warn!(
                "host driver {v} has no RM pointer table of its own; using an older release's, \
                 and refusing every control another release describes that it does not"
            );
        }
        log::info!("host driver {v}: ABI profile selected, {} escapes", t.len());
        Ok(())
    }

    /// Descriptors opened and closed since this was last called.
    pub fn poll_handle_is_live(&self, handle: u32) -> bool {
        self.handles.get_raw(u64::from(handle)).is_ok()
    }

    pub fn take_watch_updates(&mut self) -> (Vec<(u32, RawFd)>, Vec<u32>) {
        (
            std::mem::take(&mut self.watch_added),
            std::mem::take(&mut self.watch_removed),
        )
    }

    /// Give the backend somewhere to place device memory.
    pub fn set_window(&mut self, placer: Box<dyn crate::shm::WindowPlacer>) {
        self.window = Some(placer);
    }

    /// Guest RAM, from the transport, which is the only part that has it.
    pub fn set_guest_ram(&mut self, ram: Box<dyn crate::guestmem::GuestRam>) {
        self.guest_ram = Some(ram);
    }

    /// How many host descriptors the guest currently holds open.
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }

    /// How many registrations by address the guest is holding host mappings for.
    pub fn registration_count(&self) -> usize {
        self.registrations.len()
    }

    /// Free bytes per SHM zone, as `(uc, wc, wb)`.
    pub fn shm_free_bytes(&self) -> (u64, u64, u64) {
        self.shm.free_bytes()
    }

    fn release_mapped_region(&mut self, region: &crate::shm::ShmRegion) -> Result<()> {
        // An external VMM owns a separate mapping.
        if let Some(window) = self.window.as_ref() {
            window.withdraw(region.offset, region.length)?;
        }
        self.shm.free(region)
    }

    pub fn shm_base_ptr(&self) -> *mut u8 {
        self.shm.base_ptr()
    }

    /// Override the SHM base pointer to the guest memory HVA.
    pub fn set_shm_base(&mut self, ptr: *mut u8) {
        self.shm.set_base_ptr(ptr);
    }

    // ------------------------------------------------------------------ Teardown Called by the VMM on: - normal VM shutdown (virtio device reset before exit) - ungraceful VM exit (SIGKILL, crash, libkrun teardown) Draining the handle table closes every host fd, which triggers the host NVIDIA driver's fd-release path and frees all RM objects.

    pub fn teardown(&mut self) {
        log::info!(
            "NvidiaBackend::teardown: video memory {} MiB in use, peak {} MiB, {} allocation(s) refused, limit {}",
            self.vram.in_use() >> 20,
            self.vram.peak() >> 20,
            self.vram.refused(),
            match self.vram.limit() {
                Some(l) => format!("{} MiB", l >> 20),
                None => "none".to_string(),
            }
        );
        if self.vidmem_untracked_frees > 0 {
            log::warn!(
                "NvidiaBackend::teardown: {} VID_HEAP_CONTROL FREE call(s) not charged back",
                self.vidmem_untracked_frees
            );
        }
        for (id, pool) in self.aperture.take_all() {
            self.unmap_uvm_pool(id, pool);
        }
        log::info!(
            "NvidiaBackend::teardown: draining {} handles, {} active maps",
            self.handles.len(),
            self.active_maps.len()
        );
        if !self.allow_refused.is_empty() {
            log::warn!(
                "NvidiaBackend::teardown: refused by the RM allowlist: {}",
                self.allow_refused
                    .iter()
                    .map(|(k, n)| format!("{k} x{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        // Guest memory this process still has mapped after RM has been told to let go of it.
        if self.registrations_served > 0 || !self.registrations.is_empty() {
            let left = self.registrations.len();
            let line = format!(
                "NvidiaBackend::teardown: {} registration(s) by address, at most {} held at once, {left} still held",
                self.registrations_served, self.registrations_peak,
            );
            if left == 0 {
                log::info!("{line}");
            } else {
                log::warn!("{line} -- guest memory is still mapped here");
            }
        }
        if !self.caps_refused.is_empty() {
            log::warn!(
                "NvidiaBackend::teardown: refused for want of a capability: {}",
                self.caps_refused
                    .iter()
                    .map(|(w, n)| format!("{w}={n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        if !self.abi_refused.is_empty() {
            log::warn!(
                "NvidiaBackend::teardown: refused {} ioctl(s) the ABI profile does not describe: {}",
                self.abi_refused.values().sum::<u64>(),
                self.abi_refused
                    .iter()
                    .map(|(e, n)| format!("{e:#04x}={n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        // The whole forwarded surface, by namespace.
        if !self.ioctls_by_ns.is_empty() {
            let mut by_ns: std::collections::BTreeMap<char, Vec<String>> = Default::default();
            for ((ns, nr), n) in &self.ioctls_by_ns {
                by_ns.entry(*ns).or_default().push(format!("{nr:#04x}={n}"));
            }
            for (ns, entries) in by_ns {
                let what = match ns {
                    'F' => "nvidia escapes",
                    'd' => "DRM ioctls",
                    'm' => "modeset ioctls",
                    'u' => "UVM ioctls",
                    _ => "unknown namespace",
                };
                log::info!(
                    "NvidiaBackend::teardown: {} {what} ({}): {}",
                    entries.len(),
                    ns,
                    entries.join(" ")
                );
            }
        }

        // The two sets a filter would be written from.
        if !self.rm_classes.is_empty() {
            log::info!(
                "NvidiaBackend::teardown: {} RM_ALLOC class(es): {}",
                self.rm_classes.len(),
                self.rm_classes
                    .iter()
                    .map(|(c, n)| format!("{c:#06x}={n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        if !self.rm_controls.is_empty() {
            log::info!(
                "NvidiaBackend::teardown: {} RM_CONTROL command(s): {}",
                self.rm_controls.len(),
                self.rm_controls
                    .iter()
                    .map(|(c, n)| format!("{c:#010x}={n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        let total: u64 = self.msg_counts.values().sum();
        log::info!(
            "NvidiaBackend::teardown: served {total} message(s): {}",
            self.msg_counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        // Restore SHM backing and reclaim every extent before closing host fds.
        let leftovers: Vec<_> = self
            .active_maps
            .drain()
            .into_iter()
            .map(|e| e.region)
            .collect();
        for region in leftovers {
            if let Err(e) = self.release_mapped_region(&region) {
                log::warn!(
                    "teardown: SHM free of {:#x}+{:#x} failed: {}",
                    region.offset,
                    region.length,
                    e
                );
            }
        }
        self.legion_display.take();
        self.legion_fences.clear();
        self.handles.drain_all();
    }

    // ------------------------------------------------------------------ Top-level dispatch ------------------------------------------------------------------

    pub fn dispatch(&mut self, req_buf: &[u8], resp_buf: &mut [u8]) -> usize {
        if req_buf.len() < size_of::<MsgHeader>() {
            return self.write_error_resp(resp_buf, Status::InvalidMsgType, 0, 0);
        }
        let hdr = read_struct::<MsgHeader>(req_buf, 0);

        let Some(msg_type) = MsgType::from_u32(hdr.msg_type) else {
            log::warn!("unknown msg_type {}", hdr.msg_type);
            self.current_msg = MsgType::Ioctl;
            return self.write_error_resp(resp_buf, Status::InvalidMsgType, 0, 0);
        };
        self.current_msg = msg_type;
        *self
            .msg_counts
            .entry(match msg_type {
                MsgType::Open => "open",
                MsgType::Close => "close",
                MsgType::Ioctl => "ioctl",
                MsgType::Mmap => "mmap",
                MsgType::Munmap => "munmap",
                MsgType::GetProcFiles => "get_proc_files",
                MsgType::GetSysFiles => "get_sys_files",
                MsgType::EventReady => "event_ready",
            })
            .or_insert(0) += 1;
        // The handle travels in the header, not the payload -- every message after Open acts on one, and Open's response returns one the same way.
        self.current_handle = hdr.handle;

        let payload = &req_buf[size_of::<MsgHeader>()..];
        match msg_type {
            MsgType::Open => self.handle_open(0, payload, resp_buf),
            MsgType::Close => self.handle_close(0, payload, resp_buf),
            MsgType::Ioctl => self.handle_ioctl(0, payload, resp_buf),
            MsgType::Mmap => self.handle_mmap(payload, resp_buf),
            MsgType::Munmap => self.handle_munmap(payload, resp_buf),
            MsgType::GetProcFiles => self.handle_get_files(FileTree::Proc, resp_buf),
            MsgType::GetSysFiles => self.handle_get_files(FileTree::Sys, resp_buf),
            // Host to guest only.
            MsgType::EventReady => {
                log::warn!("EventReady arrived from the guest; that message only travels outward");
                self.write_error_resp(resp_buf, Status::InvalidMsgType, 0, libc::EINVAL)
            }
        }
    }
}

/// Close whatever the guest left open.
impl Drop for NvidiaBackend {
    fn drop(&mut self) {
        if !self.handles.is_empty() {
            log::warn!(
                "NvidiaBackend dropped with {} handles still open — \
                 call teardown() before dropping for clean shutdown",
                self.handles.len()
            );
            self.handles.drain_all();
        }
    }
}

// ============================================================ Serialisation helpers ============================================================

fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> T {
    assert!(buf.len() >= offset + size_of::<T>());
    unsafe { (buf.as_ptr().add(offset) as *const T).read_unaligned() }
}

fn write_struct<T: Copy>(buf: &mut [u8], val: &T) -> usize {
    let sz = size_of::<T>();
    assert!(buf.len() >= sz);
    unsafe { (buf.as_mut_ptr() as *mut T).write_unaligned(*val) }
    sz
}

mod aperture;
pub use aperture::APERTURE_LEN;
mod files;
pub use files::FileTree;
mod host;
pub use host::{HostDriver, RealHost};
mod ioctl;
mod legion_display;
mod legion_event_data;
mod legion_fence;
mod legion_memory_cache;
mod legion_userd_cache;
mod nested;
mod open;
mod osdesc;
mod resp;
mod rm_fd;
mod rmctrl;
mod simple;
mod uvm;
mod vidmem;
mod window;

#[cfg(test)]
#[path = "../../tests/unit/nvidia/backend.rs"]
mod tests;
