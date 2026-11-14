//! Runs only in the disposable initramfs, after the PID1 check in main.
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::gpu_kind::GpuKind;
use anyhow::{Context, Result, ensure};
use rustix::mount::{MountFlags, mount};
use serde_json::{Value, json};

fn selected_gpu() -> Result<GpuKind> {
    GpuKind::from_cmdline(&fs::read_to_string("/proc/cmdline")?)
}

pub fn report() -> Value {
    match inspect() {
        Ok(report) => report,
        Err(error) => json!({"schema": 1, "passed": false, "error": format!("{error:#}")}),
    }
}

pub fn vulkan_report() -> Value {
    match inspect_vulkan() {
        Ok(report) => report,
        Err(error) => json!({"schema": 1, "passed": false, "error": format!("{error:#}")}),
    }
}

/// Generic virtio-GPU plumbing, not a claim of hardware rendering.
pub fn drm_report() -> Value {
    match inspect_drm() {
        Ok(report) => report,
        Err(error) => json!({"schema":1,"passed":false,"scope":"virtio_gpu_driver_only",
            "hardware_rendering_verified":false,"error":format!("{error:#}")}),
    }
}

fn inspect_drm() -> Result<Value> {
    use rustix::ioctl::{Opcode, Updater, ioctl, opcode};
    ensure!(std::process::id() == 1, "DRM probe requires guest PID1");
    let modules = load_modules()?;
    let mut nodes = Vec::new();
    let mut observed = Vec::new();
    for entry in fs::read_dir("/sys/class/drm")? {
        let entry = entry?;
        observed.push(json!({"name":entry.file_name().to_string_lossy(),
            "driver":fs::read_link(entry.path().join("device/driver")).ok()}));
        if !entry.file_name().as_encoded_bytes().starts_with(b"renderD") {
            continue;
        }
        let node = Path::new("/dev/dri").join(entry.file_name());
        let file = OpenOptions::new().read(true).write(true).open(&node)?;
        if drm_driver_name(&file)? != "virtio_gpu" {
            continue;
        }
        let parameter = |param: u64| -> Result<u64> {
            // Linux uapi drm/virtgpu_drm.h: DRM_COMMAND_BASE + GETPARAM, two __u64 fields, the second pointing to a __u64 result.
            const GETPARAM: Opcode = opcode::read_write::<[u64; 2]>(b'd', 0x43);
            let mut value = 0_u64;
            let mut request = [param, (&mut value as *mut u64) as u64];
            // SAFETY: DRM's version query identified this node as virtio_gpu.
            unsafe { ioctl(&file, Updater::<GETPARAM, _>::new(&mut request)) }
                .context("query guest virtio-GPU parameter")?;
            Ok(value)
        };
        let capsets = parameter(7)?;
        nodes.push(
            json!({"node":node,"driver":"virtio_gpu","resource_blob":parameter(3)?,
            "context_init":parameter(6)?,"supported_capsets":capsets,
            "drm_native_context_capset":capsets & (1 << 6) != 0}),
        );
    }
    ensure!(
        !nodes.is_empty(),
        "virtio-GPU has no usable guest render node; observed DRM entries: {observed:?}"
    );
    Ok(
        json!({"schema":1,"passed":true,"scope":"virtio_gpu_driver_only",
        "hardware_rendering_verified":false,"loaded_modules":modules,"render_nodes":nodes}),
    )
}

fn inspect_vulkan() -> Result<Value> {
    for tag in ["usr", "frames"] {
        let target = format!("/{tag}");
        fs::create_dir_all(&target)?;
        mount(
            tag,
            target.as_str(),
            "virtiofs",
            if tag == "usr" {
                MountFlags::RDONLY
            } else {
                MountFlags::empty()
            },
            None,
        )
        .with_context(|| format!("mount guest share {tag}"))?;
    }
    // Mount only explicitly exported extra directories under a dedicated root.
    let shares = Path::new("/frames").join(legion_shared_directories::MANIFEST);
    if shares.exists() {
        ensure!(
            fs::metadata(&shares)?.len() <= legion_shared_directories::MAX_MANIFEST_BYTES,
            "guest share manifest exceeds 64 KiB"
        );
        let manifest: legion_shared_directories::Manifest =
            serde_json::from_slice(&fs::read(shares)?)?;
        manifest.validate()?;
        let libraries = Path::new("/frames").join(legion_shared_directories::LIBRARY_MANIFEST);
        let bindings: legion_shared_directories::LibraryBindings = if libraries.is_file() {
            ensure!(
                fs::metadata(&libraries)?.len() <= legion_shared_directories::MAX_MANIFEST_BYTES,
                "driver library manifest exceeds size bound"
            );
            serde_json::from_slice(&fs::read(libraries)?)?
        } else {
            Default::default()
        };
        bindings.validate(&manifest)?;
        let mut mounted = Vec::new();
        for share in manifest.mounts {
            let target = share.target();
            fs::create_dir_all(&target)?;
            mount(
                share.tag.as_str(),
                &target,
                "virtiofs",
                if share.readonly {
                    MountFlags::RDONLY
                } else {
                    MountFlags::empty()
                },
                None,
            )
            .with_context(|| format!("mount additional guest share {}", share.tag))?;
            let readonly = rustix::fs::statvfs(target.as_path())?
                .f_flag
                .contains(rustix::fs::StatVfsMountFlags::RDONLY);
            ensure!(
                readonly == share.readonly,
                "share {} mount permission mismatch",
                share.tag
            );
            mounted.push(legion_shared_directories::Mounted {
                tag: share.tag,
                target,
                readonly,
            });
        }
        fs::write("/frames/mounted-shares.json", serde_json::to_vec(&mounted)?)?;
        for file in &bindings.files {
            let source = Path::new(legion_shared_directories::GUEST_ROOT)
                .join(&file.tag)
                .join(&file.source_name);
            let target = Path::new("/usr/lib").join(&file.target_name);
            ensure!(
                source.is_file() && target.is_file() && !target.is_symlink(),
                "driver library source/placeholder missing"
            );
            mount(&source, &target, "", MountFlags::BIND, None)
                .with_context(|| format!("bind host driver library {}", file.target_name))?;
            ensure!(
                rustix::fs::statvfs(&target)?
                    .f_flag
                    .contains(rustix::fs::StatVfsMountFlags::RDONLY),
                "driver library binding did not retain read-only access"
            );
        }
        fs::write(
            "/frames/mounted-driver-libraries.json",
            serde_json::to_vec(&bindings)?,
        )?;
    }
    // Development userspace layout.
    for (name, target) in [
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib"),
        ("/bin", "usr/bin"),
        ("/sbin", "usr/bin"),
    ] {
        symlink(target, name).with_context(|| format!("create guest {name} link"))?;
    }
    fs::create_dir_all("/tmp")?;
    fs::set_permissions("/tmp", fs::Permissions::from_mode(0o1777))?;
    fs::create_dir_all("/run/user/0")?;
    fs::set_permissions("/run/user/0", fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all("/dev/shm")?;
    mount(
        "tmpfs",
        "/dev/shm",
        "tmpfs",
        MountFlags::empty(),
        Some(c"mode=1777,size=64m"),
    )?;
    let expected = selected_gpu()?;
    let dependencies = if expected == GpuKind::Amd {
        let check = run_vulkan_program(
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            &["--list", "/usr/lib/x86_64-linux-gnu/libvulkan_radeon.so"],
            "radv-dependencies",
        )?;
        if check["success"] != true {
            return Ok(
                json!({"schema":1,"passed":false,"enumeration_verified":false,"draw_verified":false,
                "expected_vendor":expected.vendor_id(),"selected_icd":expected.icd(),
                "driver_dependency_check":check,"error":"RADV guest dependencies failed to load"}),
            );
        }
        Some(check)
    } else {
        None
    };
    let info = run_vulkan_program("/usr/bin/vulkaninfo", &["--summary"], "vulkaninfo")?;
    let text = info["stdout"].as_str().unwrap_or_default();
    let vendor = text.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "vendorID" && value.trim() == expected.vendor_id()
        })
    });
    let hardware = text.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "deviceType"
                && (value.contains("DISCRETE_GPU") || value.contains("INTEGRATED_GPU"))
        })
    });
    if info["success"] != true || !vendor || !hardware {
        return Ok(
            json!({"schema": 1, "passed": false, "enumeration_verified": false, "draw_verified": false,
                "expected_vendor":expected.vendor_id(),"selected_icd":expected.icd(),
                "driver_dependency_check":dependencies,
                "vulkaninfo": info, "error": "selected hardware Vulkan enumeration failed"}),
        );
    }
    let draw = if Path::new("/probe-draw").is_file() {
        Some(run_vulkan_program(
            "/probe-draw",
            &["/frames/triangle.ppm"],
            "draw",
        )?)
    } else {
        None
    };
    let draw_verified = draw.as_ref().is_some_and(|value| {
        value["success"] == true
            && value["stdout"]
                .as_str()
                .is_some_and(|text| text.contains("red=11858 blue=53678 other=0"))
    });
    let passed = draw.is_none() || draw_verified;
    let display = if Path::new("/probe-display").is_file() {
        Some(run_vulkan_program("/probe-display", &[], "display")?)
    } else {
        None
    };
    let passed = passed
        && display
            .as_ref()
            .is_none_or(|value| value["success"] == true);
    let workload = if Path::new("/probe-workload").is_file() {
        Some(run_vulkan_program(
            "/probe-workload",
            &["/workload-config.json", "/frames/workload-result.json"],
            "workload",
        )?)
    } else {
        None
    };
    let mut workload_gpu_verified = false;
    let passed = if let Some(run) = &workload {
        ensure!(run["success"] == true, "workload process failed: {run}");
        let result = fs::read("/frames/workload-result.json").context("read workload result")?;
        ensure!(
            result.len() <= 8 * 1024 * 1024,
            "workload result exceeds 8 MiB"
        );
        let result: Value = serde_json::from_slice(&result)?;
        workload_gpu_verified = result["gpu_verified"] == true;
        passed && run["success"] == true && result["schema"] == 1 && result["passed"] == true
    } else {
        passed
    };
    Ok(json!({
        "schema": 1, "passed": passed, "enumeration_verified": true,
        "draw_verified": draw_verified, "vulkaninfo": info, "draw": draw,
        "driver_dependency_check":dependencies,
        "display": display,
        "workload": workload, "workload_gpu_verified": workload_gpu_verified,
        "interrupts": interrupt_report()?,
        "idle_driver": read_sysfs("/sys/devices/system/cpu/cpuidle/current_driver"),
        "idle_governor": read_sysfs("/sys/devices/system/cpu/cpuidle/current_governor_ro"),
        "haltpoll_ns": read_sysfs("/sys/module/haltpoll/parameters/guest_halt_poll_ns"),
        "cpu_environment": cpu_environment(),
        "graphics_sync": match graphics_sync() {
            Ok(value) => value,
            Err(error) => json!({"error":format!("{error:#}")}),
        },
        "error": if passed { None::<&str> } else { Some("offscreen draw or pixel verification failed") },
    }))
}

// Observational metadata, outside the workload's timed interval.
fn read_sysfs(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

/// Identify the DRM implementation; a virtio render node's sysfs parent can name its PCI transport rather than its graphics driver.
fn drm_driver_name(file: &File) -> Result<String> {
    use rustix::ioctl::{Opcode, Updater, ioctl, opcode};

    #[repr(C)]
    struct DrmVersion {
        major: i32,
        minor: i32,
        patch: i32,
        _pad: u32,
        name_len: usize,
        name: *mut u8,
        date_len: usize,
        date: *mut u8,
        description_len: usize,
        description: *mut u8,
    }
    const VERSION: Opcode = opcode::read_write::<DrmVersion>(b'd', 0);
    let mut driver_name = [0_u8; 32];
    let mut version = DrmVersion {
        major: 0,
        minor: 0,
        patch: 0,
        _pad: 0,
        name_len: driver_name.len(),
        name: driver_name.as_mut_ptr(),
        date_len: 0,
        date: std::ptr::null_mut(),
        description_len: 0,
        description: std::ptr::null_mut(),
    };
    // SAFETY: VERSION is the standard x86-64 DRM version query.
    unsafe { ioctl(file, Updater::<VERSION, _>::new(&mut version)) }
        .context("identify DRM render-node driver")?;
    ensure!(
        version.name_len <= driver_name.len(),
        "DRM driver name exceeds buffer"
    );
    String::from_utf8(driver_name[..version.name_len].to_vec()).map_err(Into::into)
}

/// Query NVIDIA proxy capabilities after timing; an unsupported query remains diagnostic data rather than a rendering failure.
fn graphics_sync() -> Result<Value> {
    use rustix::ioctl::{Opcode, Updater, ioctl, opcode};
    // NVIDIA's current GET_DEV_INFO ABI is nine u32 fields.
    const GET_DEV_INFO: Opcode = opcode::read_write::<[u32; 9]>(b'd', 0x43);
    let mut devices = Vec::new();
    for entry in fs::read_dir("/dev/dri")? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_str().is_some_and(|s| s.starts_with("renderD")) {
            continue;
        }
        let path = Path::new("/dev/dri").join(&name);
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        if drm_driver_name(&file)? != "nvidia-drm" {
            continue;
        }
        let mut fields = [0_u32; 9];
        // SAFETY: this owned descriptor belongs to the verified NVIDIA proxy.
        unsafe { ioctl(&file, Updater::<GET_DEV_INFO, _>::new(&mut fields)) }
            .context("query NVIDIA proxy device capabilities")?;
        devices.push(json!({
            "render_node":path,
            "supports_alloc":fields[3] != 0,
            "supports_sync_fd":fields[7] != 0,
            "supports_semsurf":fields[8] != 0,
        }));
    }
    ensure!(
        !devices.is_empty(),
        "no NVIDIA proxy render node for capability query"
    );
    Ok(json!({"devices":devices,"error":null}))
}

/// Observe the disposable guest's scheduling inputs after the workload.
fn cpu_environment() -> Value {
    let mut caches = std::collections::BTreeSet::new();
    if let Ok(cpus) = fs::read_dir("/sys/devices/system/cpu") {
        for cpu in cpus.flatten() {
            let name = cpu.file_name();
            let Some(id) = name.to_str().and_then(|s| s.strip_prefix("cpu")) else {
                continue;
            };
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(indices) = fs::read_dir(cpu.path().join("cache")) else {
                continue;
            };
            for index in indices.flatten() {
                let read = |name: &str| {
                    fs::read_to_string(index.path().join(name))
                        .ok()
                        .map(|s| s.trim().to_owned())
                };
                if let (Some(level), Some(kind), Some(size), Some(shared_cpus)) = (
                    read("level"),
                    read("type"),
                    read("size"),
                    read("shared_cpu_list"),
                ) {
                    caches.insert((level, kind, size, shared_cpus));
                }
            }
        }
    }
    let caches: Vec<_> = caches.into_iter().map(|(level, kind, size, shared_cpus)| {
        json!({"level":level,"type":kind,"size":size,"shared_cpu_list":shared_cpus})
    }).collect();
    json!({
        "cache_groups":caches,
        "nohz_full":read_sysfs("/sys/devices/system/cpu/nohz_full"),
        "cmdline":read_sysfs("/proc/cmdline"),
        "sched_bore":read_sysfs("/proc/sys/kernel/sched_bore"),
        "hypervisor_cpuid":super::cpuid(0x4000_0000, 0),
        "kvm_features_cpuid":super::cpuid(0x4000_0001, 0),
    })
}

/// Read the actual guest interrupt allocation, rather than infer it from QEMU options.
fn interrupt_report() -> Result<Value> {
    let mut devices = Vec::new();
    let mut names = Vec::new();
    for entry in fs::read_dir("/sys/bus/virtio/devices")? {
        let entry = entry?;
        if fs::read_link(entry.path().join("driver"))
            .ok()
            .as_ref()
            .and_then(|path| path.file_name())
            != Some(std::ffi::OsStr::new("virtio-gpu-nv"))
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = fs::canonicalize(entry.path())?;
        let parent = path
            .parent()
            .context("virtio device has no transport parent")?;
        let pci = parent.join("config").is_file();
        let mut vectors = Vec::new();
        match fs::read_dir(parent.join("msi_irqs")) {
            Ok(entries) => {
                for irq in entries {
                    let irq = irq?;
                    vectors.push(json!({
                        "irq": irq.file_name().to_string_lossy().parse::<u32>()?,
                        "kind": fs::read_to_string(irq.path())?.trim(),
                    }));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        vectors.sort_by_key(|value| value["irq"].as_u64());
        devices.push(json!({"device": name, "transport": if pci { "pci" } else { "mmio" }, "vectors": vectors}));
        names.push(name);
    }
    let interrupts = fs::read_to_string("/proc/interrupts")?;
    let lines = interrupts
        .lines()
        .filter(|line| names.iter().any(|name| line.contains(name)))
        .collect::<Vec<_>>();
    Ok(json!({"devices": devices, "irq_lines": lines}))
}

fn run_vulkan_program(program: &str, args: &[&str], name: &str) -> Result<Value> {
    let stdout = format!("/tmp/{name}.stdout");
    let stderr = format!("/tmp/{name}.stderr");
    let status = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("HOME", "/tmp")
        .env("XDG_RUNTIME_DIR", "/run/user/0")
        .env("LD_LIBRARY_PATH", "/usr/lib")
        .env("VK_DRIVER_FILES", selected_gpu()?.icd())
        .env("__EGL_VENDOR_LIBRARY_DIRS", "/usr/share/glvnd/egl_vendor.d")
        .env("VK_LOADER_DEBUG", "error,warn")
        .stdin(Stdio::null())
        .stdout(File::create(&stdout)?)
        .stderr(File::create(&stderr)?)
        .status()
        .with_context(|| format!("run guest {program}"))?;
    let read = |path: &str| -> Result<String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        File::open(path)?.take(64 * 1024).read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    // Always capture the ring: the driver reports device loss through NVRM messages
    // and then exits normally, so a signal is not the interesting case.
    let kernel_messages = {
        let mut bytes = vec![0_u8; 64 * 1024];
        // SAFETY: SYSLOG_ACTION_READ_ALL writes at most the allocated buffer length.
        let length = unsafe { libc::klogctl(3, bytes.as_mut_ptr().cast(), 65536) };
        if length > 0 {
            String::from_utf8_lossy(&bytes[..length as usize]).into_owned()
        } else {
            String::new()
        }
    };
    Ok(
        json!({"success": status.success(), "exit_code": status.code(), "signal": status.signal(), "stdout": read(&stdout)?, "stderr": read(&stderr)?, "kernel_messages": kernel_messages, "driver_view": driver_view(), "nvml": nvml_view()}),
    )
}

/// Ask NVML what userspace RM thinks of the GPU. A device-loss verdict shows up here
/// as a return code, which is the one place it can be read without driver logging.
fn nvml_view() -> Value {
    #[repr(C)]
    struct Memory {
        total: u64,
        free: u64,
        used: u64,
    }
    unsafe {
        let mut handle = libc::dlopen(c"libnvidia-ml.so.1".as_ptr(), libc::RTLD_NOW);
        if handle.is_null() {
            handle = libc::dlopen(c"/usr/lib/libnvidia-ml.so.1".as_ptr(), libc::RTLD_NOW);
        }
        if handle.is_null() {
            let libs = fs::read_dir("/usr/lib")
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .filter(|name| name.contains("nvidia"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return json!({"loaded": false, "error": "libnvidia-ml.so.1 did not load", "usr_lib_nvidia": libs});
        }
        let sym = |name: &std::ffi::CStr| libc::dlsym(handle, name.as_ptr());
        let init: extern "C" fn() -> i32 = std::mem::transmute(sym(c"nvmlInit_v2"));
        let count_devices: extern "C" fn(*mut u32) -> i32 =
            std::mem::transmute(sym(c"nvmlDeviceGetCount_v2"));
        let by_index: extern "C" fn(u32, *mut *mut std::ffi::c_void) -> i32 =
            std::mem::transmute(sym(c"nvmlDeviceGetHandleByIndex_v2"));
        let get_name: extern "C" fn(*mut std::ffi::c_void, *mut u8, u32) -> i32 =
            std::mem::transmute(sym(c"nvmlDeviceGetName"));
        let get_memory: extern "C" fn(*mut std::ffi::c_void, *mut Memory) -> i32 =
            std::mem::transmute(sym(c"nvmlDeviceGetMemoryInfo"));

        let mut count = 0_u32;
        let init_rc = init();
        let count_rc = if init_rc == 0 { count_devices(&mut count) } else { -1 };
        let mut device: *mut std::ffi::c_void = std::ptr::null_mut();
        let handle_rc = if count_rc == 0 && count > 0 {
            by_index(0, &mut device)
        } else {
            -1
        };
        let mut name = [0_u8; 96];
        let name_rc = if handle_rc == 0 {
            get_name(device, name.as_mut_ptr(), name.len() as u32)
        } else {
            -1
        };
        let mut memory = Memory { total: 0, free: 0, used: 0 };
        let memory_rc = if handle_rc == 0 {
            get_memory(device, &mut memory)
        } else {
            -1
        };
        json!({
            "loaded": true,
            "init": init_rc,
            "count_rc": count_rc,
            "count": count,
            "handle_rc": handle_rc,
            "name_rc": name_rc,
            "name": String::from_utf8_lossy(&name).trim_end_matches('\0').to_owned(),
            "memory_rc": memory_rc,
            "total_mib": memory.total / (1024 * 1024),
            "used_mib": memory.used / (1024 * 1024),
        })
    }
}

/// What the loaded driver itself thinks of the GPU, straight out of procfs.
fn driver_view() -> Value {
    let mut gpus = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc/driver/nvidia/gpus") {
        for entry in entries.flatten() {
            gpus.push(json!({
                "pci": entry.file_name().to_string_lossy(),
                "information": fs::read_to_string(entry.path().join("information")).unwrap_or_default(),
            }));
        }
    }
    let sys = |name: &str| {
        fs::read_to_string(format!("/sys/bus/pci/devices/0000:01:00.0/{name}"))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    };
    json!({
        "version": fs::read_to_string("/proc/driver/nvidia/version").unwrap_or_default(),
        "gpus": gpus,
        "power_state": sys("power_state"),
        "runtime_status": sys("runtime_status"),
        "current_link_speed": sys("current_link_speed"),
        "dev_dri": fs::read_dir("/dev/dri")
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    })
}

fn load_modules() -> Result<Vec<String>> {
    ensure!(std::process::id() == 1, "guest driver probe requires PID1");
    // PID1 mounted proc/sys/dev before recording the CPU topology proof.
    let mut modules = Vec::new();
    for name in fs::read_to_string("/modules/load-order")?.lines() {
        ensure!(
            !name.is_empty()
                && name.bytes().all(|byte| byte.is_ascii_digit()
                    || byte == b'.'
                    || byte == b'k'
                    || byte == b'o'),
            "invalid module manifest entry"
        );
        let file = File::open(Path::new("/modules").join(name))?;
        // This loads into the disposable guest kernel, never the host kernel.
        rustix::system::finit_module(&file, c"", 0)
            .with_context(|| format!("load guest module {name}"))?;
        modules.push(name.to_owned());
    }
    Ok(modules)
}

fn inspect() -> Result<Value> {
    let modules = load_modules()?;
    let mut bound_devices = Vec::new();
    for entry in fs::read_dir("/sys/bus/virtio/devices")? {
        let entry = entry?;
        let driver = fs::read_link(entry.path().join("driver")).ok();
        if driver.as_ref().and_then(|path| path.file_name())
            == Some(std::ffi::OsStr::new("virtio-gpu-nv"))
        {
            bound_devices.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    ensure!(
        !bound_devices.is_empty(),
        "NVIDIA virtio driver did not bind; inspect guest kernel log"
    );
    let _control = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/nvidiactl")
        .context("open guest NVIDIA control device")?;
    let _device = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/nvidia0")
        .context("open guest NVIDIA GPU device")?;
    let version = fs::read_to_string("/proc/driver/nvidia/version")?;
    let mut render_nodes = Vec::new();
    for entry in fs::read_dir("/dev/dri").context("list guest DRM devices")? {
        let entry = entry?;
        if entry.file_name().as_encoded_bytes().starts_with(b"renderD") {
            let _render = OpenOptions::new()
                .read(true)
                .write(true)
                .open(entry.path())
                .context("open guest DRM render node")?;
            render_nodes.push(entry.path().to_string_lossy().into_owned());
        }
    }
    ensure!(
        !render_nodes.is_empty(),
        "guest has no usable DRM render node"
    );
    Ok(json!({
        "schema": 1, "passed": true, "driver_bound": true,
        "nvidia_control_open": true, "nvidia_device_open": true,
        "bound_devices": bound_devices, "render_nodes": render_nodes,
        "driver_version": version.trim(), "loaded_modules": modules,
        "error": null,
    }))
}
