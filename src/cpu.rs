use anyhow::{Context, Result};
use legion_cpu_topology::Topology;
use serde::Serialize;

/// Mirror all online host cores/threads without expanding launcher affinity.
pub fn host_topology() -> Result<Topology> {
    let topology = Topology::detect()?;
    let status =
        std::fs::read_to_string("/proc/self/status").context("read launcher CPU affinity")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .context("launcher CPU affinity list is unavailable")?;
    topology.check_affinity(allowed)?;
    Ok(topology)
}

/// Preserve AMD's supported topology extension when exposing SMT to the guest.
pub fn boot_cpu() -> Result<String> {
    let info =
        std::fs::read_to_string("/proc/cpuinfo").context("read host topology capabilities")?;
    Ok(format!(
        "{}{}",
        boot_cpu_for_info(&info),
        target_overrides()
    ))
}

/// `TARGET` expressed as QEMU `-cpu` property overrides.
///
/// The guest has to answer the packed binary's CPUID handshake itself, and it can
/// only do that from the kernel, so the identity has to be in the vCPU from boot
/// rather than spoofed per process. Decode the signature back into the family,
/// model and stepping fields QEMU re-encodes into leaf 1.
fn target_overrides() -> String {
    let signature = TARGET.signature;
    let stepping = signature & 0xf;
    let base_model = (signature >> 4) & 0xf;
    let base_family = (signature >> 8) & 0xf;
    let ext_model = (signature >> 16) & 0xf;
    let ext_family = (signature >> 20) & 0xff;

    let family = if base_family == 0xf {
        base_family + ext_family
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        (ext_model << 4) | base_model
    } else {
        base_model
    };

    format!(
        ",vendor={},family={:#x},model={:#x},stepping={}",
        TARGET.vendor, family, model, stepping
    )
}

fn boot_cpu_for_info(info: &str) -> String {
    let first = info.split("\n\n").next().unwrap_or(info);
    let field = |name| {
        first.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then_some(value.trim())
        })
    };
    let mut model = BOOT_CPU.to_owned();
    if field("vendor_id") == Some("AuthenticAMD")
        && field("flags")
            .is_some_and(|flags| flags.split_whitespace().any(|flag| flag == "topoext"))
    {
        model.push_str(",+topoext");
    }
    model
}

/// Guest CPU compatibility policy.
#[derive(Debug, Serialize)]
pub struct CpuPolicy {
    pub vendor: &'static str,
    pub signature: u32,
    pub leaf_1_ecx: u32,
    pub leaf_1_edx: u32,
    pub leaf_7_0_ebx: u32,
    pub leaf_7_0_ecx: u32,
    pub leaf_7_0_edx: u32,
    pub xcr0: u64,
}

pub const TARGET: CpuPolicy = CpuPolicy {
    vendor: "AuthenticAMD",
    signature: 0x00a2_0f12,
    leaf_1_ecx: 0x7ef8_320b,
    leaf_1_edx: 0x178b_fbff,
    leaf_7_0_ebx: 0x219c_97a9,
    leaf_7_0_ecx: 0x0040_068c,
    leaf_7_0_edx: 0x10,
    xcr0: 7,
};

// Bootstrap policy for testing XSTATE only.
pub const BOOT_CPU: &str = concat!(
    "host",
    ",-avx512f,-avx512dq,-avx512ifma,-avx512pf,-avx512er,-avx512cd",
    ",-avx512bw,-avx512vl,-avx512vbmi,-avx512vbmi2,-avx512vnni",
    ",-avx512bitalg,-avx512-vpopcntdq,-avx512-vp2intersect",
    ",-avx512-bf16,-avx512-fp16,-avx512-4vnniw,-avx512-4fmaps",
    ",-pku,-amx-tile,-x2apic",
    // Guest reports AuthenticAMD, so the kernel encodes paravirt hypercalls with
    // AMD's VMMCALL. The host is Intel, so those trap as #UD: drop the features
    // that issue them and let IPIs go through the APIC.
    ",-kvm-pv-ipi,-kvm-pv-sched-yield,-kvm-pv-tlb-flush,-kvm-pv-unhalt,-kvm-asyncpf",
);

#[cfg(test)]
#[path = "../tests/unit/cpu.rs"]
mod tests;
