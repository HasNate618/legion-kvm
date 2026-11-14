//! IOCTL: the ABI check and the routing of each namespace to its handler.

use super::*;

// Root allocation classes create a client handle.
impl NvidiaBackend {
    // ------------------------------------------------------------------ IOCTL — top-level ------------------------------------------------------------------

    /// Learn the host driver version from a successful `NV_ESC_CHECK_VERSION_STR` reply and select the ABI profile for it.
    pub(super) fn learn_driver_version(&mut self, param_buf: &[u8]) {
        if self.driver.is_some() || param_buf.len() < 12 {
            return;
        }
        let tail = &param_buf[8..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let Ok(text) = std::str::from_utf8(&tail[..end]) else {
            return;
        };
        let Some(v) = abi::version::DriverVersion::parse(text) else {
            return;
        };
        self.driver = Some(v);
        self.abi = abi::versions::table_for(v);
        // The RM pointer table goes with it.
        self.rmctrl = abi::rmctrl::select(v);
        self.rmallow = abi::rmallow::select(v);
        self.uvm = abi::uvm::select(v);
        self.osdesc = abi::osdesc::select(v);
        self.vidmem = abi::vidmem::select(v);
        match self.abi {
            Some(t) => log::info!("host driver {v}: ABI profile selected, {} escapes", t.len()),
            None => log::warn!(
                "host driver {v} is older than every ABI profile; ioctls will be \
                 forwarded without size checking"
            ),
        }
    }

    /// Refuse an RM_ALLOC whose class needs a capability this guest lacks.
    pub(super) fn refuse_alloc_class(
        &mut self,
        cookie: u64,
        class: u32,
        bit: u32,
        param_in: &[u8],
        resp_buf: &mut [u8],
    ) -> usize {
        const NV_ERR_INVALID_CLASS: u32 = 0x22;
        let needs = if bit == crate::caps::VIDEO {
            "video"
        } else {
            "graphics"
        };
        self.refuse_for_caps(format!("RM_ALLOC class {class:#06x}"), needs);
        let mut out = param_in.to_vec();
        if out.len() < NVOS64_STATUS + 4 {
            return self.write_error_resp(resp_buf, Status::IoctlFailed, cookie, libc::EINVAL);
        }
        out[NVOS64_STATUS..NVOS64_STATUS + 4].copy_from_slice(&NV_ERR_INVALID_CLASS.to_le_bytes());
        self.write_ioctl_resp(resp_buf, cookie, &out)
    }

    /// Whether RM exports this control to an unprivileged caller.
    fn rm_control_refusal(&self, cmd: u32, declared: u32, sent: u32) -> Option<String> {
        if let Some(name) = abi::rmallow::denied(cmd) {
            return Some(format!("{name} answers about the host, not this guest"));
        }
        // No allowlist at all means nothing can be said about any control.
        let Some(sel) = self.rmallow else {
            return Some("no RM allowlist for this host".into());
        };
        let Some(rule) = sel.ctrl_rule(cmd) else {
            return Some(if sel.exact {
                "RM does not serve it to an unprivileged caller".into()
            } else {
                // Either RM never served it, or the table is an older release's and the releases disagree.
                "no release this backend knows serves it to an unprivileged caller".into()
            });
        };
        match rule {
            // RM sizes this from its own descriptor, so the block has to be exactly that size and the guest has to have sent all of it.
            abi::rmallow::CtrlAllow::Exact(want) => {
                if declared != want {
                    return Some(format!(
                        "parameters are declared {declared} bytes, RM's are {want}"
                    ));
                }
            }
            // RM reads nothing here -- it hands the block to GSP firmware -- so there is no size to require, only the ceiling RM puts on a parameter copy for an unprivileged caller.
            abi::rmallow::CtrlAllow::UpTo(max) => {
                if declared > max {
                    return Some(format!(
                        "parameters are declared {declared} bytes, more than the {max} RM copies"
                    ));
                }
            }
        }
        (sent != declared)
            .then(|| format!("parameters are declared {declared} bytes and {sent} arrived"))
    }

    /// Whether RM lets an unprivileged caller allocate this class.
    fn rm_class_refusal(&self, class: u32, have: usize) -> Option<String> {
        let Some(sel) = self.rmallow else {
            return Some("no RM allowlist for this host".into());
        };
        let Some(entry) = sel.class_entry(class) else {
            return Some(if sel.exact {
                "RM does not let an unprivileged caller allocate it".into()
            } else {
                "no release this backend knows lets an unprivileged caller allocate it".into()
            });
        };
        // RS_OPTIONAL means the parameters may be absent entirely; RS_REQUIRED means they may not.
        if have == 0 {
            return entry
                .params_required
                .then(|| "RM requires allocation parameters and none were sent".to_string());
        }
        (have != entry.params_size as usize).then(|| {
            format!(
                "allocation parameters are {have} bytes, RM's are {}",
                entry.params_size
            )
        })
    }

    /// Answer an RM_CONTROL the allowlist refused, without calling the host.
    pub(super) fn refuse_control(
        &mut self,
        cookie: u64,
        cmd: u32,
        why: String,
        param_in: &[u8],
        resp_buf: &mut [u8],
    ) -> usize {
        const NVOS54_STATUS: usize = 28;
        const NV_ERR_NOT_SUPPORTED: u32 = 0x56;
        self.note_allow_refusal(format!("RM_CONTROL cmd {cmd:#010x}"), why);
        let mut out = param_in.to_vec();
        if out.len() < NVOS54_STATUS + 4 {
            return self.write_error_resp(resp_buf, Status::IoctlFailed, cookie, libc::EINVAL);
        }
        out[NVOS54_STATUS..NVOS54_STATUS + 4].copy_from_slice(&NV_ERR_NOT_SUPPORTED.to_le_bytes());
        self.write_ioctl_resp(resp_buf, cookie, &out)
    }

    /// Answer an RM_ALLOC the allowlist refused, without calling the host.
    pub(super) fn refuse_alloc(
        &mut self,
        cookie: u64,
        class: u32,
        why: String,
        param_in: &[u8],
        resp_buf: &mut [u8],
    ) -> usize {
        const NV_ERR_INVALID_CLASS: u32 = 0x22;
        self.note_allow_refusal(format!("RM_ALLOC class {class:#06x}"), why);
        let mut out = param_in.to_vec();
        if out.len() < NVOS64_STATUS + 4 {
            return self.write_error_resp(resp_buf, Status::IoctlFailed, cookie, libc::EINVAL);
        }
        out[NVOS64_STATUS..NVOS64_STATUS + 4].copy_from_slice(&NV_ERR_INVALID_CLASS.to_le_bytes());
        self.write_ioctl_resp(resp_buf, cookie, &out)
    }

    /// Count a refusal, and say why the first time.
    pub(super) fn note_allow_refusal(&mut self, what: String, why: String) {
        let n = self.allow_refused.entry(what.clone()).or_insert(0);
        *n += 1;
        if *n == 1 {
            log::warn!("{what} refused: {why}");
        }
    }

    /// Check one guest ioctl against the host's ABI profile.
    pub fn check_abi(&self, escape: u32, param_size: u32) -> AbiCheck {
        let Some(table) = self.abi else {
            return AbiCheck::NoProfile;
        };
        let Some(entry) = abi::versions::lookup(table, escape) else {
            return AbiCheck::UnknownEscape;
        };
        match entry.param_size {
            None => AbiCheck::VariableLength,
            Some(expected) if expected == param_size => AbiCheck::Ok,
            Some(expected) => AbiCheck::SizeMismatch {
                expected,
                actual: param_size,
            },
        }
    }

    pub(super) fn handle_ioctl(
        &mut self,
        cookie: u64,
        payload: &[u8],
        resp_buf: &mut [u8],
    ) -> usize {
        if let Some(n) = self.vidmem_admit(cookie, payload, resp_buf) {
            return n;
        }
        let n = self.serve_ioctl(cookie, payload, resp_buf);
        self.vidmem_note(payload, &mut resp_buf[..n]);
        self.note_clients(payload, &resp_buf[..n]);
        self.note_registrations(payload, &resp_buf[..n]);
        self.note_alloc_status(payload, &resp_buf[..n]);
        n
    }

    /// Record what RM answered for an allocation. A refusal here is silent at the syscall level: the ioctl succeeds and the status travels inside the parameters.
    fn note_alloc_status(&mut self, payload: &[u8], resp: &[u8]) {
        let req = read_struct::<IoctlReq>(payload, 0);
        let request = req.cmd as u64;
        if (request >> 8) & 0xFF != u64::from(b'F') || request & 0xFF != 0x2b {
            return;
        }
        let head = size_of::<MsgHeader>() + size_of::<IoctlResp>();
        if resp.len() < head + NVOS64_STATUS + 4 || read_struct::<MsgHeader>(resp, 0).status != 0 {
            return;
        }
        let out = &resp[head..];
        let status = u32::from_le_bytes(out[NVOS64_STATUS..NVOS64_STATUS + 4].try_into().unwrap());
        let body = &payload[size_of::<IoctlReq>()..];
        if body.len() < 16 {
            return;
        }
        let class = u32::from_le_bytes(body[12..16].try_into().unwrap());
        let root = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let parent = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let new = u32::from_le_bytes(body[8..12].try_into().unwrap());
        // What RM says the object handle is, which is not always what was asked for.
        let resp_new = if out.len() >= 12 {
            u32::from_le_bytes(out[8..12].try_into().unwrap())
        } else {
            new
        };
        let kind = self
            .handle_kinds
            .get(&(self.current_handle as u64))
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "?".into());
        let count = self.alloc_status.entry((class, status)).or_insert(0);
        *count += 1;
        // The first words of the parameter block, so a refusal can be read against what RM was sent.
        let nested_at = size_of::<IoctlReq>() + req.data_len as usize;
        let tail = &payload[nested_at..];
        let n = (req.nested_len as usize).min(tail.len());
        let w = |i: usize| {
            if n >= i + 4 {
                u32::from_le_bytes(tail[i..i + 4].try_into().unwrap())
            } else {
                0
            }
        };
        log::info!(
            "RM_ALLOC class {class:#06x} status {status:#x}: root={root} parent={parent} \
             new={new} nested={} params={:#010x} {:#010x} {:#010x} {:#010x} on file {} ({kind})",
            req.nested_len,
            w(0),
            w(4),
            w(8),
            w(12),
            self.current_handle
        );
        if resp_new != new && status == NV_OK {
            log::info!(
                "RM_ALLOC class {class:#06x}: requested new={new:#010x}, RM assigned {resp_new:#010x}"
            );
        }
    }

    /// Release the guest memory a freed object had registered.
    fn note_registrations(&mut self, payload: &[u8], resp: &[u8]) {
        if self.registrations.is_empty() {
            return;
        }
        let req = read_struct::<IoctlReq>(payload, 0);
        let request = req.cmd as u64;
        if (request >> 8) & 0xFF != b'F' as u64 || request & 0xFF != 0x29 {
            return;
        }
        let head = size_of::<MsgHeader>() + size_of::<IoctlResp>();
        if resp.len() < head || read_struct::<MsgHeader>(resp, 0).status != 0 {
            return;
        }
        // NVOS00: hRoot, hObjectParent, hObjectOld, status.
        let out = &resp[head..];
        if out.len() < 16 {
            return;
        }
        let word = |at: usize| u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
        if word(12) == NV_OK {
            self.release_registrations(word(0), word(8));
        }
    }

    /// Keep the record of which RM clients were made on which control file, read from what RM answered rather than what the guest asked: a root allocation's handle is RM's to choose, and only a call that succeeded made or freed anything.
    fn note_clients(&mut self, payload: &[u8], resp: &[u8]) {
        let file = self.current_handle as u64;
        if self.handle_kinds.get(&file) != Some(&DeviceKind::Ctl) {
            return;
        }
        let req = read_struct::<IoctlReq>(payload, 0);
        let request = req.cmd as u64;
        if (request >> 8) & 0xFF != b'F' as u64 {
            return;
        }
        let head = size_of::<MsgHeader>() + size_of::<IoctlResp>();
        if resp.len() < head || read_struct::<MsgHeader>(resp, 0).status != 0 {
            return;
        }
        let out = &resp[head..];
        let word = |at: usize| u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
        match (request & 0xFF, out.len()) {
            // NVOS21 is 32 bytes with status at 28; NVOS64 is 48 with status at 40.
            (0x2b, n) if n >= 32 => {
                let status = if n >= 48 { word(40) } else { word(28) };
                if status == NV_OK && ROOT_CLASSES.contains(&word(12)) {
                    self.vram.client_opened(file, word(8));
                }
            }
            // NVOS00: hRoot, hObjectParent, hObjectOld, status.
            (0x29, n) if n >= 16 && word(12) == NV_OK && word(8) == word(0) => {
                log::info!("RM_FREE object={:#010x} on file {}", word(8), file);
                self.vram.client_freed(word(0));
            }
            _ => {}
        }
    }

    fn serve_ioctl(&mut self, cookie: u64, payload: &[u8], resp_buf: &mut [u8]) -> usize {
        if payload.len() < size_of::<IoctlReq>() {
            return self.write_error_resp(resp_buf, Status::InvalidMsgType, cookie, 0);
        }
        let ireq = read_struct::<IoctlReq>(payload, 0);

        // The guest sends the top-level struct and the block any pointer in it refers to, back to back.
        let body = &payload[size_of::<IoctlReq>()..];
        let want = ireq.data_len as usize + ireq.nested_len as usize + ireq.deep_len as usize;
        if body.len() < want {
            log::warn!(
                "ioctl cmd={:#x}: guest promised {want} bytes and sent {}",
                ireq.cmd,
                body.len()
            );
            return self.write_error_resp(resp_buf, Status::InvalidMsgType, cookie, libc::EINVAL);
        }
        let nested_end = ireq.data_len as usize + ireq.nested_len as usize;
        let param_in = &body[..nested_end];

        // What a pointer inside the nested block refers to.
        let deep_in: Option<(usize, &[u8])> = if ireq.deep_len > 0 {
            Some((ireq.deep_ptr_offset as usize, &body[nested_end..want]))
        } else {
            None
        };

        // How much of the response is the top-level struct.
        self.current_data_len = ireq.data_len;

        let request = ireq.cmd as u64;
        let host_fd = match self.handles.get_raw(self.current_handle as u64) {
            Ok(fd) => fd,
            Err(_) => return self.write_error_resp(resp_buf, Status::BadHandle, cookie, 0),
        };

        if ((request >> 8) & 0xff) == u64::from(b'L') {
            if ireq.nested_len != 0 || ireq.deep_len != 0 {
                return self.write_error_resp(
                    resp_buf,
                    Status::InvalidMsgType,
                    cookie,
                    libc::EINVAL,
                );
            }
            if (ireq.cmd & 0xff) >= 0x20 {
                return self.handle_fence_probe(cookie, host_fd, ireq.cmd, param_in, resp_buf);
            }
            return self.handle_legion_display(host_fd, ireq.cmd, param_in, resp_buf);
        }

        let escape = (request & 0xFF) as u32;
        let ioc_type = ((request >> 8) & 0xFF) as u32;

        // Counted before anything decides whether to serve it, so a refusal still shows up as something the workload asked for.
        let on_uvm = self.handle_kinds.get(&(self.current_handle as u64)) == Some(&DeviceKind::Uvm);
        let ns = match ioc_type {
            _ if on_uvm => 'u',
            x if x == b'F' as u32 => 'F',
            x if x == b'd' as u32 => 'd',
            x if x == b'm' as u32 => 'm',
            _ => '?',
        };
        // UVM is counted by its whole number, not by the low byte: 0x30000001 and 1 are different commands that share one.
        let counted = if on_uvm { request as u32 } else { escape };
        *self.ioctls_by_ns.entry((ns, counted)).or_insert(0) += 1;

        // A UVM file takes UVM's numbering, and the number alone cannot say so: UVM_INITIALIZE is 0x30000001 and UVM_RESERVE_VA is 1, and the two agree in every byte an ioctl type is read from.
        if on_uvm {
            return self.dispatch_uvm(cookie, host_fd, request, param_in, resp_buf);
        }

        // Only NVIDIA's own magic is described by the ABI tables; modeset uses a different namespace.
        if ioc_type == b'F' as u32 {
            // Only NVIDIA's own magic is described by the tables.
            let refuse = match self.check_abi(escape, ireq.data_len) {
                AbiCheck::SizeMismatch { expected, actual } => {
                    log::warn!(
                        "escape {escape:#04x}: guest sent {actual} bytes, host driver {} expects \
                         {expected}",
                        self.driver.expect("a profile implies a known version")
                    );
                    true
                }
                AbiCheck::UnknownEscape => {
                    log::warn!(
                        "escape {escape:#04x} is not in the ABI profile for host driver {}",
                        self.driver.expect("a profile implies a known version")
                    );
                    true
                }
                // No profile yet means CHECK_VERSION_STR has not been answered, which is itself one of the first ioctls a client sends.
                AbiCheck::Ok | AbiCheck::VariableLength | AbiCheck::NoProfile => false,
            };

            if refuse {
                *self.abi_refused.entry(escape).or_insert(0) += 1;
                return self.write_error_resp(resp_buf, Status::IoctlFailed, cookie, libc::EINVAL);
            }
        }

        // nvidia-modeset ioctls: type 'm' (0x6d), nested pointer at offset 8, size at offset 4
        if ioc_type == 0x6d {
            // NVKMS multiplexes every operation through one ioctl number, so the number says nothing and the command inside says everything.
            if param_in.len() >= 4 {
                let nvkms_cmd = u32::from_le_bytes(param_in[0..4].try_into().unwrap());
                log::debug!("NVKMS cmd={nvkms_cmd} (0x{nvkms_cmd:x})");
            }
            // REGISTER_SURFACE carries one of our handles where NVKMS expects a descriptor, because a guest's descriptor number means nothing here.
            let nvkms_fd_offset = if param_in.len() >= 4
                && u32::from_le_bytes(param_in[0..4].try_into().unwrap()) == NVKMS_REGISTER_SURFACE
            {
                Some(NVKMS_SURFACE_FD_OFFSET)
            } else {
                None
            };

            return self.dispatch_nested(
                cookie,
                host_fd,
                request,
                param_in,
                resp_buf,
                16, // outer_size
                8,  // ptr_offset
                4,  // size_offset
                deep_in,
                nvkms_fd_offset,
            );
        }

        // nvidia-drm's GEM ioctls: type 'd' (0x64), and `escape` is the absolute DRM ioctl number, not an offset from DRM_COMMAND_BASE.
        if ioc_type == b'd' as u32 {
            if escape == 0x54 {
                if request != 0xc020_6454
                    || ireq.data_len != 32
                    || ireq.nested_offset != 32
                    || ireq.nested_len != 16
                    || ireq.deep_len != 0
                {
                    return self.write_error_resp(
                        resp_buf,
                        Status::IoctlFailed,
                        cookie,
                        libc::EINVAL,
                    );
                }
                if !matches!(
                    self.handle_kinds.get(&u64::from(self.current_handle)),
                    Some(DeviceKind::Dri(_))
                ) {
                    return self.write_error_resp(
                        resp_buf,
                        Status::IoctlFailed,
                        cookie,
                        libc::ENOTTY,
                    );
                }
                return self.handle_fence_context(cookie, host_fd, param_in, resp_buf);
            }
            // (outer_size, ptr_offset, size_offset)
            let nested = match escape {
                0x41 => Some((32usize, 8usize, 16usize)), // GEM_IMPORT_NVKMS_MEMORY
                0x49 => Some((24usize, 8usize, 16usize)), // GEM_EXPORT_NVKMS_MEMORY
                0x4d => Some((24usize, 8usize, 16usize)), // GEM_EXPORT_DMABUF_MEMORY
                _ => None,
            };
            log::debug!("drm ioctl nr={escape:#04x} ({} bytes in)", param_in.len());
            if let Some((outer_size, ptr_offset, size_offset)) = nested {
                return self.dispatch_nested(
                    cookie,
                    host_fd,
                    request,
                    param_in,
                    resp_buf,
                    outer_size,
                    ptr_offset,
                    size_offset,
                    deep_in,
                    // Both NVKMS blocks begin with `int memFd`.
                    Some(0),
                );
            }
        }

        // Escape numbers below are NVIDIA's, and they are only NVIDIA's inside type 'F'.
        if ioc_type != b'F' as u32 {
            return self.dispatch_simple(cookie, host_fd, request, param_in, resp_buf);
        }

        use abi::ioctl::*;
        match escape {
            // --------------------------------------------------------------- FD-carrying ioctls — need handle translation ---------------------------------------------------------------
            NV_ESC_REGISTER_FD | NV_ESC_ALLOC_OS_EVENT | NV_ESC_FREE_OS_EVENT => {
                self.dispatch_fd_carrying(cookie, host_fd, request, escape, param_in, resp_buf)
            }

            NV_ESC_RM_ALLOC_MEMORY => {
                // The older of the two allocation escapes, and it carries its class inside the parameters rather than beside them.
                if let Some(route) = self.registration_by_address(escape, None, param_in) {
                    return self.serve_registration(
                        cookie, host_fd, request, route, 0, param_in, deep_in, resp_buf,
                    );
                }
                self.dispatch_fd_carrying(cookie, host_fd, request, escape, param_in, resp_buf)
            }

            NV_ESC_RM_MAP_MEMORY => {
                self.dispatch_map_memory(cookie, host_fd, request, param_in, resp_buf)
            }

            NV_ESC_RM_UNMAP_MEMORY => {
                self.dispatch_unmap_memory(cookie, host_fd, request, param_in, resp_buf)
            }

            NV_ESC_RM_GET_EVENT_DATA => {
                if ireq.data_len != 16 || ireq.nested_len != 16 || ireq.deep_len != 0 {
                    return self.write_error_resp(
                        resp_buf,
                        Status::IoctlFailed,
                        cookie,
                        libc::EINVAL,
                    );
                }
                self.dispatch_event_data(cookie, host_fd, request, param_in, resp_buf)
            }

            NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO => self
                .dispatch_update_device_mapping_info(cookie, host_fd, request, param_in, resp_buf),

            // --------------------------------------------------------------- RM control requires nested handling ---------------------------------------------------------------
            NV_ESC_RM_CONTROL => {
                // Counted here rather than in the forwarder, which holds only a shared borrow.
                if param_in.len() >= 12 {
                    let cmd = u32::from_le_bytes(param_in[8..12].try_into().unwrap());
                    *self.rm_controls.entry(cmd).or_insert(0) += 1;
                    // RM's own rule, applied on the guest's behalf.
                    let declared = if param_in.len() >= 28 {
                        u32::from_le_bytes(param_in[24..28].try_into().unwrap())
                    } else {
                        0
                    };
                    let sent = ireq.nested_len;
                    if let Some(why) = self.rm_control_refusal(cmd, declared, sent) {
                        return self.refuse_control(cookie, cmd, why, param_in, resp_buf);
                    }
                }
                self.dispatch_nested(
                    cookie, host_fd, request, param_in, resp_buf, 32, 16, 24, deep_in, None,
                )
            }

            // --------------------------------------------------------------- RM alloc as well.. ---------------------------------------------------------------
            NV_ESC_RM_ALLOC => {
                // NVOS64: hRoot, hObjectParent, hObjectNew, hClass at byte 12.
                if param_in.len() >= 16 {
                    let class = u32::from_le_bytes(param_in[12..16].try_into().unwrap());
                    *self.rm_classes.entry(class).or_insert(0) += 1;
                    if let Some(bit) = crate::caps::Caps::for_class(class)
                        && !self.caps.has(bit)
                    {
                        return self.refuse_alloc_class(cookie, class, bit, param_in, resp_buf);
                    }
                    // The cap is a decision somebody made; this is RM's.
                    let have = ireq.nested_len as usize;
                    if let Some(why) = self.rm_class_refusal(class, have) {
                        return self.refuse_alloc(cookie, class, why, param_in, resp_buf);
                    }
                    // RM marks this class non-privileged, so the allowlist above lets it through: RM is right, for a caller whose address space is its own.
                    let nested = &param_in[(ireq.data_len as usize).min(param_in.len())..];
                    if let Some(route) = self.registration_by_address(escape, Some(class), nested) {
                        return self.serve_registration(
                            cookie,
                            host_fd,
                            request,
                            route,
                            ireq.data_len as usize,
                            param_in,
                            deep_in,
                            resp_buf,
                        );
                    }
                }
                self.dispatch_nested(
                    cookie, host_fd, request, param_in, resp_buf, 48, 16, 32, deep_in, None,
                )
            }

            // The heap ioctl is a union, and exactly one of its functions names memory by a CPU address.
            NV_ESC_RM_VID_HEAP_CONTROL => {
                if let Some(route) = self.registration_by_address(escape, None, param_in) {
                    return self.serve_registration(
                        cookie, host_fd, request, route, 0, param_in, deep_in, resp_buf,
                    );
                }
                self.dispatch_simple(cookie, host_fd, request, param_in, resp_buf)
            }

            // --------------------------------------------------------------- Everything else — simple passthrough to host ---------------------------------------------------------------
            _other => {
                if _other == 0x5E {
                    log::warn!("0x5E hit DEFAULT arm instead of dedicated handler!");
                }
                if _other == 0x00 {
                    log::debug!(
                        "MODESET IOCTL: handle={} request=0x{:x} param_in={:02x?}",
                        self.current_handle,
                        request,
                        &param_in[..std::cmp::min(param_in.len(), 16)]
                    );
                }
                self.dispatch_simple(cookie, host_fd, request, param_in, resp_buf)
            }
        }
    }
}
