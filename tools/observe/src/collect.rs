//! Capturing the machine.
//!
//! The only module here that touches Win32, and the only one that cannot be
//! tested on Linux. Everything it produces is [`crate::model`] data, so the
//! differ and the draft generator never see a handle.
//!
//! # Read-only, structurally
//!
//! `docs/16-OBSERVATION-HARNESS.md`: "Snapshots are **read-only**. The harness
//! has no removal code path at all — it is a separate binary from the broker
//! for exactly this reason."
//!
//! The service control manager is opened with `SC_MANAGER_ENUMERATE_SERVICE`
//! and each service with `SERVICE_QUERY_CONFIG`. Neither grants the rights that
//! would let this binary change or delete anything, so the read-only claim is
//! enforced by the handles it holds rather than by the calls it happens to
//! make. `core/tests/no_destructive_code.rs` covers this directory too.

use crate::model::{AccessDenied, Coverage, Domain, ServiceRecord, Snapshot};

/// Everything one domain's collector returns.
pub struct Captured {
    /// The records themselves.
    pub services: Vec<ServiceRecord>,
    /// Items that could not be read, with the platform's reason.
    pub access_denied: Vec<AccessDenied>,
}

/// Take a snapshot of every domain this build can capture.
///
/// # Errors
/// If the platform refuses the enumeration outright. Individual items that
/// cannot be read are recorded in [`Coverage::access_denied`] rather than
/// failing the snapshot: a machine where three services are unreadable is still
/// worth capturing, provided the file says which three.
pub fn snapshot(label: &str, taken_utc: String) -> anyhow::Result<Snapshot> {
    let captured = services()?;

    // Exactly one domain so far. The others are named as not captured rather
    // than omitted, so a diff cannot present their absence as "nothing changed
    // there" — see the module comment on `crate::model`.
    let coverage = Coverage {
        captured: vec![Domain::Services],
        not_captured: Domain::all()
            .into_iter()
            .filter(|domain| *domain != Domain::Services)
            .collect(),
        access_denied: captured.access_denied,
    };

    Ok(Snapshot {
        format_version: crate::model::SNAPSHOT_FORMAT_VERSION,
        taken_utc,
        harness_version: env!("CARGO_PKG_VERSION").to_owned(),
        label: label.to_owned(),
        coverage,
        services: captured.services,
    })
}

#[cfg(not(windows))]
/// Not available off Windows.
///
/// The crate still builds and its pure-logic half still runs its tests there,
/// which is what the ubuntu lint job in `rust-ci.yml` exercises.
///
/// # Errors
/// Always.
pub fn services() -> anyhow::Result<Captured> {
    anyhow::bail!("snapshot requires Windows; the diff and suggest commands do not")
}

#[cfg(windows)]
pub use self::win32::services;

#[cfg(windows)]
mod win32 {
    use anyhow::{Context, Result, bail};
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
    use windows::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW,
        SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
        SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW, SERVICE_DRIVER,
        SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
    };
    use windows::core::PCWSTR;

    use super::Captured;
    use crate::model::{AccessDenied, Domain, ServiceRecord};

    /// A byte buffer aligned for the structures the SCM writes into it.
    ///
    /// `vec![0u8; n]` has an alignment of 1. Every one of these calls writes a
    /// structure containing pointers at the head of the buffer, so reading one
    /// back through a `*const u8` cast is undefined behaviour unless the
    /// allocation is aligned for it. The global allocator happens to oblige for
    /// buffers this size, which is exactly why the bug would never show up in
    /// testing — backing the buffer with `u64` makes the alignment a property
    /// of the type instead of a property of today's allocator.
    struct Aligned(Vec<u64>);

    impl Aligned {
        fn new(bytes: usize) -> Self {
            Self(vec![0u64; bytes.div_ceil(size_of::<u64>()).max(1)])
        }

        fn as_mut_bytes(&mut self) -> &mut [u8] {
            // SAFETY: a u64 slice is a valid byte slice of eight times the
            // length, and u8 has no alignment or validity requirement.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.0.as_mut_ptr().cast::<u8>(),
                    self.0.len() * size_of::<u64>(),
                )
            }
        }

        fn as_ptr<T>(&self) -> *const T {
            self.0.as_ptr().cast::<T>()
        }

        fn as_mut_ptr<T>(&mut self) -> *mut T {
            self.0.as_mut_ptr().cast::<T>()
        }
    }

    /// An `SC_HANDLE` that closes itself.
    struct Handle(SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: a handle this type owns and has not closed.
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(pointer: windows::core::PWSTR) -> String {
        if pointer.is_null() {
            return String::new();
        }
        // SAFETY: the SCM returns NUL-terminated wide strings inside the buffer
        // the caller supplied, which is alive for the duration of the read.
        unsafe { pointer.to_string() }.unwrap_or_default()
    }

    /// A `REG_MULTI_SZ`-style double-NUL-terminated list.
    fn multi_string(pointer: windows::core::PWSTR) -> Vec<String> {
        if pointer.is_null() {
            return Vec::new();
        }

        let mut values = Vec::new();
        let mut cursor = pointer.0;
        loop {
            // SAFETY: cursor walks a double-NUL-terminated wide buffer owned by
            // the caller's allocation; the outer NUL terminates the walk.
            let length = unsafe {
                let mut length = 0usize;
                while *cursor.add(length) != 0 {
                    length += 1;
                }
                length
            };
            if length == 0 {
                break;
            }
            // SAFETY: length is the count of non-NUL units just measured.
            let slice = unsafe { std::slice::from_raw_parts(cursor, length) };
            values.push(String::from_utf16_lossy(slice));
            // SAFETY: step past this string and its terminator.
            cursor = unsafe { cursor.add(length + 1) };
        }
        values
    }

    fn service_type_name(flags: u32) -> String {
        let mut parts = Vec::new();
        if flags & 0x0000_0001 != 0 {
            parts.push("kernel_driver");
        }
        if flags & 0x0000_0002 != 0 {
            parts.push("file_system_driver");
        }
        if flags & 0x0000_0010 != 0 {
            parts.push("win32_own_process");
        }
        if flags & 0x0000_0020 != 0 {
            parts.push("win32_share_process");
        }
        if flags & 0x0000_0040 != 0 {
            parts.push("user_own_process");
        }
        if flags & 0x0000_0080 != 0 {
            parts.push("user_share_process");
        }
        if flags & 0x0000_0100 != 0 {
            parts.push("interactive_process");
        }
        if parts.is_empty() {
            return format!("unknown(0x{flags:08x})");
        }
        parts.join("|")
    }

    fn start_type_name(value: u32) -> &'static str {
        match value {
            0 => "boot",
            1 => "system",
            2 => "auto",
            3 => "demand",
            4 => "disabled",
            _ => "unknown",
        }
    }

    fn error_control_name(value: u32) -> &'static str {
        match value {
            0 => "ignore",
            1 => "normal",
            2 => "severe",
            3 => "critical",
            _ => "unknown",
        }
    }

    /// Enumerate every service and driver, and read each one's configuration.
    ///
    /// # Errors
    /// If the service control manager cannot be opened or enumerated.
    pub fn services() -> Result<Captured> {
        // SAFETY: null machine and database name mean the local SCM and the
        // active database. ENUMERATE_SERVICE is the weakest right that answers
        // the question and grants nothing that could modify a service.
        let manager = unsafe {
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE)
                .context("OpenSCManagerW(SC_MANAGER_ENUMERATE_SERVICE)")?
        };
        let manager = Handle(manager);

        let entries = enumerate(manager.0)?;

        let mut services = Vec::with_capacity(entries.len());
        let mut access_denied = Vec::new();

        for (name, display_name) in entries {
            match configuration(manager.0, &name, &display_name) {
                Ok(record) => services.push(record),
                Err(error) => access_denied.push(AccessDenied {
                    domain: Domain::Services,
                    item: name,
                    // Recorded, not skipped. A service that could not be read is
                    // not a service that is absent, and a later diff must be
                    // able to tell the two apart.
                    reason: format!("{error:#}"),
                }),
            }
        }

        services.sort_by(|a, b| a.name.cmp(&b.name));
        access_denied.sort_by(|a, b| a.item.cmp(&b.item));

        Ok(Captured {
            services,
            access_denied,
        })
    }

    /// Service key names and display names, via the two-call size idiom.
    fn enumerate(manager: SC_HANDLE) -> Result<Vec<(String, String)>> {
        let mut needed = 0u32;
        let mut returned = 0u32;
        let mut resume = 0u32;

        // SAFETY: a null buffer asks for the required size; the call is
        // expected to fail with ERROR_MORE_DATA.
        let probe = unsafe {
            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                None,
                &raw mut needed,
                &raw mut returned,
                Some(&raw mut resume),
                PCWSTR::null(),
            )
        };
        if let Err(error) = probe {
            let code = error.code().0.cast_unsigned() & 0xFFFF;
            if code != ERROR_MORE_DATA.0 && code != ERROR_INSUFFICIENT_BUFFER.0 {
                bail!("EnumServicesStatusExW size probe failed: {error}");
            }
        }
        if needed == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = Aligned::new(needed as usize);
        resume = 0;
        // SAFETY: buffer is at least the size the probe asked for.
        unsafe {
            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                Some(buffer.as_mut_bytes()),
                &raw mut needed,
                &raw mut returned,
                Some(&raw mut resume),
                PCWSTR::null(),
            )
            .context("EnumServicesStatusExW")?;
        }

        let mut entries = Vec::with_capacity(returned as usize);
        // SAFETY: the SCM wrote `returned` ENUM_SERVICE_STATUS_PROCESSW
        // structures at the head of the buffer, with their strings pointing
        // further into the same allocation.
        let statuses = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr::<ENUM_SERVICE_STATUS_PROCESSW>(),
                returned as usize,
            )
        };
        for status in statuses {
            entries.push((
                from_wide(status.lpServiceName),
                from_wide(status.lpDisplayName),
            ));
        }

        Ok(entries)
    }

    /// One service's configuration.
    fn configuration(manager: SC_HANDLE, name: &str, display_name: &str) -> Result<ServiceRecord> {
        let name_wide = wide(name);
        // SAFETY: name_wide outlives the call. SERVICE_QUERY_CONFIG is
        // read-only; it does not permit reconfiguration or deletion.
        let service = unsafe {
            OpenServiceW(manager, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_CONFIG)
                .with_context(|| format!("OpenServiceW({name}, SERVICE_QUERY_CONFIG)"))?
        };
        let service = Handle(service);

        let mut needed = 0u32;
        // SAFETY: a null buffer asks for the required size.
        let probe = unsafe { QueryServiceConfigW(service.0, None, 0, &raw mut needed) };
        if probe.is_err() && needed == 0 {
            bail!("QueryServiceConfigW size probe returned no size for {name}");
        }

        let mut buffer = Aligned::new(needed as usize);
        // SAFETY: buffer is at least the size just asked for, and
        // QUERY_SERVICE_CONFIGW is written at its head with the strings
        // following.
        unsafe {
            QueryServiceConfigW(
                service.0,
                Some(buffer.as_mut_ptr::<QUERY_SERVICE_CONFIGW>()),
                needed,
                &raw mut needed,
            )
            .with_context(|| format!("QueryServiceConfigW({name})"))?;
        }
        // SAFETY: the call above populated this structure.
        let config = unsafe { &*buffer.as_ptr::<QUERY_SERVICE_CONFIGW>() };

        Ok(ServiceRecord {
            name: name.to_owned(),
            display_name: if display_name.is_empty() {
                from_wide(config.lpDisplayName)
            } else {
                display_name.to_owned()
            },
            service_type: service_type_name(config.dwServiceType.0),
            start_type: start_type_name(config.dwStartType.0).to_owned(),
            error_control: error_control_name(config.dwErrorControl.0).to_owned(),
            binary_path: from_wide(config.lpBinaryPathName),
            load_order_group: from_wide(config.lpLoadOrderGroup),
            start_name: from_wide(config.lpServiceStartName),
            dependencies: multi_string(config.lpDependencies),
            description: description(service.0),
            delayed_auto_start: delayed_auto_start(service.0),
        })
    }

    /// Description text, or empty when none is registered.
    fn description(service: SC_HANDLE) -> String {
        let mut needed = 0u32;
        // SAFETY: null buffer asks for the size.
        let _ = unsafe {
            QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, None, &raw mut needed)
        };
        if needed == 0 {
            return String::new();
        }

        let mut buffer = Aligned::new(needed as usize);
        // SAFETY: buffer is at least the size just asked for.
        let read = unsafe {
            QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                Some(buffer.as_mut_bytes()),
                &raw mut needed,
            )
        };
        if read.is_err() {
            return String::new();
        }

        // SAFETY: the call populated a SERVICE_DESCRIPTIONW at the head.
        let description = unsafe { &*buffer.as_ptr::<SERVICE_DESCRIPTIONW>() };
        from_wide(description.lpDescription)
    }

    /// Whether an automatic-start service is delayed.
    fn delayed_auto_start(service: SC_HANDLE) -> bool {
        let mut needed = 0u32;
        let mut buffer = Aligned::new(size_of::<SERVICE_DELAYED_AUTO_START_INFO>());
        // SAFETY: the buffer is at least one SERVICE_DELAYED_AUTO_START_INFO.
        let read = unsafe {
            QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some(buffer.as_mut_bytes()),
                &raw mut needed,
            )
        };
        if read.is_err() {
            return false;
        }

        // SAFETY: the call populated the structure.
        let info = unsafe { &*buffer.as_ptr::<SERVICE_DELAYED_AUTO_START_INFO>() };
        info.fDelayedAutostart.as_bool()
    }
}
