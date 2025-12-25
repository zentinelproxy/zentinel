use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;
use tracing::{debug, error, warn};

// Include the generated bindings
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod ffi {
    #![allow(clippy::all)]
    #[cfg(not(feature = "standalone"))]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    #[cfg(feature = "standalone")]
    pub type ModSecurityIntervention = crate::modsecurity::ModSecurityIntervention;
}

// Re-export intervention struct
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ModSecurityIntervention {
    pub status: i32,
    pub pause: i32,
    pub url: *mut c_char,
    pub log: *mut c_char,
    pub disruptive: i32,
}

impl Default for ModSecurityIntervention {
    fn default() -> Self {
        ModSecurityIntervention {
            status: 0,
            pause: 0,
            url: ptr::null_mut(),
            log: ptr::null_mut(),
            disruptive: 0,
        }
    }
}

impl Drop for ModSecurityIntervention {
    fn drop(&mut self) {
        unsafe {
            if !self.url.is_null() {
                libc::free(self.url as *mut c_void);
                self.url = ptr::null_mut();
            }
            if !self.log.is_null() {
                libc::free(self.log as *mut c_void);
                self.log = ptr::null_mut();
            }
        }
    }
}

// External FFI functions (linked from modsec_wrapper.c)
#[cfg(not(feature = "standalone"))]
extern "C" {
    fn modsec_init() -> *mut c_void;
    fn modsec_cleanup(modsec: *mut c_void);
    fn modsec_create_rules_set() -> *mut c_void;
    fn modsec_add_rules_file(rules_set: *mut c_void, file: *const c_char) -> c_int;
    fn modsec_add_rules(rules_set: *mut c_void, rules: *const c_char) -> c_int;
    fn modsec_get_rules_count(rules_set: *mut c_void) -> c_int;
    fn modsec_new_transaction(
        modsec: *mut c_void,
        rules_set: *mut c_void,
        log_cb: *mut c_void,
    ) -> *mut c_void;
    fn modsec_process_connection(
        transaction: *mut c_void,
        client_ip: *const c_char,
        client_port: c_int,
        server_ip: *const c_char,
        server_port: c_int,
    ) -> c_int;
    fn modsec_process_uri(
        transaction: *mut c_void,
        uri: *const c_char,
        protocol: *const c_char,
        http_version: *const c_char,
    ) -> c_int;
    fn modsec_process_request_headers(transaction: *mut c_void) -> c_int;
    fn modsec_add_request_header(
        transaction: *mut c_void,
        key: *const c_char,
        value: *const c_char,
    ) -> c_int;
    fn modsec_process_request_body(transaction: *mut c_void) -> c_int;
    fn modsec_append_request_body(transaction: *mut c_void, body: *const u8, size: usize) -> c_int;
    fn modsec_process_response_headers(
        transaction: *mut c_void,
        status_code: c_int,
        protocol: *const c_char,
    ) -> c_int;
    fn modsec_add_response_header(
        transaction: *mut c_void,
        key: *const c_char,
        value: *const c_char,
    ) -> c_int;
    fn modsec_process_response_body(transaction: *mut c_void) -> c_int;
    fn modsec_append_response_body(transaction: *mut c_void, body: *const u8, size: usize)
        -> c_int;
    fn modsec_intervention(
        transaction: *mut c_void,
        intervention: *mut ModSecurityIntervention,
    ) -> c_int;
    fn modsec_get_variable(transaction: *mut c_void, name: *const c_char) -> *const c_char;
    fn modsec_get_transaction_id(transaction: *mut c_void) -> *const c_char;
    fn modsec_process_logging(transaction: *mut c_void) -> c_int;
    fn modsec_transaction_cleanup(transaction: *mut c_void);
    fn modsec_get_version() -> *const c_char;
    fn modsec_set_log_callback(
        modsec: *mut c_void,
        callback: Option<extern "C" fn(*mut c_void, c_int, *const c_char)>,
        cb_data: *mut c_void,
    );
}

// Log callback for ModSecurity
extern "C" fn modsec_log_callback(_cb_data: *mut c_void, level: c_int, message: *const c_char) {
    let msg = unsafe {
        if message.is_null() {
            return;
        }
        CStr::from_ptr(message).to_string_lossy()
    };

    match level {
        1 => error!("ModSecurity: {}", msg),
        2 => warn!("ModSecurity: {}", msg),
        3 | 4 => debug!("ModSecurity: {}", msg),
        _ => debug!("ModSecurity [{}]: {}", level, msg),
    }
}

/// ModSecurity engine wrapper
pub struct ModSecurity {
    handle: *mut c_void,
    _phantom: std::marker::PhantomData<*mut c_void>,
}

unsafe impl Send for ModSecurity {}
unsafe impl Sync for ModSecurity {}

impl ModSecurity {
    /// Create a new ModSecurity instance
    pub fn new() -> Result<Self> {
        #[cfg(feature = "standalone")]
        {
            Ok(ModSecurity {
                handle: ptr::null_mut(),
                _phantom: std::marker::PhantomData,
            })
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let handle = modsec_init();
            if handle.is_null() {
                anyhow::bail!("Failed to initialize ModSecurity");
            }

            // Set up logging callback
            modsec_set_log_callback(handle, Some(modsec_log_callback), ptr::null_mut());

            Ok(ModSecurity {
                handle,
                _phantom: std::marker::PhantomData,
            })
        }
    }

    /// Get ModSecurity version
    pub fn version() -> String {
        #[cfg(feature = "standalone")]
        {
            return "standalone-mock".to_string();
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let version_ptr = modsec_get_version();
            if version_ptr.is_null() {
                return "unknown".to_string();
            }
            CStr::from_ptr(version_ptr).to_string_lossy().into_owned()
        }
    }
}

impl Drop for ModSecurity {
    fn drop(&mut self) {
        #[cfg(not(feature = "standalone"))]
        unsafe {
            if !self.handle.is_null() {
                modsec_cleanup(self.handle);
            }
        }
    }
}

/// ModSecurity rules set
pub struct RulesSet {
    handle: *mut c_void,
    rules_count: Arc<Mutex<i32>>,
}

unsafe impl Send for RulesSet {}
unsafe impl Sync for RulesSet {}

impl RulesSet {
    /// Create a new rules set
    pub fn new() -> Result<Self> {
        #[cfg(feature = "standalone")]
        {
            Ok(RulesSet {
                handle: ptr::null_mut(),
                rules_count: Arc::new(Mutex::new(0)),
            })
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let handle = modsec_create_rules_set();
            if handle.is_null() {
                anyhow::bail!("Failed to create ModSecurity rules set");
            }

            Ok(RulesSet {
                handle,
                rules_count: Arc::new(Mutex::new(0)),
            })
        }
    }

    /// Load rules from file
    pub fn load_file(&self, path: &str) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone mode: would load rules from {}", path);
            *self.rules_count.lock() += 100; // Mock some rules
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_path = CString::new(path).context("Invalid path string")?;

            let ret = modsec_add_rules_file(self.handle, c_path.as_ptr());
            if ret < 0 {
                anyhow::bail!("Failed to load rules from file: {}", path);
            }

            let count = modsec_get_rules_count(self.handle);
            *self.rules_count.lock() = count;

            debug!("Loaded {} rules from {}", count, path);
            Ok(())
        }
    }

    /// Load rules from string
    pub fn load_rules(&self, rules: &str) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone mode: would load {} bytes of rules", rules.len());
            *self.rules_count.lock() += 10;
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_rules = CString::new(rules).context("Invalid rules string")?;

            let ret = modsec_add_rules(self.handle, c_rules.as_ptr());
            if ret < 0 {
                anyhow::bail!("Failed to load rules");
            }

            let count = modsec_get_rules_count(self.handle);
            *self.rules_count.lock() = count;

            debug!("Loaded {} total rules", count);
            Ok(())
        }
    }

    /// Get the number of loaded rules
    pub fn rules_count(&self) -> i32 {
        *self.rules_count.lock()
    }
}

impl Drop for RulesSet {
    fn drop(&mut self) {
        // ModSecurity will clean up rules set when engine is destroyed
    }
}

/// ModSecurity transaction
pub struct Transaction {
    handle: *mut c_void,
    intervention: ModSecurityIntervention,
    transaction_id: String,
}

unsafe impl Send for Transaction {}

impl Transaction {
    /// Create a new transaction
    pub fn new(modsec: &ModSecurity, rules: &RulesSet) -> Result<Self> {
        #[cfg(feature = "standalone")]
        {
            let transaction_id = uuid::Uuid::new_v4().to_string();
            Ok(Transaction {
                handle: ptr::null_mut(),
                intervention: Default::default(),
                transaction_id,
            })
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let handle = modsec_new_transaction(modsec.handle, rules.handle, ptr::null_mut());

            if handle.is_null() {
                anyhow::bail!("Failed to create ModSecurity transaction");
            }

            let transaction_id = {
                let id_ptr = modsec_get_transaction_id(handle);
                if id_ptr.is_null() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    CStr::from_ptr(id_ptr).to_string_lossy().into_owned()
                }
            };

            Ok(Transaction {
                handle,
                intervention: Default::default(),
                transaction_id,
            })
        }
    }

    /// Get transaction ID
    pub fn id(&self) -> &str {
        &self.transaction_id
    }

    /// Process connection information
    pub fn process_connection(
        &mut self,
        client_ip: &str,
        client_port: u16,
        server_ip: &str,
        server_port: u16,
    ) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!(
                "Standalone: process connection {}:{} -> {}:{}",
                client_ip, client_port, server_ip, server_port
            );
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_client_ip = CString::new(client_ip)?;
            let c_server_ip = CString::new(server_ip)?;

            let ret = modsec_process_connection(
                self.handle,
                c_client_ip.as_ptr(),
                client_port as c_int,
                c_server_ip.as_ptr(),
                server_port as c_int,
            );

            if ret != 0 {
                anyhow::bail!("Failed to process connection");
            }

            Ok(())
        }
    }

    /// Process URI
    pub fn process_uri(&mut self, uri: &str, method: &str, http_version: &str) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!(
                "Standalone: process URI {} {} {}",
                method, uri, http_version
            );
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_uri = CString::new(uri)?;
            let c_method = CString::new(method)?;
            let c_version = CString::new(http_version)?;

            let ret = modsec_process_uri(
                self.handle,
                c_uri.as_ptr(),
                c_method.as_ptr(),
                c_version.as_ptr(),
            );

            if ret != 0 {
                anyhow::bail!("Failed to process URI");
            }

            Ok(())
        }
    }

    /// Add request header
    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: add request header {}: {}", name, value);
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_name = CString::new(name)?;
            let c_value = CString::new(value)?;

            let ret = modsec_add_request_header(self.handle, c_name.as_ptr(), c_value.as_ptr());

            if ret != 0 {
                anyhow::bail!("Failed to add request header");
            }

            Ok(())
        }
    }

    /// Process request headers
    pub fn process_request_headers(&mut self) -> Result<bool> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: process request headers");
            return Ok(false);
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let ret = modsec_process_request_headers(self.handle);
            if ret != 0 {
                // Check for intervention
                modsec_intervention(self.handle, &mut self.intervention);
                if self.intervention.disruptive != 0 {
                    return Ok(true);
                }
            }

            Ok(false)
        }
    }

    /// Append request body
    pub fn append_request_body(&mut self, body: &[u8]) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: append {} bytes of request body", body.len());
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let ret = modsec_append_request_body(self.handle, body.as_ptr(), body.len());

            if ret != 0 {
                anyhow::bail!("Failed to append request body");
            }

            Ok(())
        }
    }

    /// Process request body
    pub fn process_request_body(&mut self) -> Result<bool> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: process request body");
            return Ok(false);
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let ret = modsec_process_request_body(self.handle);
            if ret != 0 {
                // Check for intervention
                modsec_intervention(self.handle, &mut self.intervention);
                if self.intervention.disruptive != 0 {
                    return Ok(true);
                }
            }

            Ok(false)
        }
    }

    /// Add response header
    pub fn add_response_header(&mut self, name: &str, value: &str) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: add response header {}: {}", name, value);
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_name = CString::new(name)?;
            let c_value = CString::new(value)?;

            let ret = modsec_add_response_header(self.handle, c_name.as_ptr(), c_value.as_ptr());

            if ret != 0 {
                anyhow::bail!("Failed to add response header");
            }

            Ok(())
        }
    }

    /// Process response headers
    pub fn process_response_headers(&mut self, status_code: u16, protocol: &str) -> Result<bool> {
        #[cfg(feature = "standalone")]
        {
            debug!(
                "Standalone: process response headers {} {}",
                status_code, protocol
            );
            return Ok(false);
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_protocol = CString::new(protocol)?;

            let ret = modsec_process_response_headers(
                self.handle,
                status_code as c_int,
                c_protocol.as_ptr(),
            );

            if ret != 0 {
                // Check for intervention
                modsec_intervention(self.handle, &mut self.intervention);
                if self.intervention.disruptive != 0 {
                    return Ok(true);
                }
            }

            Ok(false)
        }
    }

    /// Append response body
    pub fn append_response_body(&mut self, body: &[u8]) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: append {} bytes of response body", body.len());
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let ret = modsec_append_response_body(self.handle, body.as_ptr(), body.len());

            if ret != 0 {
                anyhow::bail!("Failed to append response body");
            }

            Ok(())
        }
    }

    /// Process response body
    pub fn process_response_body(&mut self) -> Result<bool> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: process response body");
            return Ok(false);
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let ret = modsec_process_response_body(self.handle);
            if ret != 0 {
                // Check for intervention
                modsec_intervention(self.handle, &mut self.intervention);
                if self.intervention.disruptive != 0 {
                    return Ok(true);
                }
            }

            Ok(false)
        }
    }

    /// Process logging
    pub fn process_logging(&mut self) -> Result<()> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: process logging");
            return Ok(());
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            modsec_process_logging(self.handle);
            Ok(())
        }
    }

    /// Get intervention details
    pub fn get_intervention(&mut self) -> Option<Intervention> {
        #[cfg(feature = "standalone")]
        {
            return None;
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            modsec_intervention(self.handle, &mut self.intervention);

            if self.intervention.disruptive != 0 {
                let url = if !self.intervention.url.is_null() {
                    Some(
                        CStr::from_ptr(self.intervention.url)
                            .to_string_lossy()
                            .into_owned(),
                    )
                } else {
                    None
                };

                let log = if !self.intervention.log.is_null() {
                    Some(
                        CStr::from_ptr(self.intervention.log)
                            .to_string_lossy()
                            .into_owned(),
                    )
                } else {
                    None
                };

                Some(Intervention {
                    disruptive: true,
                    status: self.intervention.status,
                    pause: self.intervention.pause,
                    url,
                    log,
                })
            } else {
                None
            }
        }
    }

    /// Get a ModSecurity variable value
    pub fn get_variable(&self, name: &str) -> Option<String> {
        #[cfg(feature = "standalone")]
        {
            debug!("Standalone: get variable {}", name);
            return None;
        }

        #[cfg(not(feature = "standalone"))]
        unsafe {
            let c_name = match CString::new(name) {
                Ok(s) => s,
                Err(_) => return None,
            };

            let value_ptr = modsec_get_variable(self.handle, c_name.as_ptr());
            if value_ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(value_ptr).to_string_lossy().into_owned())
            }
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        #[cfg(not(feature = "standalone"))]
        unsafe {
            if !self.handle.is_null() {
                modsec_transaction_cleanup(self.handle);
            }
        }
    }
}

/// Intervention details
#[derive(Debug, Clone)]
pub struct Intervention {
    pub disruptive: bool,
    pub status: i32,
    pub pause: i32,
    pub url: Option<String>,
    pub log: Option<String>,
}

impl Intervention {
    /// Get HTTP status code for the intervention
    pub fn http_status(&self) -> u16 {
        match self.status {
            403 => 403, // Forbidden
            302 => 302, // Redirect
            _ => 403,   // Default to forbidden
        }
    }

    /// Check if this is a redirect
    pub fn is_redirect(&self) -> bool {
        self.status == 302 && self.url.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modsecurity_version() {
        let version = ModSecurity::version();
        assert!(!version.is_empty());
        println!("ModSecurity version: {}", version);
    }

    #[test]
    fn test_modsecurity_init() {
        let modsec = ModSecurity::new();
        assert!(modsec.is_ok());
    }

    #[test]
    fn test_rules_set_creation() {
        let rules = RulesSet::new();
        assert!(rules.is_ok());

        let rules = rules.unwrap();
        assert_eq!(rules.rules_count(), 0);
    }

    #[test]
    fn test_transaction_creation() {
        let modsec = ModSecurity::new().unwrap();
        let rules = RulesSet::new().unwrap();

        let transaction = Transaction::new(&modsec, &rules);
        assert!(transaction.is_ok());

        let transaction = transaction.unwrap();
        assert!(!transaction.id().is_empty());
    }
}
