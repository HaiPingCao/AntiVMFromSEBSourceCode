use std::ptr::null_mut;
use std::slice;

// Windows error code indicating a successful API call
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

// APIs and structures used to enumerate network adapters
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};

// Address family used to request both IPv4 and IPv6 adapters
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

// Windows Registry APIs and constants
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegCloseKey, RegOpenKeyExA, RegQueryValueExA,
};

/// Stateless detector implementing multiple heuristics
/// to identify execution inside a virtual machine.
pub struct VirtualMachineDetector;

impl VirtualMachineDetector {
    /// Constructs a new detector instance.
    /// No internal state is required.
    pub fn new() -> Self {
        Self
    }

    /// Executes all VM detection heuristics and aggregates results.
    /// Returns true if any heuristic indicates virtualization.
    pub fn is_virtual_machine(&self) -> bool {
        let mut is_vm = false;

        println!("Running Heuristics...");

        // MAC address heuristic:
        // Detects virtual NIC vendors on active adapters
        if self.check_mac_address() {
            println!("[!] Virtual MAC Address detected on PRIMARY/Active Interface.");
            is_vm = true;
        }

        // BIOS / manufacturer heuristic:
        // Reads firmware identifiers commonly exposed by hypervisors
        if self.check_bios_strings() {
            println!("[!] Virtual BIOS/Manufacturer strings detected.");
            is_vm = true;
        }

        // Service / driver heuristic:
        // Checks for known VM-related kernel drivers and services
        if self.check_virtual_services() {
            println!("[!] Virtual Machine Tools/Drivers detected.");
            is_vm = true;
        }

        is_vm
    }

    /// Checks the MAC address of non-host network adapters
    /// against known OUI prefixes used by virtualization vendors.
    fn check_mac_address(&self) -> bool {
        // Known Organizationally Unique Identifiers (OUIs)
        // assigned to virtual network adapters
        let blacklisted_ouis = [
            [0x00, 0x00, 0x00],
            [0x52, 0x54, 0x00], // QEMU
            [0x08, 0x00, 0x27], // VirtualBox
            [0x00, 0x0C, 0x29], // VMware
            [0x00, 0x50, 0x56], // VMware
        ];

        // Initial buffer size recommended by Microsoft documentation
        let mut buffer_len = 15000;
        let mut buffer = vec![0u8; buffer_len as usize];

        // Raw pointer cast required by the Windows API
        let addresses: *mut IP_ADAPTER_ADDRESSES_LH = buffer.as_mut_ptr() as *mut _;

        /*
          Enumerates all network adapters on the system.

          Safety considerations:
          - `addresses` must point to a valid writable buffer
          - `buffer_len` may be updated if the buffer is insufficient
          - Returned linked list must be traversed using raw pointers
        */
        unsafe {
            let ret = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                null_mut(),
                addresses,
                &mut buffer_len,
            );

            // Abort heuristic if adapter enumeration fails
            if ret != ERROR_SUCCESS {
                return false;
            }

            // Iterate through the linked list of adapters
            let mut curr = addresses;
            while !curr.is_null() {
                let addr = &*curr;

                // Adapter description is used to filter out host-only adapters
                let description = self.parse_wide_string(addr.Description);
                let desc_lower = description.to_lowercase();

                // Host-only or bridge adapters are ignored
                let is_host_adapter = desc_lower.contains("vmware")
                    || desc_lower.contains("virtualbox")
                    || desc_lower.contains("host-only");

                // Only check adapters with a valid MAC address length
                if !is_host_adapter && addr.PhysicalAddressLength >= 3 {
                    let mac = &addr.PhysicalAddress;

                    // Compare the first three bytes (OUI) against known VM vendors
                    for oui in &blacklisted_ouis {
                        if mac[0] == oui[0] && mac[1] == oui[1] && mac[2] == oui[2] {
                            println!(
                                "    -> Suspicious Adapter: {} (MAC: {:02X}:{:02X}:{:02X})",
                                description, mac[0], mac[1], mac[2]
                            );
                            return true;
                        }
                    }
                }

                // Move to the next adapter in the linked list
                curr = addr.Next;
            }
        }
        false
    }

    /// Reads BIOS-related registry values commonly populated
    /// by virtual machine firmware implementations.
    fn check_bios_strings(&self) -> bool {
        // Registry values that frequently expose VM identifiers
        let keys_to_check = ["SystemManufacturer", "SystemProductName", "BIOSVersion"];

        // BIOS information registry path
        let path = "HARDWARE\\DESCRIPTION\\System\\BIOS\0";
        let mut found_vm = false;

        /*
          Opens the BIOS registry key and scans known values.

          Detection logic:
          - Matches known hypervisor vendors
          - Allows Microsoft systems unless Surface-class hardware
        */
        if let Ok(hkey) = self.open_registry_key(HKEY_LOCAL_MACHINE, path) {
            for key in &keys_to_check {
                if let Ok(value) = self.read_registry_string(hkey, key) {
                    let v = value.to_lowercase();

                    if v.contains("virtualbox")
                        || v.contains("vmware")
                        || v.contains("qemu")
                        || v.contains("kvm")
                        || v.contains("parallels")
                        || (v.contains("microsoft corporation")
                            && !v.contains("surface")
                            && !v.contains("z490"))
                    {
                        found_vm = true;
                        break;
                    }
                }
            }

            // Registry handle must always be closed
            unsafe { RegCloseKey(hkey) };
        }

        found_vm
    }

    /// Detects installed VM-related drivers and services
    /// by probing known service registry keys.
    fn check_virtual_services(&self) -> bool {
        // Common VM service and driver names
        let services = [
            "VBoxGuest",
            "VBoxMouse",
            "VBoxService",
            "VMTools",
            "vm3dmp",
            "vmusbmouse",
        ];

        let base_path = "SYSTEM\\CurrentControlSet\\Services\\";

        // Presence of any service key is sufficient for detection
        for service in services {
            let full_path = format!("{}{}\0", base_path, service);

            if let Ok(hkey) = self.open_registry_key(HKEY_LOCAL_MACHINE, &full_path) {
                unsafe { RegCloseKey(hkey) };
                return true;
            }
        }
        false
    }

    /// Opens a registry key in read-only mode.
    /// Caller is responsible for closing the handle.
    fn open_registry_key(&self, root: HKEY, path: &str) -> Result<HKEY, u32> {
        let mut hkey: HKEY = 0;

        unsafe {
            let ret = RegOpenKeyExA(root, path.as_ptr(), 0, KEY_READ, &mut hkey);

            if ret == ERROR_SUCCESS {
                Ok(hkey)
            } else {
                Err(ret)
            }
        }
    }

    /// Reads a null-terminated REG_SZ value from the registry
    /// and converts it to a Rust UTF-8 String.
    fn read_registry_string(&self, key: HKEY, value_name: &str) -> Result<String, u32> {
        let mut buffer = [0u8; 256];
        let mut len = buffer.len() as u32;
        let mut val_type = 0;

        // Value names must be explicitly null-terminated
        let c_value_name = format!("{}\0", value_name);

        unsafe {
            let ret = RegQueryValueExA(
                key,
                c_value_name.as_ptr(),
                null_mut(),
                &mut val_type,
                buffer.as_mut_ptr(),
                &mut len,
            );

            if ret == ERROR_SUCCESS && val_type == REG_SZ {
                // Strip trailing null byte if present
                let actual_len = if len > 0 && buffer[(len - 1) as usize] == 0 {
                    len - 1
                } else {
                    len
                };

                let s = std::str::from_utf8(&buffer[..actual_len as usize]).unwrap_or("");

                Ok(s.to_string())
            } else {
                Err(ret)
            }
        }
    }

    /*
      Converts a null-terminated UTF-16 wide string
      returned by Windows APIs into a Rust String.

      Safety requirements:
      - `ptr` must reference valid readable memory
      - The string must be properly null-terminated
    */
    unsafe fn parse_wide_string(&self, ptr: *mut u16) -> String {
        if ptr.is_null() {
            return String::new();
        }

        let mut len = 0;

        // Count UTF-16 code units until null terminator
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
        }

        // Create a slice from the raw pointer and length
        let slice = unsafe { slice::from_raw_parts(ptr, len) };

        String::from_utf16_lossy(slice)
    }
}
