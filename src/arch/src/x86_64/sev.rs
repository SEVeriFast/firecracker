use std::{
    arch::x86_64::__cpuid,
    convert::TryInto,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::prelude::AsRawFd,
    path::PathBuf,
    sync::Arc,
};

use kvm_bindings::{
    kvm_sev_cmd, kvm_sev_launch_measure, kvm_sev_launch_start, kvm_sev_launch_update_data,
    kvm_snp_init, sev_cmd_id_KVM_SEV_ES_INIT, sev_cmd_id_KVM_SEV_INIT,
    sev_cmd_id_KVM_SEV_LAUNCH_FINISH, sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
    sev_cmd_id_KVM_SEV_LAUNCH_START, sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
    sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA, sev_cmd_id_KVM_SEV_SNP_INIT,
};
use kvm_ioctls::VmFd;
use logger::info;
use thiserror::Error;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

/// Length of intial boot time measurement
const MEASUREMENT_LEN: u32 = 48;
/// Where the SEV firmware will be loaded in guest memory
pub const FIRMWARE_ADDR: GuestAddress = GuestAddress(0x100000);
//From SEV/KVM API SPEC
/// Debugging of the guest is disallowed when set
const POLICY_NOBDG: u32 = 1;
/// Sharing keys with other guests is disallowed when set
const POLICY_NOKS: u32 = 1 << 1;
/// SEV-ES is required when set
const POLICY_ES: u32 = 1 << 2;
/// Sending the guest to another platform is disallowed when set
const POLICY_NOSEND: u32 = 1 << 3;
/// The guest must not be transmitted to another platform that is not in the domain when set
const POLICY_DOMAIN: u32 = 1 << 4;
/// The guest must not be transmitted to another platform that is not SEV capable when set
const POLICY_SEV: u32 = 1 << 5;

//This excludes SUCCESS=0 and ACTIVE=18
#[derive(Debug, Error)]
/// SEV platform errors
pub enum SevError {
    /// The platform state is invalid for this command
    InvalidPlatformState,
    /// The guest state is invalid for this command
    InvalidGuestState,
    /// The platform configuration is invalid
    InvalidConfig,
    /// A memory buffer is too small
    InvalidLength,
    /// The platform is already owned
    AlreadyOwned,
    /// The certificate is invalid
    InvalidCertificate,
    /// Request is not allowed by guest policy
    PolicyFailure,
    /// The guest is inactive
    Inactive,
    /// The address provided is inactive
    InvalidAddress,
    /// The provided signature is invalid
    BadSignature,
    /// The provided measurement is invalid
    BadMeasurement,
    /// The ASID is already owned
    AsidOwned,
    /// The ASID is invalid
    InvalidAsid,
    /// WBINVD instruction required
    WBINVDRequired,
    ///DF_FLUSH invocation required
    DfFlushRequired,
    /// The guest handle is invalid
    InvalidGuest,
    /// The command issued is invalid
    InvalidCommand,
    /// A hardware condition has occurred affecting the platform. It is safe to re-allocate parameter buffers
    HwerrorPlatform,
    /// A hardware condition has occurred affecting the platform. Re-allocating parameter buffers is not safe
    HwerrorUnsafe,
    /// Feature is unsupported
    Unsupported,
    /// A parameter is invalid
    InvalidParam,
    /// The SEV FW has run out of a resource necessary to complete the command
    ResourceLimit,
    /// The part-specific SEV data failed integrity checks
    SecureDataInvalid,
    /// A mailbox mode command was sent while the SEV FW was in Ring Buffer mode.
    RbModeExited,
    /// The RMP page size is incorrect
    InvalidPageSize,
    /// The RMP page state is incorrect
    InvalidPageState,
    /// The metadata entry is invalid
    InvalidMDataEntry,
    /// The page ownership is incorrect
    InvalidPageOwner,
    /// The AEAD algorithm would have overflowed
    AeadOverflow,
    /// The RMP must be reinitialized
    RmpInitRequired,
    /// SVN of provided image is lower than the committed SVN
    BadSvn,
    /// Firmware version anti-rollback
    BadVersion,
    /// An invocation of SNP_SHUTDOWN is required to complete this action
    ShutdownRequired,
    /// Update of the firmware internal state or a guest context page has failed
    UpdateFailed,
    /// Installation of the committed firmware image required
    RestoreRequired,
    /// The RMP initialization failed
    RmpInitFailed,
    /// The key requested is invalid, not present, or not allowed
    InvalidKey,
    /// The error code returned by the SEV device is not valid
    InvalidErrorCode,
    /// Other error code
    Errno(i32),
}
#[derive(Debug)]
/// Temp
pub enum Error {
    /// Error loading SEV firmware
    FirmwareLoad,
}

impl Display for SevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u32> for SevError {
    fn from(code: u32) -> Self {
        match code {
            0x01 => Self::InvalidPlatformState,
            0x02 => Self::InvalidGuestState,
            0x03 => Self::InvalidConfig,
            0x04 => Self::InvalidLength,
            0x05 => Self::AlreadyOwned,
            0x06 => Self::InvalidCertificate,
            0x07 => Self::PolicyFailure,
            0x08 => Self::Inactive,
            0x09 => Self::InvalidAddress,
            0x0a => Self::BadSignature,
            0x0b => Self::BadMeasurement,
            0x0c => Self::AsidOwned,
            0x0d => Self::InvalidAsid,
            0x0e => Self::WBINVDRequired,
            0x0f => Self::DfFlushRequired,
            0x10 => Self::InvalidGuest,
            0x11 => Self::InvalidCommand,
            0x13 => Self::HwerrorPlatform,
            0x14 => Self::HwerrorUnsafe,
            0x15 => Self::Unsupported,
            0x16 => Self::InvalidParam,
            0x17 => Self::ResourceLimit,
            0x18 => Self::SecureDataInvalid,
            0x1F => Self::RbModeExited,
            0x19 => Self::InvalidPageSize,
            0x1a => Self::InvalidPageState,
            0x1b => Self::InvalidMDataEntry,
            0x1c => Self::InvalidPageOwner,
            0x1d => Self::AeadOverflow,
            0x20 => Self::RmpInitRequired,
            0x21 => Self::BadSvn,
            0x22 => Self::BadVersion,
            0x23 => Self::ShutdownRequired,
            0x24 => Self::UpdateFailed,
            0x25 => Self::RestoreRequired,
            0x26 => Self::RmpInitFailed,
            0x27 => Self::InvalidKey,
            _ => Self::InvalidErrorCode,
        }
    }
}

/// SEV result return type
pub type SevResult<T> = std::result::Result<T, SevError>;
/// SEV Guest states
#[derive(PartialEq)]
pub enum State {
    /// The guest is uninitialized
    UnInit,
    /// The SEV platform has been initialized
    Init,
    /// The guest is currently beign launched and plaintext data and VMCB save areas are being imported
    LaunchUpdate,
    /// The guest is currently being launched and ciphertext data are being imported
    LaunchSecret,
    /// The guest is fully launched or migrated in, and not being migrated out to another machine
    Running,
    /// The guest is currently being migrated out to another machine
    SendUpdate,
    /// The guest is currently being migrated from another machine
    RecieveUpdate,
    /// The guest has been sent to another machine
    Sent,
}
/// Struct to hold SEV info
pub struct Sev {
    fd: File,
    vm_fd: Arc<VmFd>,
    handle: u32,
    policy: u32,
    state: State,
    measure: [u8; 48],
    timestamp: TimestampUs,
    /// SNP active
    pub snp: bool,
    /// position of the Cbit
    pub cbitpos: u32,
    /// DEBUG whether or not encryption is active. This is for testing the firmware without encryption
    pub encryption: bool,
    /// Whether the guest policy requires SEV-ES
    pub es: bool,
}

impl Sev {
    ///Initialize SEV
    pub fn new(
        vm_fd: Arc<VmFd>,
        snp: bool,
        encryption: bool,
        timestamp: TimestampUs,
        policy: u32,
    ) -> Self {
        //Open /dev/sev

        info!("Initializing new SEV guest context: policy 0x{:x}", policy);

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev")
            .unwrap();

        let ebx;

        //check if guest owner wants encrypted state
        let es = (policy & POLICY_ES) != 0;

        //Get position of the C-bit
        unsafe {
            ebx = __cpuid(0x8000001F).ebx & 0x3f;
        }

        Sev {
            fd: fd,
            vm_fd: vm_fd,
            handle: 0,
            policy: policy,
            state: State::UnInit,
            measure: [0u8; 48],
            cbitpos: ebx,
            snp: snp,
            encryption: encryption,
            timestamp,
            es,
        }
    }

    fn sev_ioctl(&mut self, cmd: &mut kvm_sev_cmd) -> SevResult<()> {
        match self.vm_fd.encrypt_op_sev(cmd) {
            Err(err) => {
                if cmd.error > 0 {
                    return Err(SevError::from(cmd.error));
                } else {
                    return Err(SevError::Errno(err.errno()));
                }
            }
            _ => Ok(()),
        }
    }

    /// Initialize SEV-SNP platform
    pub fn snp_init(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }

        info!("Sending SNP_INIT");

        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }

        let cmd = sev_cmd_id_KVM_SEV_SNP_INIT;

        let snp_init = kvm_snp_init { flags: 0 };

        let mut init = kvm_sev_cmd {
            id: cmd,
            data: &snp_init as *const kvm_snp_init as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init)?;

        self.state = State::Init;
        info!("Done Sending SEV_INIT");

        self.snp_launch_start()
    }

    /// Initialize SEV platform
    pub fn sev_init(
        &mut self,
        session: &mut Option<File>,
        dh_cert: &mut Option<File>,
    ) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending SEV_INIT");

        if self.state != State::UnInit {
            return Err(SevError::InvalidPlatformState);
        }

        let cmd = if self.es {
            info!("Initializing SEV-ES");
            sev_cmd_id_KVM_SEV_ES_INIT
        } else {
            info!("Initializing SEV-ES");
            sev_cmd_id_KVM_SEV_INIT
        };

        let mut init = kvm_sev_cmd {
            id: cmd,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut init).unwrap();

        self.state = State::Init;
        info!("Done Sending SEV_INIT");

        self.sev_launch_start(session, dh_cert)
    }

    fn snp_launch_start(&mut self) -> SevResult<()> {
        Ok(())
    }

    /// Get SEV guest handle
    fn sev_launch_start(
        &mut self,
        session: &mut Option<File>,
        dh_cert: &mut Option<File>,
    ) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("LAUNCH_START");

        if self.state != State::Init {
            return Err(SevError::InvalidPlatformState);
        }

        let dh_cert_data = match dh_cert {
            None => None,
            Some(file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                Some(buf)
            }
        };

        let (dh_cert_paddr, dh_cert_len) = match dh_cert_data.as_ref() {
            None => (0, 0),
            Some(buf) => (buf.as_ptr() as u64, buf.len() as u32),
        };

        let session_data = match session {
            None => None,
            Some(file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                Some(buf)
            }
        };

        let (session_paddr, session_len) = match session_data.as_ref() {
            None => (0, 0),
            Some(buf) => (buf.as_ptr() as u64, buf.len() as u32),
        };

        let start = kvm_sev_launch_start {
            handle: 0,
            policy: self.policy,
            session_uaddr: session_paddr,
            session_len: session_len,
            dh_uaddr: dh_cert_paddr,
            dh_len: dh_cert_len,
        };

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_START,
            data: &start as *const kvm_sev_launch_start as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.handle = start.handle;
        self.state = State::LaunchUpdate;
        info!("LAUNCH_START Done");
        Ok(())
    }

    /// Encrypt VMSA
    pub fn launch_update_vmsa(&mut self) -> SevResult<()> {
        //test for debug encryption disabled or non-es boot
        if !self.encryption || !self.es {
            return Ok(());
        }

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_VMSA,
            data: 0,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        info!("Encrypting VM save area...");

        self.sev_ioctl(&mut msg).unwrap();
        Ok(())
    }

    /// Encrypt region
    pub fn launch_update_data(
        &mut self,
        guest_addr: GuestAddress,
        len: u32,
        guest_mem: &GuestMemoryMmap,
    ) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }

        let addr = guest_mem.get_host_address(guest_addr).unwrap() as u64;

        let mut aligned_addr = addr;
        let mut aligned_len = len;

        if aligned_addr % 16 != 0 {
            aligned_addr -= addr % 16;
            aligned_len += (addr % 16) as u32;
        }

        if aligned_len % 16 != 0 {
            aligned_len = aligned_len - (aligned_len % 16) + 16;
        }

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let region = kvm_sev_launch_update_data {
            uaddr: aligned_addr,
            len: aligned_len,
        };

        //fill zeros between aligned (down) address and original address
        if aligned_addr < addr {
            let n = addr - aligned_addr;
            let mut buf = vec![0; n as usize];
            guest_mem
                .read_slice(&mut buf.as_mut_slice(), GuestAddress(guest_addr.0 - n))
                .unwrap();
        }

        let region_end = aligned_addr + aligned_len as u64;
        let original_end = addr + len as u64;

        //fill zeros between original end and end of aligned region
        if region_end > original_end {
            let n = region_end - original_end;
            let mut buf = vec![0; n as usize];
            guest_mem
                .read_slice(
                    &mut buf.as_mut_slice(),
                    GuestAddress(guest_addr.0 + len as u64),
                )
                .unwrap();
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_UPDATE_DATA,
            data: &region as *const kvm_sev_launch_update_data as _,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!("Pre-encryption start: {:>06} us, {:>06} CPU us", real, cpu);
        self.sev_ioctl(&mut msg).unwrap();
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!("Pre-encryption done: {:>06} us, {:>06} CPU us", real, cpu);
        Ok(())
    }

    /// Get boot measurement
    pub fn get_launch_measurement(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending LAUNCH_MEASURE");

        if self.state != State::LaunchUpdate {
            return Err(SevError::InvalidPlatformState);
        }

        let mut measure: kvm_sev_launch_measure = Default::default();

        measure.uaddr = self.measure.as_ptr() as _;
        measure.len = MEASUREMENT_LEN;

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_MEASURE,
            data: &measure as *const kvm_sev_launch_measure as u64,
            sev_fd: self.fd.as_raw_fd() as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::LaunchSecret;
        info!("Done Sending LAUNCH_MEASURE");

        Ok(())
    }

    /// Finish SEV launch sequence
    pub fn sev_launch_finish(&mut self) -> SevResult<()> {
        if !self.encryption {
            return Ok(());
        }
        info!("Sending LAUNCH_FINISH");

        if self.state != State::LaunchSecret {
            return Err(SevError::InvalidPlatformState);
        }

        let mut msg = kvm_sev_cmd {
            id: sev_cmd_id_KVM_SEV_LAUNCH_FINISH,
            sev_fd: self.fd.as_raw_fd() as _,
            data: self.handle as _,
            ..Default::default()
        };

        self.sev_ioctl(&mut msg).unwrap();

        self.state = State::Running;
        info!("Done Sending LAUNCH_FINISH");

        Ok(())
    }

    ///copy bzimage to guest memory
    pub fn load_kernel(
        &mut self,
        kernel_file: &mut File,
        guest_mem: &GuestMemoryMmap,
    ) -> SevResult<u64> {
        kernel_file.seek(SeekFrom::Start(0)).unwrap();
        let len = kernel_file.seek(SeekFrom::End(0)).unwrap();
        kernel_file.seek(SeekFrom::Start(0)).unwrap();

        //Load bzimage at 16mib
        guest_mem
            .read_exact_from(
                GuestAddress(0x1000000),
                kernel_file,
                len.try_into().unwrap(),
            )
            .unwrap();

        // let addr = guest_mem.get_host_address(GuestAddress(0x200000)).unwrap() as u64;

        // self.launch_update_data(addr, len.try_into().unwrap())
        //     .unwrap();

        Ok(len)
    }

    ///Load SEV firmware
    pub fn load_firmware(&mut self, path: &String, guest_mem: &GuestMemoryMmap) -> SevResult<()> {
        let path = PathBuf::from(path);
        let mut f_firmware = File::open(path.as_path()).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();
        let len = f_firmware.seek(SeekFrom::End(0)).unwrap();
        f_firmware.seek(SeekFrom::Start(0)).unwrap();

        guest_mem
            .read_exact_from(FIRMWARE_ADDR, &mut f_firmware, len.try_into().unwrap())
            .unwrap();

        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Pre-encrypting firmware: {:>06} us, {:>06} CPU us",
            real, cpu
        );
        self.launch_update_data(FIRMWARE_ADDR, len.try_into().unwrap(), guest_mem)?;
        let now_tm_us = TimestampUs::default();
        let real = now_tm_us.time_us - self.timestamp.time_us;
        let cpu = now_tm_us.cputime_us - self.timestamp.cputime_us;
        info!(
            "Done pre-encrypting firmware: {:>06} us, {:>06} CPU us",
            real, cpu
        );

        Ok(())
    }
}
