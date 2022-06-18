use colored::Colorize;
use std::io::{self, prelude::*, Error as IoError};
use winapi::{
    shared::minwindef::DWORD,
    um::winnt::{
        CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, INHERITED_ACE, INHERIT_ONLY_ACE,
        NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, PSID, SUCCESSFUL_ACCESS_ACE_FLAG,
    },
};
use windows_acl::acl::ACL;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    IoError(#[from] IoError),

    #[error("error occured! error code {0}")]
    WindowsErrorCode(DWORD),
}
impl From<DWORD> for Error {
    fn from(code: DWORD) -> Self {
        let ioerror = IoError::from_raw_os_error(code as i32);

        if ioerror.kind() != io::ErrorKind::Other {
            Self::IoError(ioerror)
        } else {
            Self::WindowsErrorCode(code)
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

fn current_user_sid() -> Result<(String, Vec<u8>)> {
    let sid = windows_acl::helper::name_to_sid(
        &windows_acl::helper::current_user().unwrap_or_default(),
        None,
    )?;

    Ok((
        windows_acl::helper::sid_to_string(sid.as_ptr() as PSID)?,
        sid,
    ))
}

fn print_acl_entries(acl: &ACL) -> Result<()> {
    let equals = "=".red();
    let index = format!("{} {equals}", "index".yellow());
    let size = format!("{} {equals}", "size".yellow());
    let entry_type = format!("{} {equals}", "entry_type".yellow());
    let flags = format!("{} {equals}", "flags".yellow());
    let sid = format!("{} {equals}", "sid".yellow());
    let access_mask = format!("{} {equals}", "access mask".yellow());
    let spacer = "\n\n-------\n\n".bright_black();
    let mut cerr = io::stderr().lock();

    for entry in acl.all()? {
        write!(cerr, "{spacer}")?;
        writeln!(cerr, "{index} {}", entry.index.to_string().blue())?;
        writeln!(cerr, "{size} {}", entry.size.to_string().blue())?;
        writeln!(cerr, "{entry_type} {}", entry.entry_type.to_string().blue())?;
        writeln!(cerr, "{sid} {}", entry.string_sid.to_string().blue())?;
        {
            write!(
                cerr,
                "{flags} {}\n        ",
                format!("{:08b}", entry.flags).blue()
            )?;
            if entry.flags == 0 {
                write!(cerr, "None")?;
            } else {
                match (
                    entry.flags & FAILED_ACCESS_ACE_FLAG == FAILED_ACCESS_ACE_FLAG,
                    entry.flags & SUCCESSFUL_ACCESS_ACE_FLAG == SUCCESSFUL_ACCESS_ACE_FLAG,
                ) {
                    (true, true) => write!(cerr, " {}", "AuditAlways".blue())?,
                    (true, false) => write!(cerr, " {}", "AuditFailedAccess".blue())?,
                    (false, true) => write!(cerr, " {}", "AuditSuccessfulAccess".blue())?,
                    _ => (),
                }
                if entry.flags & INHERITED_ACE == INHERITED_ACE {
                    write!(cerr, " {}", "Inherited".blue())?;
                }
                if entry.flags & INHERIT_ONLY_ACE == INHERIT_ONLY_ACE {
                    write!(cerr, " {}", "InheritOnly".blue())?;
                }
                if entry.flags & OBJECT_INHERIT_ACE == OBJECT_INHERIT_ACE {
                    write!(cerr, " {}", "ObjectInherit".blue())?;
                }
                if entry.flags & CONTAINER_INHERIT_ACE == CONTAINER_INHERIT_ACE {
                    write!(cerr, " {}", "ContainerInherit".blue())?;
                }
                if entry.flags & NO_PROPAGATE_INHERIT_ACE == NO_PROPAGATE_INHERIT_ACE {
                    write!(cerr, " {}", "NoPropagateInherit".blue())?;
                }
            }
            writeln!(cerr,)?;
        }
        {
            write!(
                cerr,
                "{access_mask} {}\n             ",
                format!("{:032b}", entry.mask).blue()
            )?;
            if entry.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
                write!(cerr, " {}", "AllAccess".blue())?;
            } else {
                if entry.mask & FILE_GENERIC_READ == FILE_GENERIC_READ {
                    write!(cerr, " {}", "GenericRead".blue())?;
                }
                if entry.mask & FILE_GENERIC_WRITE == FILE_GENERIC_WRITE {
                    write!(cerr, " {}", "GenericRead".blue())?;
                }
                if entry.mask & FILE_GENERIC_EXECUTE == FILE_GENERIC_EXECUTE {
                    write!(cerr, " {}", "GenericExecute".blue())?;
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let acl = ACL::from_file_path(
        &std::env::args().nth(1).unwrap_or_else(|| ".".to_string()),
        false,
    )?;

    print_acl_entries(&acl)?;
    Ok(())
}
