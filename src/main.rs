use colored::Colorize;
use std::io::{self, prelude::*, Error as IoError};
use winapi::{
    shared::minwindef::DWORD,
    um::winnt::{
        CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, INHERITED_ACE, OBJECT_INHERIT_ACE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
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
        Error::WindowsErrorCode(code)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

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
        writeln!(cerr, "{sid} {}", entry.string_sid.to_string().blue(),)?;
        {
            write!(
                cerr,
                "{flags} {}\n        ",
                format!("{:08b}", entry.flags).blue()
            )?;
            if entry.flags == 0 {
                write!(cerr, "None")?;
            } else {
                if entry.flags & FAILED_ACCESS_ACE_FLAG == FAILED_ACCESS_ACE_FLAG {
                    write!(cerr, " {}", "FailedAccess".blue())?;
                }
                if entry.flags & SUCCESSFUL_ACCESS_ACE_FLAG == SUCCESSFUL_ACCESS_ACE_FLAG {
                    write!(cerr, " {}", "SuccessfulAccess".blue())?;
                }
                if entry.flags & INHERITED_ACE == INHERITED_ACE {
                    write!(cerr, " {}", "Inherited".blue())?;
                }
                if entry.flags & OBJECT_INHERIT_ACE == OBJECT_INHERIT_ACE {
                    write!(cerr, " {}", "ObjectInherit".blue())?;
                }
                if entry.flags & CONTAINER_INHERIT_ACE == CONTAINER_INHERIT_ACE {
                    write!(cerr, " {}", "ContainerInherit".blue())?;
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
    let acl = dbg!(ACL::from_file_path(
        &dirs::home_dir().unwrap_or_default().to_string_lossy(),
        false
    ))?;

    print_acl_entries(&acl)?;
    Ok(())
}
