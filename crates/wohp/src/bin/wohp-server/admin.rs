//! Operator commands on the core identity database: `backup` and `restore`.
//! They read the same `WOHP_SERVER_*` paths as the server and never create a
//! lookup key. Output names files and counts, never people or subjects.
use super::*;
use wohp::backup::{backup, restore};

pub const USAGE: &str = "\
usage:
  wohp-server                     run the server
  wohp-server backup <directory>  write a consistent snapshot of WOHP_SERVER_CORE_DB into a
                                  private (0700) directory; safe while the server runs
  wohp-server restore <snapshot>  install a snapshot as WOHP_SERVER_CORE_DB; the server must be
                                  stopped and its old core and server databases moved aside.
                                  Every authentication epoch becomes the restore time";

/// Runs one command and exits: 0 done, 1 refused or failed, 2 wrong usage.
pub fn run(arguments: &[OsString]) -> ! {
    let result = match (arguments[0].to_str(), &arguments[1..]) {
        (Some("backup"), [directory]) => run_backup(FsPath::new(directory)),
        (Some("restore"), [snapshot]) => run_restore(FsPath::new(snapshot)),
        (Some("help" | "--help" | "-h"), []) => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    match result {
        Ok(message) => {
            println!("{message}");
            std::process::exit(0)
        }
        Err(message) => {
            eprintln!("wohp-server: {message}");
            std::process::exit(1)
        }
    }
}

fn now() -> Result<u64, String> {
    timestamp().map_err(|_| "system clock before 1970".into())
}

fn key(paths: &StoragePaths) -> Result<LookupKey, String> {
    read_key(&paths.key_file).map_err(|_| {
        "cannot read WOHP_SERVER_CORE_KEY: it must be the existing 32-byte key file, mode 0600"
            .into()
    })
}

fn exists(path: &FsPath) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn with_suffix(path: &FsPath, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn run_backup(directory: &FsPath) -> Result<String, String> {
    let paths = storage_paths().map_err(String::from)?;
    let key = key(&paths)?;
    let summary = backup(&paths.database, &key, directory, now()?).map_err(|error| {
        match error {
            CoreError::InvalidConfiguration => {
                "the backup directory must exist with mode 0700, WOHP_SERVER_CORE_DB must be an \
                 existing 0600 file, and a snapshot of this second must not exist yet"
            }
            CoreError::ConfigurationMismatch => {
                "WOHP_SERVER_CORE_KEY does not belong to WOHP_SERVER_CORE_DB, or the database \
                 is not at the current schema: nothing was written"
            }
            _ => {
                "the snapshot could not be written or failed its integrity check: nothing was kept"
            }
        }
        .to_owned()
    })?;
    Ok(format!(
        "wrote {} (people: {}, clients: {}).\nThe snapshot does not contain the lookup key: keep a \
         separate, protected copy of WOHP_SERVER_CORE_KEY, without it no snapshot can be restored.",
        summary.path.display(),
        summary.humans,
        summary.clients
    ))
}

fn run_restore(snapshot: &FsPath) -> Result<String, String> {
    let paths = storage_paths().map_err(String::from)?;
    let server = &paths.server_database;
    if [
        server.clone(),
        with_suffix(server, "-wal"),
        with_suffix(server, "-shm"),
    ]
    .iter()
    .any(|path| exists(path))
    {
        return Err(
            "stop the server and move WOHP_SERVER_DB (and its -wal/-shm files) aside: \
                    its verifications and codes must not survive a restore"
                .into(),
        );
    }
    let key = key(&paths)?;
    let summary = restore(snapshot, &key, &paths.database, now()?).map_err(|error| {
        match error {
            CoreError::InvalidConfiguration => {
                "stop the server and move WOHP_SERVER_CORE_DB (and its -wal/-shm files) aside; \
                 the snapshot must be a 0600 file, the database directory must have mode 0700, \
                 and no .restore file may be left from an interrupted restore"
            }
            CoreError::InvalidInput => {
                "the snapshot has a -wal or -journal file next to it: it is a live or \
                 interrupted database, not a snapshot written by `wohp-server backup`"
            }
            CoreError::ConfigurationMismatch => {
                "the snapshot does not belong to WOHP_SERVER_CORE_KEY, or it is from another \
                 schema version: nothing was installed"
            }
            CoreError::Clock => {
                "the snapshot has an authentication epoch at or above the current time: the \
                 system clock is behind a previous restore. Fix the clock; nothing was installed"
            }
            _ => "the snapshot is damaged or could not be copied: nothing was installed",
        }
        .to_owned()
    })?;
    Ok(format!(
        "restored {} people from {}.\nEvery authentication epoch is now {} (the restore time), \
         above any epoch relying parties saw: they drop credentials and sessions from before the \
         restore, and people verify with the wallet again. {} pending verifications were \
         discarded.\nPeople enrolled after the snapshot will get a new subject; re-apply any \
         revocation made after it, then start the server.",
        summary.humans,
        snapshot.display(),
        summary.epoch,
        summary.discarded_challenges,
    ))
}
