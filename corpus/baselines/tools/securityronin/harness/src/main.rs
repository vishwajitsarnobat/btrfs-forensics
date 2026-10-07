//! recover_deleted IMAGE OUT_DIR NAMES_TSV
//!
//! Reads the whole image (a file or a block device) into memory, calls
//! `btrfs_forensic::recover_deleted` on it, and writes each recovered file's content to
//! `OUT_DIR/inode_<INODE>_gen_<GENERATION>`. NAMES_TSV gets one line per file, the output name and
//! the recovered directory-entry name, with backslash, tab and newline escaped as `\\`, `\t` and
//! `\n` (the format of corpus/baselines/guest/job.sh). A summary line per file goes to stdout.
//! The image is only read: `std::fs::read` opens it read-only.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: recover_deleted IMAGE OUT_DIR NAMES_TSV");
        return ExitCode::from(2);
    }
    let image = match fs::read(&args[1]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("recover_deleted: cannot read {}: {err}", args[1]);
            return ExitCode::from(1);
        }
    };
    let out = Path::new(&args[2]);
    if let Err(err) = fs::create_dir_all(out) {
        eprintln!("recover_deleted: cannot create {}: {err}", args[2]);
        return ExitCode::from(1);
    }
    let mut names = match fs::File::create(&args[3]) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("recover_deleted: cannot create {}: {err}", args[3]);
            return ExitCode::from(1);
        }
    };
    let recovered = btrfs_forensic::recover_deleted(&image);
    println!("inode\tgeneration\tsize\tcontent_sha256\tname");
    for file in &recovered {
        let stem = format!("inode_{}_gen_{}", file.inode, file.generation);
        if let Err(err) = fs::write(out.join(&stem), &file.content) {
            eprintln!("recover_deleted: cannot write {stem}: {err}");
            return ExitCode::from(1);
        }
        if let Err(err) = writeln!(names, "{stem}\t{}", escape(&file.path)) {
            eprintln!("recover_deleted: cannot write {}: {err}", args[3]);
            return ExitCode::from(1);
        }
        println!(
            "{}\t{}\t{}\t{}\t{}",
            file.inode,
            file.generation,
            file.size,
            file.content_sha256,
            escape(&file.path)
        );
    }
    eprintln!("recover_deleted: {} files", recovered.len());
    ExitCode::SUCCESS
}
