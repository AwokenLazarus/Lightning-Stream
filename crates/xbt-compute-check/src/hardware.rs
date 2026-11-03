//! What this machine has. Reading, not measuring, except the disk test, which the tester asks for.

use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::{Gpu, Report, SCHEMA};

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Reads this machine. `id` is the run's link key and `region` the tester's own wording.
pub fn read(id: &str, region: &str, disk_dir: &Path) -> Result<Report, String> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(|e| format!("this check reads /proc/meminfo, and only runs on Linux for now: {e}"))?;
    let (ram_total_gib, ram_available_gib) = parse_meminfo(&meminfo).ok_or("/proc/meminfo has no MemTotal or MemAvailable")?;
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cores = parse_physical_cores(&cpuinfo).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get() as u32));
    let mut gpus = nvidia_gpus();
    gpus.extend(amd_gpus(Path::new("/sys/class/drm")));
    Ok(Report {
        schema: SCHEMA,
        id: id.to_string(),
        region: region.chars().take(40).collect(),
        arch: std::env::consts::ARCH.to_string(),
        cores,
        ram_total_gib,
        ram_available_gib,
        gpus,
        disk_free_gib: free_gib(disk_dir)?,
        disk_read_mb_s: None,
    })
}

/// `MemTotal` and `MemAvailable`, in GiB.
pub fn parse_meminfo(text: &str) -> Option<(f64, f64)> {
    let field = |name: &str| {
        text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(':')?.trim().strip_suffix("kB")?.trim().parse::<f64>().ok())
    };
    Some((field("MemTotal")? * 1024.0 / GIB, field("MemAvailable")? * 1024.0 / GIB))
}

/// Physical cores from `/proc/cpuinfo`, counting each (physical id, core id) once. `None` where the
/// file does not say, as on many Arm boards.
pub fn parse_physical_cores(text: &str) -> Option<u32> {
    let mut seen = std::collections::HashSet::new();
    let (mut phys, mut core) = (None, None);
    for line in text.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (phys.take(), core.take()) {
                seen.insert((p, c));
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim() {
            "physical id" => phys = Some(v.trim().to_string()),
            "core id" => core = Some(v.trim().to_string()),
            _ => {}
        }
    }
    (!seen.is_empty()).then_some(seen.len() as u32)
}

fn nvidia_gpus() -> Vec<Gpu> {
    let Ok(out) = Command::new("nvidia-smi").args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"]).output() else { return Vec::new() };
    if !out.status.success() {
        return Vec::new();
    }
    parse_nvidia_smi(&String::from_utf8_lossy(&out.stdout))
}

/// The lines of `nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits` (MiB).
pub fn parse_nvidia_smi(text: &str) -> Vec<Gpu> {
    text.lines().filter_map(|l| {
        let (name, mib) = l.rsplit_once(',')?;
        Some(Gpu { vendor: "nvidia".into(), name: name.trim().to_string(), vram_gib: mib.trim().parse::<f64>().ok()? / 1024.0 })
    }).collect()
}

/// AMD cards, from sysfs: `cardN/device/vendor` is 0x1002 and `mem_info_vram_total` says the size.
pub fn amd_gpus(drm: &Path) -> Vec<Gpu> {
    let Ok(dir) = std::fs::read_dir(drm) else { return Vec::new() };
    let mut names: Vec<_> = dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.strip_prefix("card").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))).collect();
    names.sort();
    names.iter().filter_map(|n| {
        let dev = drm.join(n).join("device");
        if std::fs::read_to_string(dev.join("vendor")).ok()?.trim() != "0x1002" {
            return None;
        }
        let bytes: f64 = std::fs::read_to_string(dev.join("mem_info_vram_total")).ok()?.trim().parse().ok()?;
        let name = std::fs::read_to_string(dev.join("product_name")).map(|s| s.trim().to_string()).unwrap_or_else(|_| "AMD graphics card".into());
        Some(Gpu { vendor: "amd".into(), name, vram_gib: bytes / GIB })
    }).collect()
}

fn free_gib(dir: &Path) -> Result<f64, String> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is a valid C string and `s` is ours to write.
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
        return Err(format!("cannot read the free space of {}: {}", dir.display(), std::io::Error::last_os_error()));
    }
    Ok(s.f_bavail as f64 * s.f_frsize as f64 / GIB)
}

/// Writes `gib` GiB to a new file in `dir`, drops it from memory, reads it back and removes it.
/// Returns the read speed in MB/s. A pre-written buffer of random bytes, so that a compressing
/// disk does not flatter the number.
pub fn disk_read_test(dir: &Path, gib: u64) -> Result<f64, String> {
    let free = free_gib(dir)?;
    if free < gib as f64 + 10.0 {
        return Err(format!("the disk test needs {} GiB free, and there are {free:.0}", gib + 10));
    }
    let mut key = [0u8; 8];
    getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
    let path = dir.join(format!(".stream-compute-check-{}", hex::encode(key)));
    let result = (|| {
        let mut block = vec![0u8; 16 << 20];
        getrandom::getrandom(&mut block).map_err(|e| e.to_string())?;
        let mut f = std::fs::File::create_new(&path).map_err(|e| format!("cannot write in {}: {e}", dir.display()))?;
        for _ in 0..gib * 64 {
            f.write_all(&block).map_err(|e| e.to_string())?;
        }
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        let mut f = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        {
            use std::os::fd::AsRawFd;
            // SAFETY: a valid descriptor, and advice changes no data.
            unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        }
        let t = Instant::now();
        let mut total = 0u64;
        loop {
            let n = f.read(&mut block).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
        }
        Ok(total as f64 / 1e6 / t.elapsed().as_secs_f64())
    })();
    let _ = std::fs::remove_file(&path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_gives_total_and_available() {
        let (t, a) = parse_meminfo("MemTotal:       16777216 kB\nMemFree: 1 kB\nMemAvailable:    8388608 kB\n").unwrap();
        assert_eq!((t, a), (16.0, 8.0));
        assert!(parse_meminfo("MemTotal: 1 kB\n").is_none());
    }

    #[test]
    fn hyperthreads_count_once_and_a_board_that_does_not_say_gives_none() {
        let two_cores_four_threads = "processor: 0\nphysical id: 0\ncore id: 0\n\nprocessor: 1\nphysical id: 0\ncore id: 1\n\n\
                                      processor: 2\nphysical id: 0\ncore id: 0\n\nprocessor: 3\nphysical id: 0\ncore id: 1\n";
        assert_eq!(parse_physical_cores(two_cores_four_threads), Some(2));
        assert_eq!(parse_physical_cores("processor: 0\nBogoMIPS: 108\n"), None);
    }

    #[test]
    fn nvidia_lines_are_read_and_a_comma_in_a_name_survives() {
        let g = parse_nvidia_smi("NVIDIA GeForce RTX 3090, 24576\nOdd, Name, 8192\nbroken\n");
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].name.as_str(), g[0].vram_gib), ("NVIDIA GeForce RTX 3090", 24.0));
        assert_eq!((g[1].name.as_str(), g[1].vram_gib), ("Odd, Name", 8.0));
    }

    #[test]
    fn only_amd_cards_are_taken_from_sysfs() {
        let d = std::env::temp_dir().join(format!("compute-check-drm-{}", std::process::id()));
        for (card, vendor) in [("card0", "0x10de"), ("card1", "0x1002")] {
            let dev = d.join(card).join("device");
            std::fs::create_dir_all(&dev).unwrap();
            std::fs::write(dev.join("vendor"), vendor).unwrap();
            std::fs::write(dev.join("mem_info_vram_total"), (24u64 << 30).to_string()).unwrap();
        }
        std::fs::create_dir_all(d.join("card1-DP-1")).unwrap();
        let g = amd_gpus(&d);
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!((g[0].vendor.as_str(), g[0].vram_gib), ("amd", 24.0));
    }
}
