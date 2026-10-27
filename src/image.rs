/*
 * Copyright (c) 2025 Phala Network
 * Copyright (c) 2025 Tinfoil Inc
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::shim;
use crate::util::utf16_encode;
use crate::{
    measure_log, measure_sha384,
    util::{authenticode_sha384_hash, debug_print_log},
    BootChain,
};
use anyhow::{bail, Context, Result};
use log::debug;
use std::fs;
use std::path::Path;
use std::process::Command;

const ESP: &str = "/boot/efi/EFI";

fn resolve_boot_chain(qcow2_path: &str, chain: &BootChain) -> Result<Vec<String>> {
    match chain {
        BootChain::Paths(paths) => {
            if paths.is_empty() || paths.iter().any(|path| !path.starts_with('/')) {
                bail!("boot chain paths must be a nonempty list of absolute guest paths");
            }
            Ok(paths.clone())
        }
        BootChain::Named(name) => {
            if name != BootChain::VENDOR && name != BootChain::REMOVABLE_MEDIA {
                bail!("unknown boot chain {name:?}; expected vendor or removable-media");
            }
            let output = Command::new("guestfish")
                .args(["--ro", "-a", qcow2_path, "-i", "find", ESP])
                .output()
                .context("Failed to list the guest EFI system partition")?;
            if !output.status.success() {
                bail!(
                    "Failed to list the guest EFI system partition: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            let entries = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|line| line.trim().trim_start_matches('/').to_string())
                .collect::<Vec<_>>();
            resolve_named_boot_chain(&entries, name)
        }
    }
}

fn resolve_named_boot_chain(entries: &[String], name: &str) -> Result<Vec<String>> {
    let mut vendors = entries
        .iter()
        .filter_map(|entry| {
            let (vendor, file) = entry.split_once('/')?;
            if !vendor.eq_ignore_ascii_case("BOOT") && file.eq_ignore_ascii_case("shimx64.efi") {
                Some(vendor)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    vendors.sort_unstable();
    vendors.dedup();
    let [vendor] = vendors[..] else {
        bail!(
            "expected one vendor shim on {ESP}, found {}; supply explicit paths instead",
            vendors.len()
        );
    };
    let vendor_grub = format!("{vendor}/grubx64.efi");
    if !entries
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(&vendor_grub))
    {
        bail!("{ESP}/{vendor} contains shim but no grubx64.efi");
    }
    let vendor_chain = [
        format!("{ESP}/{vendor}/shimx64.efi"),
        format!("{ESP}/{vendor}/grubx64.efi"),
    ];
    match name {
        BootChain::VENDOR => Ok(vendor_chain.to_vec()),
        BootChain::REMOVABLE_MEDIA => {
            let fallback = ["BOOT/BOOTX64.EFI", "BOOT/fbx64.efi"];
            for path in fallback {
                if !entries.iter().any(|entry| entry.eq_ignore_ascii_case(path)) {
                    bail!("{ESP}/{path} is missing from the selected boot chain");
                }
            }
            Ok(fallback
                .iter()
                .map(|path| format!("{ESP}/{path}"))
                .chain(vendor_chain)
                .collect())
        }
        _ => bail!("unknown boot chain {name:?}"),
    }
}

/// Helper function to download a file using guestfish
fn guestfish_download(qcow2_path: &str, source_path: &str) -> Result<Vec<u8>> {
    // Create a temporary directory for the extracted files
    let temp_dir = std::env::temp_dir().join("tdx_bootloader_extract");
    std::fs::create_dir_all(&temp_dir)?;

    // Create a temporary file path
    let dest_path = temp_dir.join("extracted_file");

    // Download the file using guestfish
    let output = Command::new("guestfish")
        .args(&[
            "--ro",
            "-a",
            qcow2_path,
            "-i",
            "download",
            source_path,
            dest_path.to_str().unwrap(),
        ])
        .output()
        .context(format!("Failed to extract {}", source_path))?;

    if !output.status.success() {
        bail!(
            "Failed to extract {}: {}",
            source_path,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Read the extracted file
    let data = std::fs::read(&dest_path).context(format!(
        "Failed to read extracted {}",
        dest_path.to_str().unwrap()
    ))?;

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(data)
}

fn download_boot_chain(qcow2_path: &str, paths: &[String]) -> Result<Vec<Vec<u8>>> {
    let temp_dir = tempfile::tempdir().context("Failed to create a temporary directory")?;
    let destinations = (0..paths.len())
        .map(|i| temp_dir.path().join(i.to_string()).display().to_string())
        .collect::<Vec<_>>();
    let mut args = vec!["--ro", "-a", qcow2_path, "-i"];
    for (index, (source, destination)) in paths.iter().zip(&destinations).enumerate() {
        if index > 0 {
            args.push(":");
        }
        args.extend(["download", source, destination]);
    }
    let output = Command::new("guestfish")
        .args(args)
        .output()
        .context("Failed to read the EFI boot chain")?;
    if !output.status.success() {
        bail!(
            "Failed to read the EFI boot chain: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    paths
        .iter()
        .zip(&destinations)
        .map(|(source, destination)| {
            fs::read(destination).with_context(|| format!("Failed to read {source} from the guest"))
        })
        .collect()
}

/// Extracts GPT event data in the format used by EV_EFI_GPT_EVENT
fn extract_gpt_event_data(qcow2_path: &str) -> Result<Vec<u8>> {
    // Extract GPT header from LBA 1 (skip MBR at LBA 0)
    let output = Command::new("guestfish")
        .args(&[
            "--ro",
            "-a",
            qcow2_path,
            "run",
            ":",
            "pread-device",
            "/dev/sda",
            "512",
            "512", // Read LBA 1 (GPT header)
        ])
        .output()
        .context("Failed to extract GPT header")?;

    if !output.status.success() {
        bail!(
            "Failed to extract GPT header: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let gpt_header = output.stdout;

    // Parse GPT header
    if gpt_header.len() < 92 {
        bail!("GPT header too short");
    }

    // Check GPT signature
    if &gpt_header[0..8] != b"EFI PART" {
        bail!("Invalid GPT signature");
    }

    // Read partition entry info from GPT header
    let partition_entry_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap()) as usize;

    // Calculate how many sectors we need to read for all partition entries
    let entries_size = num_entries * entry_size;
    let sectors_needed = (entries_size + 511) / 512; // Round up to sector boundary

    // Extract partition entries
    let entries_offset = partition_entry_lba * 512;
    let entries_length = sectors_needed * 512;

    let output = Command::new("guestfish")
        .args(&[
            "--ro",
            "-a",
            qcow2_path,
            "run",
            ":",
            "pread-device",
            "/dev/sda",
            &entries_length.to_string(),
            &entries_offset.to_string(),
        ])
        .output()
        .context("Failed to extract GPT entries")?;

    if !output.status.success() {
        bail!(
            "Failed to extract GPT entries: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let all_entries = output.stdout;

    // Filter valid partition entries (non-zero PartitionTypeGUID)
    let mut valid_entries = Vec::new();
    for i in 0..num_entries {
        let entry_offset = i * entry_size;
        if entry_offset + entry_size > all_entries.len() {
            break;
        }

        let entry = &all_entries[entry_offset..entry_offset + entry_size];

        // Check if PartitionTypeGUID is non-zero (first 16 bytes)
        let is_valid = !entry[0..16].iter().all(|&b| b == 0);

        if is_valid {
            valid_entries.push(entry.to_vec());
        }
    }

    // Build the EFI_GPT_DATA structure:
    // 1. GPT Header (92 bytes)
    // 2. NumberOfPartitions (8 bytes as UINT64)
    // 3. Valid partition entries (128 bytes each)
    let mut gpt_event_data = Vec::new();

    // Add GPT header (92 bytes)
    gpt_event_data.extend_from_slice(&gpt_header[0..92]);

    // Add NumberOfPartitions as 64-bit value
    let num_valid_partitions = valid_entries.len() as u64;
    gpt_event_data.extend_from_slice(&num_valid_partitions.to_le_bytes());

    // Add valid partition entries
    for entry in valid_entries {
        gpt_event_data.extend_from_slice(&entry);
    }

    Ok(gpt_event_data)
}

/// Reads the data from a file
fn read_file_data(filename: &str) -> Result<Vec<u8>> {
    let path = Path::new(filename);
    if path.exists() {
        match fs::read(path) {
            Ok(data) => Ok(data),
            Err(e) => {
                debug!("Failed to read {}: {}", filename, e);
                // Return empty data if file doesn't exist or can't be read
                Ok(Vec::new())
            }
        }
    } else {
        debug!("File {} not found, using empty data", filename);
        Ok(Vec::new())
    }
}

/// Extracts the kernel version from the command line BOOT_IMAGE parameter
fn extract_kernel_version_from_cmdline(cmdline: &str) -> Result<String> {
    // Look for BOOT_IMAGE parameter
    for param in cmdline.split_whitespace() {
        if param.starts_with("BOOT_IMAGE=") {
            let boot_image = param.strip_prefix("BOOT_IMAGE=").unwrap();
            // Extract version from vmlinuz filename
            // Example: /vmlinuz-6.8.0-60-generic -> 6.8.0-60-generic
            if let Some(version_start) = boot_image.find("vmlinuz-") {
                let version = &boot_image[version_start + 8..]; // Skip "vmlinuz-"
                if !version.is_empty() {
                    return Ok(version.to_string());
                }
            }
        }
    }
    bail!(
        "Could not extract kernel version from command line: {}",
        cmdline
    );
}

/// Main function to measure RTMR1 from a qcow2 disk image
pub fn measure_rtmr1_from_qcow2(qcow2_path: &str) -> Result<Vec<u8>> {
    measure_rtmr1_from_qcow2_with_efi_paths(
        qcow2_path,
        &[
            "/boot/efi/EFI/ubuntu/shimx64.efi",
            "/boot/efi/EFI/ubuntu/grubx64.efi",
        ],
    )
}

/// Measure RTMR1 for EFI applications in the order they were launched.
pub fn measure_rtmr1_from_qcow2_with_efi_paths(
    qcow2_path: &str,
    efi_paths: &[&str],
) -> Result<Vec<u8>> {
    if efi_paths.is_empty() {
        bail!("at least one EFI application path is required");
    }

    let programs = efi_paths
        .iter()
        .map(|path| guestfish_download(qcow2_path, path))
        .collect::<Result<Vec<_>>>()?;
    measure_rtmr1_from_programs(qcow2_path, &programs)
}

fn measure_rtmr1_from_programs(qcow2_path: &str, programs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let gpt_data = extract_gpt_event_data(qcow2_path)?;
    let mut rtmr1_log = vec![
        measure_sha384(b"Calling EFI Application from Boot Option"),
        measure_sha384(&[0x00, 0x00, 0x00, 0x00]), // Separator
        measure_sha384(&gpt_data),
    ];
    for program in programs {
        rtmr1_log.push(
            authenticode_sha384_hash(&program).context("Failed to compute EFI application hash")?,
        );
    }
    rtmr1_log.push(measure_sha384(b"Exit Boot Services Invocation"));
    rtmr1_log.push(measure_sha384(b"Exit Boot Services Returned with Success"));

    debug_print_log("RTMR1", &rtmr1_log);
    Ok(measure_log(&rtmr1_log))
}

/// Measures RTMR2 using actual MOK variable data extracted from shim
pub fn measure_rtmr2_from_qcow2(
    qcow2_path: &str,
    cmdline: &str,
    ref_mok_list: &str,
    ref_mok_list_trusted: &str,
    ref_mok_list_x: &str,
) -> Result<Vec<u8>> {
    // Extract reference MOK variables
    let ref_mok_list_data = read_file_data(ref_mok_list)?;
    let ref_mok_list_trusted_data = read_file_data(ref_mok_list_trusted)?;
    let ref_mok_list_x_data = read_file_data(ref_mok_list_x)?;

    // Extract kernel version from command line and construct initrd path
    let kernel_version = extract_kernel_version_from_cmdline(cmdline)?;
    let initrd_path = format!("/boot/initrd.img-{}", kernel_version);

    // Extract initrd
    let initrd_data = guestfish_download(qcow2_path, &initrd_path)?;

    // Compute RTMR2 log
    let rtmr2_log = vec![
        measure_sha384(&ref_mok_list_data),
        measure_sha384(&ref_mok_list_x_data),
        measure_sha384(&ref_mok_list_trusted_data),
        measure_sha384(&utf16_encode(cmdline)),
        measure_sha384(&initrd_data),
    ];

    debug_print_log("RTMR2", &rtmr2_log);
    Ok(measure_log(&rtmr2_log))
}

/// Compute RTMR2 from fresh-state MOK events for the given shim paths.
/// Paths must follow boot order; other RTMR2 events are excluded.
pub fn measure_rtmr2_from_qcow2_mok_events(
    qcow2_path: &str,
    shim_paths: &[&str],
) -> Result<Vec<u8>> {
    if shim_paths.is_empty() {
        bail!("at least one shim path is required");
    }

    let mut rtmr2_log = Vec::new();
    for path in shim_paths {
        let shim_binary = guestfish_download(qcow2_path, path)?;
        rtmr2_log.extend(
            shim::mok_digests(&shim_binary)
                .with_context(|| format!("Failed to derive MOK measurements from {path}"))?,
        );
    }
    debug_print_log("RTMR2", &rtmr2_log);
    Ok(measure_log(&rtmr2_log))
}

/// Predict RTMR1 and shim-only RTMR2 for the chosen boot route.
/// Assumes fresh MOK state and excludes GRUB events.
pub fn measure_rtmrs_from_qcow2_with_boot_chain(
    qcow2_path: &str,
    boot_chain: &BootChain,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let paths = resolve_boot_chain(qcow2_path, boot_chain)?;
    let programs = download_boot_chain(qcow2_path, &paths)?;
    let rtmr1 = measure_rtmr1_from_programs(qcow2_path, &programs)?;

    let mut rtmr2_log = Vec::new();
    for (path, program) in paths.iter().zip(&programs) {
        if shim::vendor_mok_data(program)?.is_some() {
            rtmr2_log.extend(
                shim::mok_digests(program)
                    .with_context(|| format!("Failed to derive MOK measurements from {path}"))?,
            );
        }
    }
    if rtmr2_log.is_empty() {
        bail!("no shim found in the selected boot chain");
    }
    debug_print_log("RTMR2", &rtmr2_log);
    Ok((rtmr1, measure_log(&rtmr2_log)))
}
