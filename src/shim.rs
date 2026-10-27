use crate::num::read_le;
use crate::util::measure_sha384;
use anyhow::{bail, Context, Result};
use object::read::pe::PeFile64;
use object::{Object, ObjectSection};

// GUIDs as stored in EFI signature lists.
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
const EFI_CERT_SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
const SHIM_LOCK_GUID: [u8; 16] = [
    0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23,
];

const SIGNATURE_LIST_HEADER: usize = 28;
const VENDOR_TABLE_HEADER: u32 = 16;

// Fresh-state value measured for MokListTrusted.
const MOK_LIST_TRUSTED: &[u8] = &[0x01];

fn signature_list(signature_type: &[u8; 16], signature: &[u8]) -> Vec<u8> {
    let mut list = Vec::with_capacity(SIGNATURE_LIST_HEADER + signature.len());
    list.extend_from_slice(signature_type);
    list.extend_from_slice(&((SIGNATURE_LIST_HEADER + signature.len()) as u32).to_le_bytes());
    list.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
    list.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    list.extend_from_slice(signature);
    list
}

/// Check a sequence of EFI signature lists.
fn validate_signature_lists(payload: &[u8]) -> Result<()> {
    let mut position = 0usize;
    while position + SIGNATURE_LIST_HEADER <= payload.len() {
        let list_size: u32 = read_le(payload, position + 16, "signature list size")?;
        let header_size: u32 = read_le(payload, position + 20, "signature header size")?;
        let signature_size: u32 = read_le(payload, position + 24, "signature size")?;
        let Some(signature_bytes) = (list_size as usize)
            .checked_sub(SIGNATURE_LIST_HEADER)
            .and_then(|n| n.checked_sub(header_size as usize))
        else {
            break;
        };
        if signature_size <= 16
            || signature_bytes == 0
            || signature_bytes % signature_size as usize != 0
        {
            break;
        }
        position += list_size as usize;
    }
    if position != payload.len() {
        bail!("shim contains malformed EFI signature-list data");
    }
    Ok(())
}

/// Build MokList from a raw certificate or an EFI signature list.
fn authorized_mok_data(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.starts_with(&[0x30, 0x82]) {
        let mut signature = SHIM_LOCK_GUID.to_vec();
        signature.extend_from_slice(payload);
        return Ok(signature_list(&EFI_CERT_X509_GUID, &signature));
    }
    validate_signature_lists(payload)?;
    Ok(payload.to_vec())
}

/// Build MokListX when shim has no vendor denylist.
fn empty_mok_list_x() -> Vec<u8> {
    let mut signature = SHIM_LOCK_GUID.to_vec();
    signature.extend_from_slice(&[0u8; 32]);
    signature_list(&EFI_CERT_SHA256_GUID, &signature)
}

/// Parse a vendor certificate table from one PE section, if present.
fn parse_vendor_table(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() < VENDOR_TABLE_HEADER as usize {
        return None;
    }
    let authorized_size: u32 = read_le(data, 0, "authorized size").ok()?;
    let deauthorized_size: u32 = read_le(data, 4, "deauthorized size").ok()?;
    let authorized_offset: u32 = read_le(data, 8, "authorized offset").ok()?;
    let deauthorized_offset: u32 = read_le(data, 12, "deauthorized offset").ok()?;

    if authorized_size == 0 || authorized_offset != VENDOR_TABLE_HEADER {
        return None;
    }
    let authorized = data.get(
        authorized_offset as usize..(authorized_offset.checked_add(authorized_size)?) as usize,
    )?;
    let mok_list = authorized_mok_data(authorized).ok()?;

    let mok_list_x = if deauthorized_size == 0 {
        empty_mok_list_x()
    } else {
        if deauthorized_offset < VENDOR_TABLE_HEADER {
            return None;
        }
        let deauthorized = data.get(
            deauthorized_offset as usize
                ..(deauthorized_offset.checked_add(deauthorized_size)?) as usize,
        )?;
        validate_signature_lists(deauthorized).ok()?;
        deauthorized.to_vec()
    };
    Some((mok_list, mok_list_x))
}

/// Find shim's built-in MokList and MokListX.
pub(crate) fn vendor_mok_data(binary: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let pe = PeFile64::parse(binary).context("not a valid PE image")?;
    // Section names may be missing, so inspect their contents.
    for section in pe.sections() {
        let Ok(data) = section.data() else { continue };
        if let Some(table) = parse_vendor_table(data) {
            return Ok(Some(table));
        }
    }
    Ok(None)
}

/// Return one shim's MokList, MokListX, and MokListTrusted event digests.
pub(crate) fn mok_digests(binary: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (mok_list, mok_list_x) =
        vendor_mok_data(binary)?.context("could not find shim's vendor certificate table")?;
    Ok(vec![
        measure_sha384(&mok_list),
        measure_sha384(&mok_list_x),
        measure_sha384(MOK_LIST_TRUSTED),
    ])
}
