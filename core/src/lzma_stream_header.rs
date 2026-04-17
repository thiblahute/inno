use std::io::{Error, ErrorKind, Read, Result};

/// Upper bound for the `dict_size` field in the 5-byte LZMA1 properties
/// header.
///
/// The LZMA1 format allows dictionaries up to ~4 GiB, but real Inno Setup
/// installers use small dictionaries (Inno's default is 8 MiB). 256 MiB is far
/// above anything produced in practice, while still preventing a crafted
/// installer from forcing `LzmaReader` into a multi-gigabyte allocation on
/// construction.
pub const MAX_LZMA1_DICT_SIZE: u32 = 256 * 1024 * 1024;

pub struct LzmaStreamHeader;

impl LzmaStreamHeader {
    /// Parses the 5-byte raw LZMA1 properties header used by Inno Setup's LZMA1
    /// streams (same layout as the `.lzma` format): a single properties byte
    /// encoding lc/lp/pb, followed by a little-endian `u32` dictionary size.
    ///
    /// Rejects headers whose `dict_size` exceeds [`MAX_LZMA1_DICT_SIZE`]:
    /// `lzma_rust2::LzmaReader` eagerly allocates a buffer of the declared
    /// size, so an attacker-controlled header could otherwise force a
    /// multi-gigabyte allocation at construction time.
    pub fn read<R>(src: &mut R) -> Result<(u8, u32)>
    where
        R: Read,
    {
        let mut properties = [0; 5];
        src.read_exact(&mut properties)?;
        let props = properties[0];
        let dict_size = u32::from_le_bytes([
            properties[1],
            properties[2],
            properties[3],
            properties[4],
        ]);
        if dict_size > MAX_LZMA1_DICT_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("LZMA1 dictionary size too large: {dict_size} bytes"),
            ));
        }
        Ok((props, dict_size))
    }
}
