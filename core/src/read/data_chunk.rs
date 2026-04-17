use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Take};

use flate2::read::ZlibDecoder;
use lzma_rust2::{Lzma2Reader, LzmaReader};

use crate::{
    error::InnoError,
    header::Compression,
    lzma_stream_header::LzmaStreamHeader,
    read::chunk::{Chunk, Encryption},
};

/// Magic bytes at the start of each data chunk.
const CHUNK_MAGIC: [u8; 4] = [b'z', b'l', b'b', 0x1a];

/// A reader for a single data chunk in the Inno Setup data stream.
///
/// Data chunks use a different format from the header streams: they start with
/// a 4-byte magic (`zlb\x1a`) followed by raw compressed data (no CRC32-checked
/// block layer).
pub enum DataChunkReader<R: Read> {
    Stored(Take<R>),
    Zlib(ZlibDecoder<Take<R>>),
    Lzma1(LzmaReader<Take<R>>),
    Lzma2(Lzma2Reader<Take<R>>),
}

/// Read the 1-byte LZMA2 properties header and derive the dictionary size.
fn read_lzma2_dict_size<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut props = [0u8; 1];
    reader.read_exact(&mut props)?;
    let props = props[0];
    if props > 40 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid LZMA2 properties byte",
        ));
    }
    Ok((2u32 | (u32::from(props) & 1)) << ((u32::from(props) >> 1) + 11))
}

impl<R: Read + Seek> DataChunkReader<R> {
    /// Open a data chunk for reading.
    ///
    /// Seeks to `data_offset + chunk.start_offset()` in the reader, validates
    /// the chunk magic, and sets up the appropriate decompression.
    pub fn new(mut reader: R, data_offset: u64, chunk: &Chunk) -> Result<Self, InnoError> {
        if chunk.encryption() != Encryption::Plaintext {
            return Err(InnoError::EncryptedInstaller);
        }

        // Seek to the chunk position in the data stream
        reader.seek(SeekFrom::Start(data_offset + chunk.start_offset()))?;

        // Read and validate the magic
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != CHUNK_MAGIC {
            return Err(InnoError::InvalidChunkMagic(magic));
        }

        // Limit reads to the compressed chunk size
        let limited = reader.take(chunk.original_size());

        match chunk.compression() {
            Compression::Stored => Ok(Self::Stored(limited)),
            Compression::Zlib => Ok(Self::Zlib(ZlibDecoder::new(limited))),
            Compression::LZMA1 => {
                let mut limited = limited;
                let (props, dict_size) = LzmaStreamHeader::read(&mut limited)?;
                Ok(Self::Lzma1(LzmaReader::new_with_props(
                    limited,
                    u64::MAX,
                    props,
                    dict_size,
                    None,
                )?))
            }
            Compression::LZMA2 => {
                let mut limited = limited;
                let dict_size = read_lzma2_dict_size(&mut limited)?;
                Ok(Self::Lzma2(Lzma2Reader::new(limited, dict_size, None)))
            }
            other => Err(InnoError::UnsupportedCompression(
                other.as_str().to_string(),
            )),
        }
    }
}

impl<R: Read> Read for DataChunkReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stored(r) => r.read(buf),
            Self::Zlib(r) => r.read(buf),
            Self::Lzma1(r) => r.read(buf),
            Self::Lzma2(r) => r.read(buf),
        }
    }
}
