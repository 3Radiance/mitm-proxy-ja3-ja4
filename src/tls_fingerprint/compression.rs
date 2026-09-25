use btls::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};
use std::io::Write;

pub struct BrotliCompressor;

impl CertificateCompressor for BrotliCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decompressor = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut decompressor, output)?;
        Ok(())
    }
}

pub struct ZlibCompressor;

impl CertificateCompressor for ZlibCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

pub struct ZstdCompressor;

impl CertificateCompressor for ZstdCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        zstd::stream::copy_decode(input, output)?;
        Ok(())
    }
}
