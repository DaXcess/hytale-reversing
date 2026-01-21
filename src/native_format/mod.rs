pub mod hashtable;
pub mod parser;
pub mod reader;
pub mod ref_table;

use std::fmt::Debug;

use binary_rw::{ReadStream, SeekStream};
use pelite::pe64::{Pe, PeFile, PeObject, Va};

#[derive(Clone, Copy)]
pub struct View<'a> {
    pub pe: PeFile<'a>,

    base: Va,
    offset: Va,
}

impl<'a> View<'a> {
    pub fn new(pe: PeFile<'a>, va: Va) -> Self {
        Self {
            pe,
            base: va,
            offset: 0,
        }
    }

    pub fn va(self) -> Va {
        self.base + self.offset
    }

    pub fn bytes(self) -> pelite::Result<&'a [u8]> {
        self.pe
            .va_to_rva(self.va())
            .and_then(|rva| self.pe.rva_to_file_offset(rva))
            .map(|fo| &self.pe.image()[fo..])
    }

    pub fn with_offset(self, offset: Va) -> Self {
        Self::new(self.pe, self.base + offset)
    }
}

impl<'a> SeekStream for View<'a> {
    fn len(&self) -> binary_rw::Result<usize> {
        Ok(self
            .bytes()
            .map_err(|_| binary_rw::BinaryError::ReadPastEof)?
            .len())
    }

    fn tell(&mut self) -> binary_rw::Result<usize> {
        Ok((self.base + self.offset) as usize)
    }

    fn seek(&mut self, to: usize) -> binary_rw::Result<usize> {
        self.offset = to as u64;

        Ok(to)
    }
}

impl<'a> std::io::Read for View<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let slice = View::bytes(*self).map_err(|e| std::io::Error::other(e))?;
        let len = std::cmp::min(slice.len(), buf.len());

        buf[..len].copy_from_slice(&slice[..len]);

        self.offset += len as u64;

        Ok(len)
    }
}

impl<'a> ReadStream for View<'a> {}

impl<'a> Debug for View<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("View")
            .field(&format_args!("{:#x}", self.va()))
            .finish()
    }
}
