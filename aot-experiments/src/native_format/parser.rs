use crate::{error::Result, native_format::reader::NativeReader};

#[derive(Clone, Copy)]
pub struct NativeParser<'a> {
    pub(super) reader: NativeReader<'a>,
    pub(super) offset: usize,
}

impl<'a> NativeParser<'a> {
    pub fn new(reader: NativeReader<'a>, offset: usize) -> Self {
        Self { reader, offset }
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        let value = self.reader.read_u8(self.offset)?;
        self.offset += 1;
        Ok(value)
    }

    pub fn get_unsigned(&mut self) -> Result<u32> {
        self.reader.decode_unsigned(&mut self.offset)
    }

    pub fn get_unsigned_long(&mut self) -> Result<u64> {
        self.reader.decode_unsigned_long(&mut self.offset)
    }

    pub fn get_signed(&mut self) -> Result<i32> {
        self.reader.decode_signed(&mut self.offset)
    }

    pub fn get_relative_offset(&mut self) -> Result<u32> {
        let pos = self.offset;
        let delta = self.reader.decode_signed(&mut self.offset)?;

        Ok(pos as u32 + delta as u32)
    }

    pub fn skip_integer(&mut self) -> Result<()> {
        self.reader.skip_integer(&mut self.offset)
    }

    pub fn get_parser_from_rel_offset(&mut self) -> Result<NativeParser<'a>> {
        Ok(NativeParser::new(
            self.reader,
            self.get_relative_offset()? as usize,
        ))
    }

    pub fn get_sequence_count(&mut self) -> Result<u32> {
        self.get_unsigned()
    }
}
