use crate::{
    error::{AotError, Result},
    native_format::{parser::NativeParser, reader::NativeReader},
};

#[derive(Clone, Copy)]
pub struct NativeHashtable<'a> {
    reader: NativeReader<'a>,
    base_offset: usize,
    bucket_mask: u32,
    entry_index_size: u8,
}

impl<'a> NativeHashtable<'a> {
    pub fn new(mut parser: NativeParser<'a>) -> Result<Self> {
        let header = parser.get_u8()?;
        let base_offset = parser.offset;

        let number_of_buckets_shift = (header >> 2) as i32;
        if number_of_buckets_shift > 31 {
            return Err(AotError::BadImage);
        }

        let entry_index_size = header & 3;
        if entry_index_size > 2 {
            return Err(AotError::BadImage);
        }

        Ok(Self {
            reader: parser.reader,
            base_offset,
            bucket_mask: ((1 << number_of_buckets_shift) - 1) as u32,
            entry_index_size,
        })
    }

    pub fn get_parser_for_bucket(
        &self,
        bucket: u32,
        offset: &mut usize,
    ) -> Result<NativeParser<'a>> {
        let (start, end) = if self.entry_index_size == 0 {
            let bucket_offset = self.base_offset + bucket as usize;

            (
                self.reader.read_u8(bucket_offset)? as u32,
                self.reader.read_u8(bucket_offset + 1)? as u32,
            )
        } else if self.entry_index_size == 1 {
            let bucket_offset = self.base_offset + 2 * bucket as usize;

            (
                self.reader.read_u16(bucket_offset)? as u32,
                self.reader.read_u16(bucket_offset + 2)? as u32,
            )
        } else {
            let bucket_offset = self.base_offset + 4 * bucket as usize;

            (
                self.reader.read_u32(bucket_offset)?,
                self.reader.read_u32(bucket_offset + 4)?,
            )
        };

        *offset = end as usize + self.base_offset;
        Ok(NativeParser::new(
            self.reader,
            self.base_offset + start as usize,
        ))
    }

    pub fn lookup(&self, hashcode: i32) -> Result<NativeHashtableIterator<'a>> {
        let mut offset = 0;
        let bucket = (hashcode as u32 >> 8) & self.bucket_mask;
        let parser = self.get_parser_for_bucket(bucket, &mut offset)?;

        Ok(NativeHashtableIterator::new(parser, offset, hashcode as u8))
    }

    pub fn enumerate_all(&self) -> Result<NativeHashtableAllEntries<'a>> {
        NativeHashtableAllEntries::new(*self)
    }
}

pub struct NativeHashtableIterator<'a> {
    parser: NativeParser<'a>,
    end_offset: usize,
    low_hashcode: u8,
}

impl<'a> NativeHashtableIterator<'a> {
    pub fn new(parser: NativeParser<'a>, end_offset: usize, low_hashcode: u8) -> Self {
        Self {
            parser,
            end_offset,
            low_hashcode,
        }
    }
}

impl<'a> Iterator for NativeHashtableIterator<'a> {
    type Item = NativeParser<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.offset < self.end_offset {
            let low_hashcode = self.parser.get_u8().ok()?;

            if low_hashcode == self.low_hashcode {
                return Some(self.parser.get_parser_from_rel_offset().ok()?);
            }

            // The entries are sorted by hashcode within the bucket. It allows us to terminate the lookup prematurely.
            if low_hashcode > self.low_hashcode {
                return None;
            }

            self.parser.skip_integer().ok()?;
        }

        None
    }
}

pub struct NativeHashtableAllEntries<'a> {
    table: NativeHashtable<'a>,
    parser: NativeParser<'a>,
    current_bucket: u32,
    end_offset: usize,
}

impl<'a> NativeHashtableAllEntries<'a> {
    pub fn new(table: NativeHashtable<'a>) -> Result<Self> {
        let mut end_offset = 0;
        let parser = table.get_parser_for_bucket(0, &mut end_offset)?;

        Ok(Self {
            table,
            parser,
            current_bucket: 0,
            end_offset,
        })
    }
}

impl<'a> Iterator for NativeHashtableAllEntries<'a> {
    type Item = NativeParser<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while self.parser.offset < self.end_offset {
                self.parser.get_u8().ok()?;
                return Some(self.parser.get_parser_from_rel_offset().ok()?);
            }

            if self.current_bucket >= self.table.bucket_mask {
                return None;
            }

            self.current_bucket += 1;
            self.parser = self
                .table
                .get_parser_for_bucket(self.current_bucket, &mut self.end_offset)
                .ok()?;
        }
    }
}
