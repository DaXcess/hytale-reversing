use std::fmt::Debug;

use crate::error::{AotError, Result};

macro_rules! impl_read_primitives {
    ($($fn:ident: $primitive:ident $(,)?)*) => {
        $(
            pub fn $fn(&self, offset: usize) -> Result<$primitive> {
                let slice = self
                    .data
                    .get(offset..offset + size_of::<$primitive>())
                    .ok_or(crate::error::AotError::BadImage)?;
                Ok($primitive::from_le_bytes(slice.try_into().unwrap()))
            }
        )*
    };
}

#[derive(Clone, Copy)]
pub struct NativeReader<'a> {
    data: &'a [u8],
}

impl<'a> NativeReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() >= (u32::MAX / 4) as usize {
            return Err(AotError::BadImage);
        }

        Ok(Self { data })
    }

    pub fn ensure_offset_in_range(&self, offset: usize, look_ahead: usize) -> Result<usize> {
        if (offset as isize) < 0 || offset + look_ahead >= self.data.len() {
            return Err(AotError::BadImage);
        }

        Ok(offset)
    }

    impl_read_primitives! {
        read_u8: u8,
        read_u16: u16,
        read_u32: u32,
        read_u64: u64,
        read_f32: f32,
        read_f64: f64,
    }

    pub fn read<R: NativeReadable<'a>>(&self, offset: &mut usize) -> Result<R> {
        R::read(self, offset)
    }

    pub fn decode_unsigned(&self, offset: &mut usize) -> Result<u32> {
        self.ensure_offset_in_range(*offset, 0)?;

        let value;
        let val = *self.data.get(*offset).ok_or(AotError::BadImage)? as u32;
        if val & 1 == 0 {
            value = val >> 1;
            *offset += 1;
        } else if val & 2 == 0 {
            if *offset + 1 > self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 2)
                | ((*self
                    .data
                    .get(*offset as usize + 1)
                    .ok_or(AotError::BadImage)? as u32)
                    << 6);
            *offset += 2;
        } else if val & 4 == 0 {
            if *offset + 2 >= self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 3)
                | ((*self.data.get(*offset + 1).ok_or(AotError::BadImage)? as u32) << 5)
                | ((*self.data.get(*offset + 2).ok_or(AotError::BadImage)? as u32) << 13);
            *offset += 3;
        } else if val & 8 == 0 {
            if *offset + 3 >= self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 4)
                | ((*self.data.get(*offset + 1).ok_or(AotError::BadImage)? as u32) << 4)
                | ((*self.data.get(*offset + 2).ok_or(AotError::BadImage)? as u32) << 12)
                | ((*self.data.get(*offset + 3).ok_or(AotError::BadImage)? as u32) << 20);
            *offset += 4;
        } else if val & 16 == 0 {
            *offset += 1;
            value = self.read_u32(*offset)?;
        } else {
            return Err(AotError::BadImage);
        }

        Ok(value)
    }

    pub fn decode_signed(&self, offset: &mut usize) -> Result<i32> {
        self.ensure_offset_in_range(*offset, 0)?;

        let value;
        let val = *self.data.get(*offset).ok_or(AotError::BadImage)? as i32;
        if val & 1 == 0 {
            value = (val as i8 >> 1) as i32;
            *offset += 1;
        } else if val & 2 == 0 {
            if *offset + 1 > self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 2)
                | ((self
                    .data
                    .get(*offset + 1)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 6);
            *offset += 2;
        } else if val & 4 == 0 {
            if *offset + 2 >= self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 3)
                | ((self
                    .data
                    .get(*offset + 1)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 5)
                | ((self
                    .data
                    .get(*offset + 2)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 13);
            *offset += 3;
        } else if val & 8 == 0 {
            if *offset + 3 >= self.data.len() {
                return Err(AotError::BadImage);
            }

            value = (val >> 4)
                | ((self
                    .data
                    .get(*offset + 1)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 4)
                | ((self
                    .data
                    .get(*offset + 2)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 12)
                | ((self
                    .data
                    .get(*offset + 3)
                    .map(|v| *v as i32)
                    .ok_or(AotError::BadImage)? as i32)
                    << 20);
            *offset += 4;
        } else if val & 16 == 0 {
            *offset += 1;
            value = self.read_u32(*offset)? as i32;
        } else {
            return Err(AotError::BadImage);
        }

        Ok(value)
    }

    pub fn decode_unsigned_long(&self, offset: &mut usize) -> Result<u64> {
        let val = *self.data.get(*offset as usize).ok_or(AotError::BadImage)?;

        Ok(if val & 31 != 31 {
            self.decode_unsigned(offset)? as u64
        } else if val & 32 == 0 {
            *offset += 1;
            self.read_u64(*offset)?
        } else {
            return Err(AotError::BadImage);
        })
    }

    pub fn decode_signed_long(&self, offset: &mut usize) -> Result<i64> {
        let val = *self.data.get(*offset as usize).ok_or(AotError::BadImage)?;

        Ok(if val & 31 != 31 {
            self.decode_signed(offset)? as i64
        } else if val & 32 == 0 {
            *offset += 1;
            self.read_u64(*offset)? as i64
        } else {
            return Err(AotError::BadImage);
        })
    }

    pub fn decode_string(&self, offset: &mut usize) -> Result<String> {
        let length = self.decode_unsigned(offset)?;

        if length == 0 {
            return Ok(String::new());
        }

        let end_offset = *offset + length as usize;
        if end_offset < length as usize || *offset > self.data.len() {
            return Err(AotError::BadImage);
        }

        Ok(
            String::from_utf8_lossy(&self.data[*offset as usize..*offset + length as usize])
                .into_owned(),
        )
    }

    pub fn skip_integer(&self, offset: &mut usize) -> Result<()> {
        let &val = self.data.get(*offset as usize).ok_or(AotError::BadImage)?;

        if val & 1 == 0 {
            *offset += 1;
        } else if val & 2 == 0 {
            *offset += 2;
        } else if val & 4 == 0 {
            *offset += 3;
        } else if val & 8 == 0 {
            *offset += 4;
        } else if val & 16 == 0 {
            *offset += 5;
        } else if val & 32 == 0 {
            *offset += 9;
        } else {
            return Err(AotError::BadImage);
        }

        Ok(())
    }

    pub fn get_unsigned_encoding_size(value: u32) -> u32 {
        match value {
            n if n < 128 => 1,
            n if n < 128 * 128 => 2,
            n if n < 128 * 128 * 128 => 3,
            n if n < 128 * 128 * 128 * 128 => 4,
            _ => 5,
        }
    }
}

impl<'a> Debug for NativeReader<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NativeReader ({} bytes)", self.data.len())
    }
}

pub trait NativeReadable<'a>
where
    Self: Sized,
{
    fn read(reader: &NativeReader<'a>, offset: &mut usize) -> Result<Self>;
}

mod native_reader_impls {
    use crate::native_format::reader::NativeReadable;

    impl<'a> NativeReadable<'a> for String {
        fn read(
            reader: &super::NativeReader<'_>,
            offset: &mut usize,
        ) -> crate::error::Result<Self> {
            reader.decode_string(offset)
        }
    }

    impl<'a> NativeReadable<'a> for u8 {
        fn read(
            reader: &super::NativeReader<'_>,
            offset: &mut usize,
        ) -> crate::error::Result<Self> {
            let value = reader.read_u8(*offset)?;
            *offset += 1;
            Ok(value)
        }
    }

    impl<'a> NativeReadable<'a> for u16 {
        fn read(
            reader: &super::NativeReader<'_>,
            offset: &mut usize,
        ) -> crate::error::Result<Self> {
            Ok(reader.decode_unsigned(offset)? as u16)
        }
    }

    impl<'a> NativeReadable<'a> for u32 {
        fn read(
            reader: &super::NativeReader<'_>,
            offset: &mut usize,
        ) -> crate::error::Result<Self> {
            reader.decode_unsigned(offset)
        }
    }
}
