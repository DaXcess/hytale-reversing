use paste::paste;

use crate::{
    embedded_meta::handles::{
        BaseHandle, CustomAttributeHandle, EventHandle, FieldHandle, GenericParameterHandle,
        MethodHandle, NamespaceDefinitionHandle, PropertyHandle, ScopeDefinitionHandle,
        TypeDefinitionHandle, TypeForwarderHandle,
    },
    native_format::reader::NativeReadable,
};

macro_rules! define_collection {
    ($name:ident, $handle:ident) => {
        define_collection!(@base $name, $handle);
        define_collection!(@reader $name);
    };

    ($name:ident, $handle:ident, @skip_read_impl) => {
        define_collection!(@base $name, $handle);
    };

    (@base $name:ident, $handle:ident) => {
        #[derive(Clone, Copy)]
        pub struct $name<'a> {
            reader: $crate::native_format::reader::NativeReader<'a>,
            offset: usize,
        }

        impl<'a> $name<'a> {
            pub fn new(reader: $crate::native_format::reader::NativeReader<'a>, offset: usize) -> Self {
                Self { reader, offset }
            }

            paste! {
                pub fn iter(&self) -> $crate::error::Result<[<$name Iter>]<'a>> {
                    [<$name Iter>]::new(self.reader, self.offset)
                }
            }

            pub fn count(&self) -> $crate::error::Result<u32> {
                let mut _offset = self.offset;
                self.reader.decode_unsigned(&mut _offset)
            }
        }

        impl<'a> core::fmt::Debug for $name<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let count = self
                    .count()
                    .map(|c| format!("{c} element{}", if c == 1 { "" } else { "s" }))
                    .unwrap_or_else(|_| "<error>".to_string());

                write!(f, "{} ({count})", stringify!($name))
            }
        }

        paste !{
            pub struct [<$name Iter>]<'a> {
                reader: $crate::native_format::reader::NativeReader<'a>,
                offset: usize,
                remaining: u32,
            }

            impl<'a> [<$name Iter>]<'a> {
                pub fn new(
                    reader: $crate::native_format::reader::NativeReader<'a>,
                    mut offset: usize,
                ) -> $crate::error::Result<Self> {
                    let count = reader.decode_unsigned(&mut offset)?;

                    Ok(Self {
                        reader,
                        offset,
                        remaining: count,
                    })
                }
            }

            impl<'a> Iterator for [<$name Iter>]<'a> {
                type Item = $crate::error::Result<$handle>;

                fn next(&mut self) -> Option<Self::Item> {
                    if self.remaining == 0 {
                        return None;
                    }

                    self.remaining -= 1;

                    Some(self.reader.read::<$handle>(&mut self.offset))
                }
            }
        }
    };

    (@reader $name:ident) => {
        impl<'a> $crate::native_format::reader::NativeReadable<'a> for $name<'a> {
            fn read(
                reader: &$crate::native_format::reader::NativeReader<'a>,
                offset: &mut usize,
            ) -> crate::error::Result<Self> {
                let collection = Self::new(*reader, *offset);
                let count = reader.decode_unsigned(offset)?;

                for _ in 0..count {
                    reader.skip_integer(offset)?;
                }

                Ok(collection)
            }
        }
    }
}

define_collection!(HandleCollection, BaseHandle);
define_collection!(CustomAttributeHandleCollection, CustomAttributeHandle);
define_collection!(EventHandleCollection, EventHandle);
define_collection!(FieldHandleCollection, FieldHandle);
define_collection!(GenericParameterHandleCollection, GenericParameterHandle);
define_collection!(MethodHandleCollection, MethodHandle);
define_collection!(
    NamespaceDefinitionHandleCollection,
    NamespaceDefinitionHandle
);
define_collection!(PropertyHandleCollection, PropertyHandle);
define_collection!(ScopeDefinitionHandleCollection, ScopeDefinitionHandle);
define_collection!(TypeDefinitionHandleCollection, TypeDefinitionHandle);
define_collection!(TypeForwarderHandleCollection, TypeForwarderHandle);
define_collection!(ByteCollection, u8, @skip_read_impl);

impl<'a> NativeReadable<'a> for ByteCollection<'a> {
    fn read(
        reader: &crate::native_format::reader::NativeReader<'a>,
        offset: &mut usize,
    ) -> crate::error::Result<Self> {
        let collection = ByteCollection::new(*reader, *offset);
        let length = reader.decode_unsigned(offset)?;
        *offset += length as usize * size_of::<u8>();

        Ok(collection)
    }
}
