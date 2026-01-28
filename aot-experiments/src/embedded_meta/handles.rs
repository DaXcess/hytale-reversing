use std::fmt::Debug;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{
    error::{AotError, Result},
    native_format::reader::NativeReadable,
};

macro_rules! define_handle {
    ($name:ident, $typ:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(u32);

        impl $crate::embedded_meta::handles::Handle for $name {
            fn from_value(value: u32) -> Result<Self> {
                let handle_type = HandleType::try_from((value >> 25) as u8)
                    .map_err(|_| AotError::InvalidMetaHandle)?;
                if handle_type != HandleType::$typ && handle_type != HandleType::Null {
                    return Err(AotError::InvalidMetaHandle)?;
                }

                Ok(Self(
                    (value & 0x01FFFFFF)
                        | (<HandleType as Into<u8>>::into(HandleType::$typ) as u32) << 25,
                ))
            }

            fn to_value(&self) -> u32 {
                self.0
            }
        }

        impl<'a> $crate::native_format::reader::NativeReadable<'a> for $name {
            fn read(
                reader: &$crate::native_format::reader::NativeReader<'a>,
                offset: &mut usize,
            ) -> Result<Self> {
                let value = reader.decode_unsigned(offset)?;

                $name::from_value(value)
            }
        }

        impl $name {
            pub fn offset(&self) -> u32 {
                self.0 & 0x01FFFFFF
            }

            pub fn is_nil(&self) -> bool {
                self.0 & 0x01FFFFFF == 0
            }
        }

        impl ToString for $name {
            fn to_string(&self) -> String {
                format!("{:#X}", self.0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&HandleType::$typ)
                    .field(&format_args!("{:#x}", self.offset()))
                    .finish()
            }
        }
    };
}

#[repr(u8)]
#[derive(IntoPrimitive, TryFromPrimitive, Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandleType {
    Null = 0x0,
    ArraySignature = 0x1,
    ByReferenceSignature = 0x2,
    ConstantBooleanArray = 0x3,
    ConstantBooleanValue = 0x4,
    ConstantByteArray = 0x5,
    ConstantByteValue = 0x6,
    ConstantCharArray = 0x7,
    ConstantCharValue = 0x8,
    ConstantDoubleArray = 0x9,
    ConstantDoubleValue = 0xa,
    ConstantEnumArray = 0xb,
    ConstantEnumValue = 0xc,
    ConstantHandleArray = 0xd,
    ConstantInt16Array = 0xe,
    ConstantInt16Value = 0xf,
    ConstantInt32Array = 0x10,
    ConstantInt32Value = 0x11,
    ConstantInt64Array = 0x12,
    ConstantInt64Value = 0x13,
    ConstantReferenceValue = 0x14,
    ConstantSByteArray = 0x15,
    ConstantSByteValue = 0x16,
    ConstantSingleArray = 0x17,
    ConstantSingleValue = 0x18,
    ConstantStringArray = 0x19,
    ConstantStringValue = 0x1a,
    ConstantUInt16Array = 0x1b,
    ConstantUInt16Value = 0x1c,
    ConstantUInt32Array = 0x1d,
    ConstantUInt32Value = 0x1e,
    ConstantUInt64Array = 0x1f,
    ConstantUInt64Value = 0x20,
    CustomAttribute = 0x21,
    Event = 0x22,
    Field = 0x23,
    FieldSignature = 0x24,
    FunctionPointerSignature = 0x25,
    GenericParameter = 0x26,
    MemberReference = 0x27,
    Method = 0x28,
    MethodInstantiation = 0x29,
    MethodSemantics = 0x2a,
    MethodSignature = 0x2b,
    MethodTypeVariableSignature = 0x2c,
    ModifiedType = 0x2d,
    NamedArgument = 0x2e,
    NamespaceDefinition = 0x2f,
    NamespaceReference = 0x30,
    Parameter = 0x31,
    PointerSignature = 0x32,
    Property = 0x33,
    PropertySignature = 0x34,
    QualifiedField = 0x35,
    QualifiedMethod = 0x36,
    SZArraySignature = 0x37,
    ScopeDefinition = 0x38,
    ScopeReference = 0x39,
    TypeDefinition = 0x3a,
    TypeForwarder = 0x3b,
    TypeInstantiationSignature = 0x3c,
    TypeReference = 0x3d,
    TypeSpecification = 0x3e,
    TypeVariableSignature = 0x3f,

    Invalid = 0xff, // I made this because I didn't like the Option<HandleType> when logging
}

pub trait Handle
where
    Self: Sized,
{
    fn from_value(value: u32) -> Result<Self>;
    fn to_value(&self) -> u32;

    fn to_base(self) -> BaseHandle {
        BaseHandle(self.to_value())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BaseHandle(u32);

impl Handle for BaseHandle {
    fn from_value(value: u32) -> Result<Self> {
        let handle_type = value & 0x7F;
        let offset = value >> 7;

        Ok(Self(handle_type << 25 | offset))
    }

    fn to_value(&self) -> u32 {
        self.0
    }
}

impl<'a> NativeReadable<'a> for BaseHandle {
    fn read(
        reader: &crate::native_format::reader::NativeReader<'a>,
        offset: &mut usize,
    ) -> Result<Self> {
        BaseHandle::from_value(reader.decode_unsigned(offset)?)
    }
}

impl BaseHandle {
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn to_handle<H: Handle>(self) -> Result<H> {
        H::from_value(self.0)
    }

    pub fn handle_type(&self) -> Option<HandleType> {
        HandleType::try_from((self.0 >> 25) as u8).ok()
    }

    pub fn offset(&self) -> u32 {
        self.0 & 0x01FFFFFF
    }

    pub fn is_nil(&self) -> bool {
        self.0 & 0x01FFFFFF == 0
    }
}

impl Debug for BaseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BaseHandle")
            .field(&self.handle_type().unwrap_or(HandleType::Invalid))
            .field(&format_args!("{:#x}", self.0 & 0x01FFFFFF))
            .finish()
    }
}

define_handle!(ByReferenceSignatureHandle, ByReferenceSignature); // 2
define_handle!(ConstantStringValueHandle, ConstantStringValue); // 26
define_handle!(CustomAttributeHandle, CustomAttribute); // 33
define_handle!(EventHandle, Event); // 34
define_handle!(FieldHandle, Field); // 35
define_handle!(FieldSignatureHandle, FieldSignature); // 36
define_handle!(GenericParameterHandle, GenericParameter); // 38
define_handle!(MethodHandle, Method); // 40
define_handle!(MethodSignatureHandle, MethodSignature); // 43
define_handle!(
    MethodTypeVariableSignatureHandle,
    MethodTypeVariableSignature
); // 44
define_handle!(NamespaceDefinitionHandle, NamespaceDefinition); // 47
define_handle!(ParameterHandle, Parameter); // 49
define_handle!(PropertyHandle, Property); // 51
define_handle!(QualifiedMethodHandle, QualifiedMethod); // 54
define_handle!(ScopeDefinitionHandle, ScopeDefinition); // 56
define_handle!(TypeDefinitionHandle, TypeDefinition); // 58
define_handle!(TypeForwarderHandle, TypeForwarder); // 59
define_handle!(TypeInstantiationSignatureHandle, TypeInstantiationSignature); // 60
define_handle!(TypeSpecificationHandle, TypeSpecification); // 62
define_handle!(TypeVariableSignatureHandle, TypeVariableSignature); // 63
