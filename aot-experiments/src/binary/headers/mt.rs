use std::{cell::RefCell, rc::Rc};

use anyhow::{Result, bail};
use binary_rw::{BinaryReader, Endian};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::native_format::View;

#[derive(Debug, Clone)]
pub struct MethodTable<'a> {
    pub view: View<'a>,

    pub flags: u32,
    pub base_size: u32,
    pub related_type_address: u64,
    pub hashcode: u32,
    pub element_type: ElementType,

    pub vtable_addresses: Rc<[u64]>,
    pub iface_addresses: Rc<[u64]>,

    // I'm not too well versed in memory optimizations, but not adding Rc's here made the app waste over 30 GiB of memory (obviously due to self-referencing)
    // Additionally adding Rc<RefCell<...>> further reduced mem usage from 2.2 GiB to ~40 MiB (not including std::fs::read) on my test binary of ~50 MiB
    // Could this be optimized even further?
    // Is this even the correct approach?
    pub related_type: Option<Rc<MethodTable<'a>>>,
    pub interfaces: Rc<RefCell<Vec<MethodTable<'a>>>>,
}

impl<'a> MethodTable<'a> {
    const ELEMENT_TYPE_MASK: u32 = 0x7C000000;
    const ELEMENT_TYPE_SHIFT: u32 = 26;

    pub fn parse(view: &mut View<'a>) -> Result<Self> {
        let table_view = *view;
        let mut reader = BinaryReader::new(view, Endian::Little);

        let flags = reader.read_u32()?;
        let base_size = reader.read_u32()?;
        let related_type = reader.read_u64()?;
        let vtable_count = reader.read_u16()?;
        let iface_count = reader.read_u16()?;
        let hashcode = reader.read_u32()?;

        if (vtable_count as i16) < 0 || vtable_count >= 1000 {
            bail!("invalid vtable slot count");
        }

        if (iface_count as i16) < 0 || iface_count >= 1000 {
            bail!("invalid interface count");
        }

        let mut vtables = Vec::with_capacity(vtable_count as _);
        for _ in 0..vtable_count {
            vtables.push(reader.read_u64()?);
        }

        let mut ifaces = Vec::with_capacity(iface_count as _);
        for _ in 0..iface_count {
            ifaces.push(reader.read_u64()?);
        }

        let element_type =
            ElementType::try_from((flags & Self::ELEMENT_TYPE_MASK) >> Self::ELEMENT_TYPE_SHIFT)
                .unwrap_or(ElementType::Unknown);
        if element_type == ElementType::Interface {
            if base_size != 0x00 {
                bail!("unexpected non-zero interface base size");
            } else if related_type != 0x00 {
                bail!("unexpected non-zero interface related type");
            }
        } else if base_size < 0x10 {
            bail!("unexpected base size")
        }

        Ok(Self {
            view: table_view,

            flags,
            base_size,
            related_type_address: related_type,
            hashcode,
            element_type,

            vtable_addresses: vtables.into(),
            iface_addresses: ifaces.into(),

            related_type: None,
            interfaces: Rc::new(RefCell::new(Vec::with_capacity(iface_count as _))),
        })
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ElementType {
    // Primitive
    Unknown = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    SByte = 0x04,
    Byte = 0x05,
    Int16 = 0x06,
    UInt16 = 0x07,
    Int32 = 0x08,
    UInt32 = 0x09,
    Int64 = 0x0A,
    UInt64 = 0x0B,
    IntPtr = 0x0C,
    UIntPtr = 0x0D,
    Single = 0x0E,
    Double = 0x0F,

    ValueType = 0x10,
    // Enum = 0x11, // EETypes store enums as their underlying type
    Nullable = 0x12,
    // Unused 0x13,
    Class = 0x14,
    Interface = 0x15,

    SystemArray = 0x16, // System.Array type

    Array = 0x17,
    SzArray = 0x18,
    ByRef = 0x19,
    Pointer = 0x1A,
    FunctionPointer = 0x1B,
}
