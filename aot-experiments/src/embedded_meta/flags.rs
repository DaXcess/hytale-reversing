use num_enum::{FromPrimitive, TryFromPrimitive};

// === Method ===

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MethodAttributes(u32);

impl MethodAttributes {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
pub enum MethodMemberAccess {
    #[default]
    PrivateScope = 0x0,
    Private = 0x1,
    FamAndAssem = 0x2,
    Assembly = 0x3,
    Family = 0x4,
    FamOrAssem = 0x5,
    Public = 0x6,
}

impl MethodAttributes {
    pub const MEMBER_ACCESS_MASK: u32 = 0x0007;

    pub fn member_access(self) -> MethodMemberAccess {
        MethodMemberAccess::from_primitive((self.0 & Self::MEMBER_ACCESS_MASK) as u8)
    }
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
pub enum VtableLayout {
    #[default]
    ReuseSlot = 0x0000,
    NewSlot = 0x0100,
}

impl MethodAttributes {
    pub const VTABLE_LAYOUT_MASK: u32 = 0x0100;

    pub fn vtable_layout(self) -> VtableLayout {
        VtableLayout::from_primitive((self.0 & Self::VTABLE_LAYOUT_MASK) as u16)
    }
}

impl MethodAttributes {
    pub const STATIC: u32 = 0x0010;
    pub const FINAL: u32 = 0x0020;
    pub const VIRTUAL: u32 = 0x0040;
    pub const ABSTRACT: u32 = 0x0400;
    pub const PINVOKE_IMPL: u32 = 0x2000;
    pub const RTSPECIAL_NAME: u32 = 0x1000;

    pub fn is_static(self) -> bool {
        self.0 & Self::STATIC != 0
    }

    pub fn is_virtual(self) -> bool {
        self.0 & Self::VIRTUAL != 0
    }

    pub fn is_abstract(self) -> bool {
        self.0 & Self::ABSTRACT != 0
    }

    pub fn is_pinvoke(self) -> bool {
        self.0 & Self::PINVOKE_IMPL != 0
    }
}

impl MethodAttributes {
    pub const RESERVED_MASK: u32 = 0xd000;

    pub fn reserved_bits(self) -> u32 {
        self.0 & Self::RESERVED_MASK
    }
}

// === Method Signature ===

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum SignatureCallingConvention {
    #[default]
    Default = 0x00,
    HasThis = 0x20,
    ExplicitThis = 0x40,
    Vararg = 0x05,
    Cdecl = 0x01,
    StdCall = 0x02,
    ThisCall = 0x03,
    FastCall = 0x04,
    Unmanaged = 0x09,
    UnmanagedCallingConventionMask = 0x0F,
}
