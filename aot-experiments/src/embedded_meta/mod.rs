pub mod collections;
pub mod flags;
pub mod handles;
pub mod utils;

use crate::{
    embedded_meta::{
        collections::{
            ByteCollection, CustomAttributeHandleCollection, EventHandleCollection,
            FieldHandleCollection, GenericParameterHandleCollection, HandleCollection,
            MethodHandleCollection, NamespaceDefinitionHandleCollection, ParameterHandleCollection,
            PropertyHandleCollection, ScopeDefinitionHandleCollection,
            TypeDefinitionHandleCollection, TypeForwarderHandleCollection,
        },
        flags::{MethodAttributes, SignatureCallingConvention},
        handles::{
            BaseHandle, ByReferenceSignatureHandle, ConstantStringValueHandle, FieldHandle,
            FieldSignatureHandle, GenericParameterHandle, MethodHandle, MethodSignatureHandle,
            MethodTypeVariableSignatureHandle, NamespaceDefinitionHandle, QualifiedMethodHandle,
            ScopeDefinitionHandle, TypeDefinitionHandle, TypeInstantiationSignatureHandle,
            TypeSpecificationHandle, TypeVariableSignatureHandle,
        },
    },
    error::{AotError, Result},
    native_format::reader::NativeReader,
};

macro_rules! impl_handle {
    (
        $name:ident,
        $handle:ident,
        {
            $(
                $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        #[derive(Clone)]
        pub struct $name<'a> {
            reader: $crate::embedded_meta::MetadataReader<'a>,
            handle: $handle,

            $(
                pub $field: $ty,
            )*
        }

        impl<'a> $name<'a> {
            pub fn new(reader: $crate::embedded_meta::MetadataReader<'a>, handle: $handle) -> $crate::error::Result<Self> {
                let mut offset = handle.offset() as usize;

                $(
                    let $field = reader.stream_reader.read::<$ty>(&mut offset)?;
                )*

                Ok(Self {
                    reader,
                    handle,

                    $(
                        $field,
                    )*
                })
            }

            pub fn handle(&self) -> $handle {
                self.handle
            }
        }

        impl $handle {
            pub fn to_data(self, reader: $crate::embedded_meta::MetadataReader<'_>) -> $crate::error::Result<$name<'_>> {
                $name::new(reader, self)
            }
        }

        impl<'a> core::fmt::Debug for $name<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(
                        .field(stringify!($field), &self.$field)
                    )*
                    .finish()
            }
        }
    };
}

#[derive(Clone, Copy, Debug)]
pub struct MetadataReader<'a> {
    stream_reader: NativeReader<'a>,
    header: MetadataHeader<'a>,
}

impl<'a> MetadataReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let stream_reader = NativeReader::new(data)?;
        let header = MetadataHeader::decode(stream_reader)?;

        Ok(Self {
            stream_reader,
            header,
        })
    }

    pub fn header(&self) -> MetadataHeader<'a> {
        self.header
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MetadataHeader<'a> {
    reader: NativeReader<'a>,
    scope_definitions: ScopeDefinitionHandleCollection<'a>,
}

impl<'a> MetadataHeader<'a> {
    const SIGNATURE: u32 = 0xDEADDFFD;

    fn decode(reader: NativeReader<'a>) -> Result<Self> {
        if reader.read_u32(0)? != Self::SIGNATURE {
            return Err(AotError::BadImage);
        }

        let collection = ScopeDefinitionHandleCollection::new(reader, 4);

        Ok(Self {
            reader,
            scope_definitions: collection,
        })
    }

    pub fn scope_definitions(&self) -> ScopeDefinitionHandleCollection<'a> {
        self.scope_definitions
    }
}

impl_handle!(ScopeDefinition, ScopeDefinitionHandle, {
    flags: u32,
    name: ConstantStringValueHandle,
    hash_algorithm: u32,
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision_number: u16,
    public_key: ByteCollection<'a>,
    culture: ConstantStringValueHandle,
    root_namespace_definition: NamespaceDefinitionHandle,
    entrypoint: QualifiedMethodHandle,
    global_module_type: TypeDefinitionHandle,
    custom_attributes: CustomAttributeHandleCollection<'a>,
    module_name: ConstantStringValueHandle,
    mvid: ByteCollection<'a>,
    module_custom_attributes: CustomAttributeHandleCollection<'a>,
});

impl_handle!(
    ConstantStringValue,
    ConstantStringValueHandle,
    { value: String }
);

impl_handle!(NamespaceDefinition, NamespaceDefinitionHandle, {
    parent_scope_or_namespace: BaseHandle,
    name: ConstantStringValueHandle,
    type_definitions: TypeDefinitionHandleCollection<'a>,
    type_forwarders: TypeForwarderHandleCollection<'a>,
    namespace_definitions: NamespaceDefinitionHandleCollection<'a>
});

impl_handle!(TypeDefinition, TypeDefinitionHandle, {
    flags: u32,
    base_type: BaseHandle,
    namespace_definition: NamespaceDefinitionHandle,
    name: ConstantStringValueHandle,
    size: u32,
    packing_size: u16,
    enclosing_type: TypeDefinitionHandle,
    nested_types: TypeDefinitionHandleCollection<'a>,
    methods: MethodHandleCollection<'a>,
    fields: FieldHandleCollection<'a>,
    properties: PropertyHandleCollection<'a>,
    events: EventHandleCollection<'a>,
    generic_parameters: GenericParameterHandleCollection<'a>,
    interfaces: HandleCollection<'a>,
    custom_attributes: CustomAttributeHandleCollection<'a>
});

impl_handle!(Method, MethodHandle, {
    flags: MethodAttributes,
    impl_flags: u32,
    name: ConstantStringValueHandle,
    signature: MethodSignatureHandle,
    parameters: ParameterHandleCollection<'a>,
    generic_parameters: GenericParameterHandleCollection<'a>,
    custom_attributes: CustomAttributeHandleCollection<'a>
});

impl_handle!(Field, FieldHandle, {
    flags: u32,
    name: ConstantStringValueHandle,
    signature: FieldSignatureHandle,
    default_value: BaseHandle,
    offset: u32,
    custom_attributes: CustomAttributeHandleCollection<'a>
});

impl_handle!(FieldSignature, FieldSignatureHandle, {
    type_handle: BaseHandle,
});

impl_handle!(MethodSignature, MethodSignatureHandle, {
    calling_convention: SignatureCallingConvention,
    generic_parameter_count: i32,
    return_type: BaseHandle,
    parameters: HandleCollection<'a>,
    var_arg_parameters: HandleCollection<'a>
});

impl_handle!(TypeSpecification, TypeSpecificationHandle, {
    signature: BaseHandle
});

impl_handle!(TypeInstantiationSignature, TypeInstantiationSignatureHandle, {
    generic_type: BaseHandle,
    generic_args: HandleCollection<'a>,
});

impl_handle!(ByReferenceSignature, ByReferenceSignatureHandle, {
    type_handle: BaseHandle
});

impl_handle!(MethodTypeVariableSignature, MethodTypeVariableSignatureHandle, {
    number: i32
});

impl_handle!(TypeVariableSignature, TypeVariableSignatureHandle, {
    number: i32
});

impl_handle!(GenericParameter, GenericParameterHandle, {
    number: u16,
    flags: u32,
    kind: u8,
    name: ConstantStringValueHandle,
    constraints: HandleCollection<'a>,
    custom_attributes: CustomAttributeHandleCollection<'a>,
});
