use std::fmt::Debug;

use anyhow::{Result, anyhow};
use binary_rw::{BinaryReader, Endian};
use num_enum::FromPrimitive;

use crate::{
    embedded_meta::MetadataReader,
    native_format::{
        View, hashtable::NativeHashtable, parser::NativeParser, reader::NativeReader,
        ref_table::ExternalReferencesTable,
    },
};

#[derive(Debug)]
pub struct ReadyToRunHeader<'a> {
    signature: Signature,

    pub major_version: u16,
    pub minor_version: u16,
    pub flags: u32,
    pub number_of_sections: u16,
    pub entry_size: u8,
    pub entry_type: u8,
    pub sections: Vec<ReadyToRunSection<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ReadyToRunSection<'a> {
    view: View<'a>,

    pub section_type: ReadyToRunSectionType,
    pub flags: u32,
    pub start: View<'a>,
    pub end: View<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyToRunSectionType {
    //
    // CoreCLR ReadyToRun sections
    //
    CompilerIdentifier,
    ImportSections,
    RuntimeFunctions,
    MethodDefEntryPoints,
    ExceptionInfo,
    DebugInfo,
    DelayLoadMethodCallThunks,
    AvailableTypes,
    InstanceMethodEntryPoints,
    InliningInfo,             // Added in v.2.1, deprecated in 4.1
    ProfileDataInfo,          // Added in v2.2
    ManifestMetadata,         // Added in v2.3
    AttributePresence,        // Added in v3.1
    InliningInfo2,            // Added in v4.1
    ComponentAssemblies,      // Added in v4.1
    OwnerCompositeExecutable, // Added in v4.1
    PgoInstrumentationData,   // Added in v5.2
    ManifestAssemblyMvids,    // Added in v5.3
    CrossModuleInlineInfo,    // Added in v6.3
    HotColdMap,               // Added in v8.0
    MethodIsGenericMap,       // Added in v9.0
    EnclosingTypeMap,         // Added in v9.0
    TypeGenericInfoMap,       // Added in v9.0

    //
    // NativeAOT ReadyToRun sections
    //
    StringTable, // Unused
    GCStaticRegion,
    ThreadStaticRegion,
    TypeManagerIndirection,
    EagerCctor,
    FrozenObjectRegion,
    DehydratedData,
    ThreadStaticOffsetRegion,
    ImportAddressTables,
    ModuleInitializerList,

    ReflectionMapBlob(ReflectionMapBlob),

    Unknown(u32),
}

#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReflectionMapBlob {
    TypeMap = 1,
    ArrayMap = 2,
    PointerTypeMap = 3,
    FunctionPointerTypeMap = 4,
    // unused                                   = 5,
    InvokeMap = 6,
    VirtualInvokeMap = 7,
    CommonFixupsTable = 8,
    FieldAccessMap = 9,
    CCtorContextMap = 10,
    ByRefTypeMap = 11,
    // unused                                   = 12,
    EmbeddedMetadata = 13,
    // Unused                                   = 14,
    UnboxingAndInstantiatingStubMap = 15,
    StructMarshallingStubMap = 16,
    DelegateMarshallingStubMap = 17,
    GenericVirtualMethodTable = 18,
    InterfaceGenericVirtualMethodTable = 19,

    // Reflection template types/methods blobs:
    TypeTemplateMap = 21,
    GenericMethodsTemplateMap = 22,
    // unused                                   = 23,
    BlobIdResourceIndex = 24,
    BlobIdResourceData = 25,
    BlobIdStackTraceEmbeddedMetadata = 26,
    BlobIdStackTraceMethodRvaToTokenMapping = 27,
    BlobIdStackTraceLineNumbers = 28,
    BlobIdStackTraceDocuments = 29,

    // Native layout blobs:
    NativeLayoutInfo = 30,
    NativeReferences = 31,
    GenericsHashtable = 32,
    NativeStatics = 33,
    StaticsInfoHashtable = 34,
    GenericMethodsHashtable = 35,
    ExactMethodInstantiationsHashtable = 36,

    // Type map blobs:
    ExternalTypeMap = 40,
    ProxyTypeMap = 41,

    #[default]
    Unknown,
}

// == Implementations ==

impl<'a> ReadyToRunHeader<'a> {
    pub fn parse(view: &mut View<'a>) -> Result<Self> {
        let mut reader = BinaryReader::new(view, Endian::Little);

        let signature = Signature::parse(&mut reader)?;
        let major_version = reader.read_u16()?;
        let minor_version = reader.read_u16()?;
        let flags = reader.read_u32()?;
        let number_of_sections = reader.read_u16()?;
        let entry_size = reader.read_u8()?;
        let entry_type = reader.read_u8()?;

        // Sanity checks
        anyhow::ensure!((number_of_sections as i16) >= 0 || number_of_sections < 1000);

        let mut sections = vec![];
        for _ in 0..number_of_sections {
            sections.push(ReadyToRunSection::parse(view)?);
        }

        Ok(Self {
            signature,
            major_version,
            minor_version,
            flags,
            number_of_sections,
            entry_size,
            entry_type,
            sections,
        })
    }

    pub fn section(&self, section_type: ReadyToRunSectionType) -> Option<ReadyToRunSection<'a>> {
        self.sections
            .iter()
            .find(|sect| sect.section_type == section_type)
            .copied()
    }

    pub fn blob(&self, blob_type: ReflectionMapBlob) -> Option<ReadyToRunSection<'a>> {
        self.section(ReadyToRunSectionType::ReflectionMapBlob(blob_type))
    }

    pub fn blob_hashtable(&self, blob_type: ReflectionMapBlob) -> Option<NativeHashtable<'a>> {
        let blob = self.blob(blob_type)?;
        let reader = NativeReader::new(blob.start.bytes().ok()?).ok()?;
        let parser = NativeParser::new(reader, 0);

        Some(NativeHashtable::new(parser).ok()?)
    }

    pub fn metadata(&self) -> Option<MetadataReader<'a>> {
        let blob = self.blob(ReflectionMapBlob::EmbeddedMetadata)?;
        let reader = MetadataReader::new(blob.start.bytes().ok()?).ok()?;

        Some(reader)
    }

    pub fn common_fixups_table(&self) -> Option<ExternalReferencesTable<'a>> {
        self.blob(ReflectionMapBlob::CommonFixupsTable)
            .map(|sect| ExternalReferencesTable::new(sect.start, sect.end.va() - sect.start.va()))
    }
}

impl<'a> ReadyToRunSection<'a> {
    fn parse(view: &mut View<'a>) -> Result<Self> {
        let sect_view = *view;

        let mut reader = BinaryReader::new(view, Endian::Little);

        let section_type = reader.read_u32().map(ReadyToRunSectionType::from_u32)?;
        let flags = reader.read_u32()?;
        let start = reader.read_u64()?;
        let end = reader.read_u64()?;

        Ok(Self {
            view: sect_view,

            section_type,
            flags,
            start: View::new(view.pe, start),
            end: View::new(view.pe, end),
        })
    }
}

impl ReadyToRunSectionType {
    fn from_u32(num: u32) -> Self {
        match num {
            //
            // CoreCLR ReadyToRun sections
            //
            100 => Self::CompilerIdentifier,
            101 => Self::ImportSections,
            102 => Self::RuntimeFunctions,
            103 => Self::MethodDefEntryPoints,
            104 => Self::ExceptionInfo,
            105 => Self::DebugInfo,
            106 => Self::DelayLoadMethodCallThunks,
            // 107 is deprecated - it was used by an older format of AvailableTypes
            108 => Self::AvailableTypes,
            109 => Self::InstanceMethodEntryPoints,
            110 => Self::InliningInfo,
            111 => Self::ProfileDataInfo,
            112 => Self::ManifestMetadata,
            113 => Self::AttributePresence,
            114 => Self::InliningInfo2,
            115 => Self::ComponentAssemblies,
            116 => Self::OwnerCompositeExecutable,
            117 => Self::PgoInstrumentationData,
            118 => Self::ManifestAssemblyMvids,
            119 => Self::CrossModuleInlineInfo,
            120 => Self::HotColdMap,
            121 => Self::MethodIsGenericMap,
            122 => Self::EnclosingTypeMap,
            123 => Self::TypeGenericInfoMap,

            200 => Self::StringTable,
            201 => Self::GCStaticRegion,
            202 => Self::ThreadStaticRegion,
            // Unused = 203,
            204 => Self::TypeManagerIndirection,
            205 => Self::EagerCctor,
            206 => Self::FrozenObjectRegion,
            207 => Self::DehydratedData,
            208 => Self::ThreadStaticOffsetRegion,
            // 209 is unused - it was used by ThreadStaticGCDescRegion
            // 210 is unused - it was used by ThreadStaticIndex
            // 211 is unused - it was used by LoopHijackFlag
            212 => Self::ImportAddressTables,
            213 => Self::ModuleInitializerList,

            // Sections 300 - 399 are reserved for RhFindBlob backwards compatibility
            num if (300..=399).contains(&num) => {
                Self::ReflectionMapBlob(ReflectionMapBlob::from(num - 300))
            }

            num => Self::Unknown(num),
        }
    }
}

// == Misc ==

#[derive(Clone, Copy)]
pub struct Signature;

impl Signature {
    const SIGNATURE: u32 = 0x00525452; // "RTR\0"

    fn parse(reader: &mut BinaryReader) -> Result<Self> {
        let signature = reader.read_u32()?;

        Ok(Self::try_from(signature)?)
    }

    fn as_bytes(self) -> [u8; 4] {
        Self::SIGNATURE.to_le_bytes()
    }

    fn as_u32(self) -> u32 {
        Self::SIGNATURE
    }
}

impl TryFrom<u32> for Signature {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        (value == Self::SIGNATURE)
            .then_some(Self)
            .ok_or_else(|| anyhow!("invalid ReadyToRunHeader signature"))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"RTR\\0\"")
    }
}
