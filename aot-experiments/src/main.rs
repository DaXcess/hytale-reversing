#![allow(unused)] // Shush

mod binary;
mod embedded_meta;
mod error;
mod ida;
mod native_format;

use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use pelite::pe64::{Pe, PeFile};

use crate::{
    binary::{NativeAotBinary, headers::rtr::ReflectionMapBlob},
    embedded_meta::{
        MetadataReader, Method, TypeDefinition, TypeInstantiationSignature, TypeSpecification,
        flags::MethodMemberAccess,
        handles::{
            BaseHandle, ByReferenceSignatureHandle, HandleType, MethodHandle,
            MethodTypeVariableSignatureHandle, TypeDefinitionHandle,
            TypeInstantiationSignatureHandle, TypeSpecificationHandle, TypeVariableSignatureHandle,
        },
    },
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to Hytale executable
    file: PathBuf,

    /// Command
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// List all assemblies compiled into this NativeAOT binary
    GetAssemblies,

    /// List all types and metadata surrounding it
    GetTypes,

    /// TODO
    CreateMetadataTree,

    DumpIDA,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse input file
    let data = std::fs::read(&args.file)?;
    let pe = PeFile::from_bytes(&data)?;
    let binary = NativeAotBinary::load_pe(pe)?;

    if let Err(why) = match args.command {
        Command::GetAssemblies => get_assemblies(binary),
        Command::GetTypes => get_types(binary),
        Command::CreateMetadataTree => create_metadata_tree(binary),
        Command::DumpIDA => dump_ida(binary),
    } {
        eprintln!("Error: {why}");
    }

    Ok(())
}

fn get_assemblies(pe: NativeAotBinary<'_>) -> Result<()> {
    let Some(metadata) = pe.rtr_header().metadata() else {
        eprintln!("Image is missing a metadata section");
        return Ok(());
    };

    for def in metadata
        .header()
        .scope_definitions()
        .iter()?
        .flatten()
        .flat_map(|hdl| hdl.to_data(metadata))
    {
        let Ok(name) = def.name.to_data(metadata) else {
            continue;
        };

        println!(
            "{}, Version={}.{}.{}.{}",
            name.value, def.major_version, def.minor_version, def.build_number, def.revision_number
        );
    }

    Ok(())
}

fn get_types(pe: NativeAotBinary<'_>) -> Result<()> {
    struct MethodDef<'a> {
        method: Method<'a>,
        parent: TypeDefinition<'a>,
    }

    let Some(metadata) = pe.rtr_header().metadata() else {
        eprintln!("Image is missing a metadata section");
        return Ok(());
    };

    let Some(invoke_table) = pe.rtr_header().blob_hashtable(ReflectionMapBlob::InvokeMap) else {
        eprintln!("Image is missing an invoke table");
        return Ok(());
    };

    let Some(fixups) = pe.rtr_header().common_fixups_table() else {
        eprintln!("Image is missing a common fixups table");
        return Ok(());
    };

    // Step 1.
    // Find potential method pointers
    let mut method_ptrs = HashMap::new();

    for mut parser in invoke_table.enumerate_all()? {
        let invoke_flags = parser.get_unsigned()?;
        let meta_handle = BaseHandle::from_raw(parser.get_unsigned()?);
        let _entry_type = parser.get_unsigned()?;
        let fixup_idx = parser.get_unsigned()?;

        if (invoke_flags & 32) == 0 {
            continue;
        }

        let Ok(method_handle) = meta_handle.to_handle::<MethodHandle>() else {
            continue;
        };

        let Some(va) = fixups.get_va_from_index(fixup_idx) else {
            continue;
        };

        method_ptrs.insert(method_handle, va);
    }

    for def in metadata
        .header()
        .scope_definitions()
        .iter()?
        .flatten()
        .flat_map(|hdl| hdl.to_data(metadata))
    {
        let types = def.get_all_types()?;

        for typ in types {
            let type_name = typ.get_full_name_with_generics()?;

            if !typ.base_type.is_nil() {
                let base_name =
                    get_type_name_from_handle(typ.base_type, ParentInfo::typ(&typ), metadata)?;

                println!("{type_name} ({base_name})");
            } else {
                println!("{type_name}");
            }

            // Print fields
            if matches!(typ.fields.count(), Ok(n) if n > 0) {
                let Ok(iter) = typ.fields.iter() else {
                    continue;
                };

                println!(" - Fields:");
                for field in iter.flatten().flat_map(|hdl| hdl.to_data(metadata)) {
                    let name = field.name.to_data(metadata)?.value;
                    let signature = field.signature.to_data(metadata)?;

                    let type_name = get_type_name_from_handle(
                        signature.type_handle,
                        ParentInfo::typ(&typ),
                        metadata,
                    )
                    .unwrap_or_else(|_| "Unknown TypeDefinition".to_string());

                    println!("  * {name} ({type_name})");
                }
            }

            // Print methods
            if matches!(typ.methods.count(), Ok(n) if n > 0) {
                let Ok(iter) = typ.methods.iter() else {
                    continue;
                };

                println!(" - Methods:");
                for method in iter.flatten().flat_map(|hdl| hdl.to_data(metadata)) {
                    let name = method.name.to_data(metadata)?.value;
                    let flags = method.flags;

                    let Ok(signature) = method.signature.to_data(metadata) else {
                        continue;
                    };

                    let generics = method.generic_parameters.iter().ok().and_then(|mut iter| {
                        let names = iter
                            .try_fold(Vec::new(), |mut acc, hdl| {
                                let hdl = hdl?;
                                let param = hdl.to_data(metadata)?;
                                let name = param.name.to_data(metadata)?;
                                acc.push(name.value);

                                Ok::<_, anyhow::Error>(acc)
                            })
                            .ok()?;

                        if names.is_empty() {
                            return None;
                        }

                        Some(format!("<{}>", names.join(", ")))
                    });

                    let return_type = match signature.return_type {
                        t if t.is_nil() => "void".to_string(),
                        t => {
                            get_type_name_from_handle(t, ParentInfo::both(&method, &typ), metadata)?
                        }
                    };

                    print!("  * ");

                    let access = match flags.member_access() {
                        MethodMemberAccess::Assembly => "internal ",
                        MethodMemberAccess::FamAndAssem => "private protected ",
                        MethodMemberAccess::FamOrAssem => "internal protected ",
                        MethodMemberAccess::Family => "protected ",
                        MethodMemberAccess::Private => "private ",
                        MethodMemberAccess::PrivateScope => "",
                        MethodMemberAccess::Public => "public ",
                    };

                    print!(
                        "{access}{return_type} {name}{}(",
                        generics.as_deref().unwrap_or("")
                    );

                    if let Ok(iter) = signature.parameters.iter() {
                        let params = iter
                            .flatten()
                            .map(|param| {
                                // Turn this BaseHandle into a readable string
                                get_type_name_from_handle(
                                    param,
                                    ParentInfo::both(&method, &typ),
                                    metadata,
                                )
                                .unwrap_or_else(|_| "<unknown>".to_string())
                            })
                            .collect::<Vec<_>>()
                            .join(", ");

                        print!("{params}");
                    }

                    print!(") //");

                    if let Some(&va) = method_ptrs.get(&method.handle()) {
                        if let Ok(rva) = pe.pe().va_to_rva(va) {
                            print!(" RVA: {rva:#x}");
                        } else {
                            print!(" VA: {va:#x}");
                        }
                    }

                    print!(" Conv: {:?}", signature.calling_convention);
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn create_metadata_tree(pe: NativeAotBinary<'_>) -> Result<()> {
    let Some(_metadata) = pe.rtr_header().metadata() else {
        eprintln!("Image is missing a metadata section");
        return Ok(());
    };

    // metadata.header().scope_definitions()

    Ok(())
}

fn dump_ida(pe: NativeAotBinary<'_>) -> Result<()> {
    // -- Check if this is a Hytale binary
    const REQUIRED_ASSEMBLIES: &[&str] = &[
        "Hytale.Nat",
        "Hytale.Protocol",
        "Hytale.Protocol.Runtime",
        "HytaleClient",
        "Noesis.GUI",
        "HytaleClient.Interop",
    ];

    let Some(metadata) = pe.rtr_header().metadata() else {
        eprintln!("Image is missing a metadata section");
        return Ok(());
    };

    let Ok(scopes) = metadata.header().scope_definitions().iter().map(|iter| {
        iter.flatten()
            .flat_map(|hdl| hdl.to_data(metadata))
            .flat_map(|scope| scope.name.to_data(metadata))
            .map(|name| name.value)
            .collect::<Vec<_>>()
    }) else {
        eprintln!("Unable to enumerate scope definitions");
        return Ok(());
    };

    for assembly in REQUIRED_ASSEMBLIES {
        if !scopes.iter().any(|scope| scope == assembly) {
            eprintln!(
                "Assembly '{assembly}' is missing from target binary. Target binary might not be the Hytale Client."
            );
            return Ok(());
        }
    }

    // -- At this point we can be certain that the target binary is the Hytale client

    // Grab a few references we're going to need later
    let Some(fixups) = pe.rtr_header().common_fixups_table() else {
        eprintln!("Missing CommonFixupsTable");
        return Ok(());
    };
    let Some(type_map) = pe.rtr_header().blob_hashtable(ReflectionMapBlob::TypeMap) else {
        eprintln!("Missing TypeMap");
        return Ok(());
    };
    let Some(invoke_map) = pe.rtr_header().blob_hashtable(ReflectionMapBlob::InvokeMap) else {
        eprintln!("Missing InvokeMap");
        return Ok(());
    };

    // Get a list of method tables
    let method_tables = pe.scan_method_tables()?;

    let mut definition = ida::HytaleDefinition::default();

    // Resolve method table names and define them
    for mt in &method_tables {
        let name = if let Ok(iter) = type_map.lookup(mt.hashcode as i32) {
            let mut name = None;

            for mut parser in iter {
                let index = parser.get_unsigned()?;
                let Some(va) = fixups.get_va_from_index(index) else {
                    continue;
                };

                if va == mt.view.va() {
                    let handle = BaseHandle::from_raw(parser.get_unsigned()?);
                    let Ok(type_def) = handle
                        .to_handle::<TypeDefinitionHandle>()
                        .and_then(|hdl| hdl.to_data(metadata))
                    else {
                        continue;
                    };

                    name = Some(format!("{}_vtbl", type_def.get_full_name_with_generics()?));
                    break;
                }
            }

            name
        } else {
            None
        };

        let name = name.unwrap_or_else(|| format!("{:?}_{:x}_vtbl", mt.element_type, mt.view.va()));

        definition.create_mt_struct(
            mt.view.va(),
            name,
            mt.vtable_addresses.len() as _,
            mt.iface_addresses.len() as _,
        );
    }

    // Resolve function names + pointers and define them
    for mut parser in invoke_map.enumerate_all()? {
        let flags = parser.get_unsigned()?;
        let handle =
            BaseHandle::from_raw(((HandleType::Method as u32) << 25) | parser.get_unsigned()?);
        let method_handle = handle.to_handle::<MethodHandle>()?;

        let Ok(method_def) = method_handle.to_data(metadata) else {
            continue;
        };

        let Some(entry_type_mt) = fixups
            .get_va_from_index(parser.get_unsigned()?)
            .and_then(|mt_va| method_tables.iter().find(|mt| mt.view.va() == mt_va))
        else {
            continue;
        };

        // Skip if no entrypoint
        if flags & 32 == 0 {
            continue;
        }

        // Find type name
        let Ok(iter) = type_map.lookup(entry_type_mt.hashcode as i32) else {
            continue;
        };

        let mut name = None;
        for mut parser in iter {
            let index = parser.get_unsigned()?;
            let Some(va) = fixups.get_va_from_index(index) else {
                continue;
            };

            if va == entry_type_mt.view.va() {
                let handle = BaseHandle::from_raw(parser.get_unsigned()?);
                let Ok(type_def) = handle
                    .to_handle::<TypeDefinitionHandle>()
                    .and_then(|hdl| hdl.to_data(metadata))
                else {
                    continue;
                };

                name = Some(type_def.get_full_name_with_generics()?);
                break;
            }
        }

        let Some(type_name) = name else {
            continue;
        };

        let Some(entrypoint_va) = fixups.get_va_from_index(parser.get_unsigned()?) else {
            continue;
        };

        let name = method_def.name.to_data(metadata)?.value;

        definition.create_function(entrypoint_va, format!("{type_name}.{name}"));
    }

    // Write definition to disk
    std::fs::write("hytale_def.json", serde_json::to_string(&definition)?)?;

    eprintln!("Definition written to 'hytale_def.json'");

    Ok(())
}

#[derive(Clone, Copy)]
struct ParentInfo<'a> {
    method: Option<&'a Method<'a>>,
    typ: Option<&'a TypeDefinition<'a>>,
}

impl<'a> ParentInfo<'a> {
    fn none() -> Self {
        Self {
            method: None,
            typ: None,
        }
    }

    fn typ(typ: &'a TypeDefinition<'a>) -> Self {
        Self {
            method: None,
            typ: Some(typ),
        }
    }

    fn both(method: &'a Method<'a>, typ: &'a TypeDefinition<'a>) -> Self {
        Self {
            method: Some(method),
            typ: Some(typ),
        }
    }

    fn has_none(&self) -> bool {
        self.method.is_none() && self.typ.is_none()
    }

    fn has_method(&self) -> bool {
        self.method.is_some()
    }

    fn has_type(&self) -> bool {
        self.typ.is_some()
    }

    fn get_method_generic(&self, reader: MetadataReader<'a>, index: usize) -> Option<String> {
        Some(
            self.method?
                .generic_parameters
                .iter()
                .ok()?
                .collect::<Vec<_>>()
                .get(index)?
                .as_ref()
                .ok()?
                .to_data(reader)
                .ok()?
                .name
                .to_data(reader)
                .ok()?
                .value,
        )
    }

    fn get_type_generic(&self, reader: MetadataReader<'a>, index: usize) -> Option<String> {
        Some(
            self.typ?
                .generic_parameters
                .iter()
                .ok()?
                .collect::<Vec<_>>()
                .get(index)?
                .as_ref()
                .ok()?
                .to_data(reader)
                .ok()?
                .name
                .to_data(reader)
                .ok()?
                .value,
        )
    }
}

fn get_type_name_from_handle(
    handle: BaseHandle,
    parent: ParentInfo,
    reader: MetadataReader<'_>,
) -> Result<String> {
    let value = match handle.handle_type() {
        Some(HandleType::TypeDefinition) => {
            let typedef = handle
                .to_handle::<TypeDefinitionHandle>()?
                .to_data(reader)?;

            format!(
                "{}",
                if parent.has_none() {
                    typedef.get_full_name_with_generics()
                } else {
                    typedef.get_full_name()
                }?
            )
        }
        Some(HandleType::TypeSpecification) => {
            let typespec = handle
                .to_handle::<TypeSpecificationHandle>()?
                .to_data(reader)?;

            get_type_name_from_handle(typespec.signature, parent, reader)?
        }
        // Generic type
        Some(HandleType::TypeInstantiationSignature) => {
            let typeinst = handle
                .to_handle::<TypeInstantiationSignatureHandle>()?
                .to_data(reader)?;

            let generic_type_name =
                get_type_name_from_handle(typeinst.generic_type, parent, reader)?;
            let mut generic_type_args = vec![];

            for typ in typeinst.generic_args.iter()?.flatten() {
                generic_type_args.push(get_type_name_from_handle(typ, parent, reader)?);
            }

            format!("{generic_type_name}<{}>", generic_type_args.join(", "))
        }
        // ref Type
        Some(HandleType::ByReferenceSignature) => {
            let refsig = handle
                .to_handle::<ByReferenceSignatureHandle>()?
                .to_data(reader)?;

            let name = get_type_name_from_handle(refsig.type_handle, parent, reader)?;

            format!("ref {name}")
        }
        Some(HandleType::MethodTypeVariableSignature) if parent.has_method() => {
            let mtvarsig = handle
                .to_handle::<MethodTypeVariableSignatureHandle>()?
                .to_data(reader)?;
            let index = mtvarsig.number as usize;

            format!(
                "{}",
                parent
                    .get_method_generic(reader, index)
                    .as_deref()
                    .unwrap_or("Unknown")
            )
        }
        Some(HandleType::TypeVariableSignature) if parent.has_type() => {
            let mtvarsig = handle
                .to_handle::<TypeVariableSignatureHandle>()?
                .to_data(reader)?;
            let index = mtvarsig.number as usize;

            format!(
                "{}",
                parent
                    .get_type_generic(reader, index)
                    .as_deref()
                    .unwrap_or("Unknown")
            )
        }
        _ => format!("{:?}", handle.handle_type().unwrap_or(HandleType::Null)),
    };

    Ok(value)
}
