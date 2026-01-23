#![allow(unused)] // Shush

mod binary;
mod embedded_meta;
mod error;
mod ida;
mod native_format;

use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Parser;
use pelite::pe64::PeFile;

use crate::{
    binary::{NativeAotBinary, headers::rtr::ReflectionMapBlob},
    embedded_meta::handles::{BaseHandle, HandleType, MethodHandle, TypeDefinitionHandle},
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
        Command::CreateMetadataTree => create_metadata_tree(binary),
        Command::DumpIDA => dump_ida(binary, &args.file),
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

fn create_metadata_tree(pe: NativeAotBinary<'_>) -> Result<()> {
    let Some(metadata) = pe.rtr_header().metadata() else {
        eprintln!("Image is missing a metadata section");
        return Ok(());
    };

    // metadata.header().scope_definitions()

    Ok(())
}

fn dump_ida(pe: NativeAotBinary<'_>, file: &Path) -> Result<()> {
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

                    name = Some(format!("{}_vtbl", type_def.get_full_name()?));
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

                name = Some(type_def.get_full_name()?);
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
