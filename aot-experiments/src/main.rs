#![allow(unused)] // Shush

mod binary;
mod embedded_meta;
mod error;
mod native_format;

use std::{collections::HashMap, ops::Deref};

use anyhow::Result;
use idalib::ffi::name::{SN_FORCE, SN_NOCHECK};
use pelite::pe64::{Pe, PeFile, PeObject};

use crate::{
    binary::{NativeAotBinary, headers::rtr::ReflectionMapBlob},
    embedded_meta::{
        MetadataReader, Method, NamespaceDefinition, TypeDefinition,
        handles::{
            BaseHandle, FieldHandle, Handle, HandleType, MethodHandle, NamespaceDefinitionHandle,
            TypeDefinitionHandle,
        },
    },
    error::AotError,
    native_format::{hashtable::NativeHashtable, parser::NativeParser, reader::NativeReader},
};

fn main() -> Result<()> {
    let idb = idalib::IDB::open_with("/home/daxcess/Share/HytaleClient.exe", false, true)?;

    fn get_type_methods<'a>(
        reader: MetadataReader<'a>,
        typ: TypeDefinition<'a>,
    ) -> Result<Vec<MethodDef<'a>>> {
        let mut methods = typ
            .methods
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
            .map(|method| MethodDef {
                method,
                parent: typ.handle(),
            })
            .collect::<Vec<_>>();

        for typ in typ
            .nested_types
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_type_methods(reader, typ)?);
        }

        Ok(methods)
    }

    fn get_namespace_methods<'a>(
        reader: MetadataReader<'a>,
        namespace: NamespaceDefinition<'a>,
    ) -> Result<Vec<MethodDef<'a>>> {
        let mut methods = Vec::new();

        for typ in namespace
            .type_definitions
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_type_methods(reader, typ)?);
        }

        for ns in namespace
            .namespace_definitions
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_namespace_methods(reader, ns)?);
        }

        Ok(methods)
    }

    let data = std::fs::read("/home/daxcess/Share/HytaleClient.exe")?;
    let pe = PeFile::from_bytes(&data)?;
    let binary = NativeAotBinary::load_pe(pe)?;

    let method_tables = binary.scan_method_tables()?;
    let fixup_table = binary
        .rtr_header()
        .common_fixups_table()
        .ok_or(AotError::BadImage)?;
    let type_table = binary
        .rtr_header()
        .blob_hashtable(ReflectionMapBlob::TypeMap)
        .ok_or(AotError::BadImage)?;
    let invoke_table = binary
        .rtr_header()
        .blob_hashtable(ReflectionMapBlob::InvokeMap)
        .ok_or(AotError::BadImage)?;
    let field_table = binary
        .rtr_header()
        .blob_hashtable(ReflectionMapBlob::FieldAccessMap)
        .ok_or(AotError::BadImage)?;
    let metadata = binary.rtr_header().metadata().ok_or(AotError::BadImage)?;

    // Step 1: Locate *all* methods, store their info by their handle
    let mut method_map = HashMap::new();

    for scope in metadata
        .header()
        .scope_definitions()
        .iter()?
        .flatten()
        .flat_map(|hdl| hdl.to_data(metadata))
    {
        if scope.root_namespace_definition.is_nil() {
            continue;
        }

        let ns_root = scope.root_namespace_definition.to_data(metadata)?;
        let methods = get_namespace_methods(metadata, ns_root)?;

        for method in methods {
            method_map.insert(method.handle(), method);
        }
    }

    let get_type_full_name = |typ: &TypeDefinition<'_>| -> Result<String> {
        let type_name = typ.name.to_data(metadata)?.value;

        // Enumerate over namespaces
        let mut ns_handle = typ.namespace_definition.to_base();
        let mut ns_names = Vec::new();

        loop {
            if ns_handle.handle_type() != Some(HandleType::NamespaceDefinition) {
                break;
            }

            let namespace = ns_handle
                .to_handle::<NamespaceDefinitionHandle>()?
                .to_data(metadata)?;

            if namespace.name.is_nil() {
                break;
            }

            ns_names.push(namespace.name.to_data(metadata)?.value);
            ns_handle = namespace.parent_scope_or_namespace;
        }

        Ok(format!(
            "{}.{type_name}",
            ns_names.into_iter().rev().collect::<Vec<_>>().join(".")
        ))
    };

    fn get_method_full_name<'a>(
        reader: MetadataReader<'a>,
        method: &MethodDef<'a>,
    ) -> Result<String> {
        // Method name
        let method_name = method.name.to_data(reader)?.value;

        // Type name
        let typ = method.parent.to_data(reader)?;
        let type_name = typ.name.to_data(reader)?.value;

        // Enumerate over namespaces
        let mut ns_handle = typ.namespace_definition.to_base();
        let mut ns_names = Vec::new();

        loop {
            if ns_handle.handle_type() != Some(HandleType::NamespaceDefinition) {
                break;
            }

            let namespace = ns_handle
                .to_handle::<NamespaceDefinitionHandle>()?
                .to_data(reader)?;

            if namespace.name.is_nil() {
                break;
            }

            ns_names.push(namespace.name.to_data(reader)?.value);
            ns_handle = namespace.parent_scope_or_namespace;
        }

        Ok(format!(
            "{}.{type_name}.{method_name}",
            ns_names.into_iter().rev().collect::<Vec<_>>().join(".")
        ))
    }

    if false {
        for table in method_tables {
            for mut parser in type_table.lookup(table.hashcode as i32)? {
                let index = parser.get_unsigned()?;
                let Some(va) = fixup_table.get_va_from_index(index) else {
                    continue;
                };

                if va == table.view.va() {
                    // SAFETY: An invalid BaseHandle is not UB
                    let handle = BaseHandle::from_raw(parser.get_unsigned()?);
                    let Ok(type_def) = handle
                        .to_handle::<TypeDefinitionHandle>()
                        .and_then(|hdl| hdl.to_data(metadata))
                    else {
                        continue;
                    };

                    println!(
                        "MethodTable {:?}_{:x} is a type called {}",
                        table.element_type,
                        table.view.va(),
                        get_type_full_name(&type_def)?
                    );
                    for field in type_def
                        .fields
                        .iter()?
                        .flatten()
                        .flat_map(|hdl| hdl.to_data(metadata))
                    {
                        println!("  {}", field.name.to_data(metadata).unwrap().value);
                    }
                    if type_def.fields.count()? > 0 {
                        println!();
                    }
                }
            }
        }
    }

    if false {
        for mut parser in field_table.enumerate_all()? {
            let flags = parser.get_unsigned()?;
            let declaring_type_handle = fixup_table
                .get_va_from_index(parser.get_unsigned()?)
                .ok_or(AotError::BadImage)?;
            let field_handle = BaseHandle::from_raw(parser.get_unsigned()?);

            let Ok(field_def) = field_handle
                .to_handle::<FieldHandle>()
                .and_then(|hdl| hdl.to_data(metadata))
            else {
                continue;
            };

            println!("{}", field_def.name.to_data(metadata).unwrap().value);
        }
    }

    for mut parser in invoke_table.enumerate_all()? {
        let flags = parser.get_unsigned()?;
        let handle = BaseHandle::from_raw(parser.get_unsigned()?);
        let _entry_type = parser.get_unsigned()?;
        let fixup_idx = parser.get_unsigned()?;

        if flags & 32 == 0 {
            continue;
        }

        let method_handle = handle.to_handle::<MethodHandle>()?;
        let Some(method) = method_map.get(&method_handle) else {
            let method = method_handle.to_data(metadata)?;

            println!(
                "Definition for method '{}' not found",
                method.name.to_data(metadata)?.value
            );

            continue;
        };

        let Some(va) = fixup_table.get_va_from_index(fixup_idx) else {
            continue;
        };

        let name = get_method_full_name(metadata, &method)?;

        if let Some(fun) = idb.function_at(va) {
            _ = idb.names().set_name(va, &name, SN_NOCHECK | SN_FORCE)?;
        }

        println!("{name} is located at {va:x}")
    }

    println!("{}", invoke_table.enumerate_all()?.count());

    Ok(())
}

// blob 8
fn test_relocation() -> Result<()> {
    fn va_to_fo(pe: &PeFile, va: u64) -> Option<usize> {
        for sect in pe.section_headers() {
            let start = pe.optional_header().ImageBase + sect.VirtualAddress as u64;
            let end = start + sect.VirtualSize as u64;

            if va >= start && va <= end {
                let offset = (va - start) + sect.PointerToRawData as u64;
                return Some(offset as usize);
            }
        }

        None
    }

    fn find_table_index(
        pe: &PeFile,
        table_start: u64,
        table_end: u64,
        method_ptr: u64,
    ) -> Option<u32> {
        for va in (table_start..table_end).step_by(4) {
            let Some(fo) = va_to_fo(&pe, va) else {
                continue;
            };

            let rel = i32::from_le_bytes(pe.image()[fo..fo + 4].try_into().unwrap()) as i64;
            let resolved = va as i64 + rel;

            if resolved as u64 == method_ptr {
                return Some(((va - table_start) / 4) as u32);
            }
        }

        None
    }

    let methods = std::fs::read_to_string("fns.txt")?
        .lines()
        .flat_map(|line| u64::from_str_radix(line, 16))
        .collect::<Vec<_>>();

    let file = std::fs::read("blobs/HytaleClient.exe")?;
    let pe = PeFile::from_bytes(&file)?;
    let image_base = pe.optional_header().ImageBase;

    let table_start = image_base + 0x18aac9c;
    let table_end = image_base + 0x18d85fb;

    for method in methods {
        if let Some(index) = find_table_index(&pe, table_start, table_end, method) {
            println!("0x{method:X} is at #{index}");
        }
    }

    Ok(())
}

fn test_maps() -> Result<()> {
    const SKIP: &[&str] = &["13_EmbeddedMetadata.blob"];

    // EmbeddedMetadata
    // let meta_data = std::fs::read("blobs/13_EmbeddedMetadata.blob").unwrap();
    // let meta_reader = MetadataReader::new(&meta_data)?;

    for entry in std::fs::read_dir("blobs").unwrap().flatten() {
        if !entry.file_type().unwrap().is_file() {
            continue;
        }

        let filename = entry.file_name().to_string_lossy().into_owned();

        if SKIP.iter().any(|skip| filename.eq_ignore_ascii_case(skip)) {
            continue;
        }

        println!("== {filename} == ");

        let data = std::fs::read(entry.path()).unwrap();
        let Ok(reader) = NativeReader::new(&data) else {
            println!("Failed to construct native reader");
            continue;
        };

        let parser = NativeParser::new(reader, 0);

        let Ok(table) = NativeHashtable::new(parser) else {
            println!("Failed to construct native hashtable");
            println!();
            continue;
        };

        let Ok(table_iter) = table.enumerate_all() else {
            println!("Failed to construct hashtable iterator");
            println!();
            continue;
        };

        for mut parser in table_iter {
            if parser.get_unsigned().is_err() {
                println!("Error during table iteration");
                break;
            }

            let Ok(handle) = parser.get_unsigned() else {
                println!("Error during table iteration");
                break;
            };

            let handle = BaseHandle::from_raw(handle);

            println!("{:?}", handle.handle_type().unwrap_or(HandleType::Invalid))
        }

        println!();
    }

    Ok(())
}

// 1: TypeMap
fn test_typemap() -> Result<()> {
    let data = std::fs::read("blobs/1_TypeMap.blob").unwrap();
    let reader = NativeReader::new(&data)?;
    let parser = NativeParser::new(reader, 0);
    let table = NativeHashtable::new(parser)?;

    // EmbeddedMetadata
    let meta_data = std::fs::read("blobs/13_EmbeddedMetadata.blob").unwrap();
    let meta_reader = MetadataReader::new(&meta_data)?;

    for mut parser in table.enumerate_all()? {
        let rth_index = parser.get_unsigned()?;
        let meta_handle = BaseHandle::from_raw(parser.get_unsigned()?);
        let type_handle = meta_handle.to_handle::<TypeDefinitionHandle>()?;

        let typ = type_handle.to_data(meta_reader)?;

        println!("#{rth_index} => {}", typ.name.to_data(meta_reader)?.value);
    }

    Ok(())
}

struct MethodDef<'a> {
    pub method: Method<'a>,
    pub parent: TypeDefinitionHandle,
}

impl<'a> Deref for MethodDef<'a> {
    type Target = Method<'a>;

    fn deref(&self) -> &Self::Target {
        &self.method
    }
}

// 6: InvokeMap
fn test_invokemap() -> Result<()> {
    fn get_method_full_name<'a>(
        reader: MetadataReader<'a>,
        method: &MethodDef<'a>,
    ) -> Result<String> {
        // Method name
        let method_name = method.name.to_data(reader)?.value;

        // Type name
        let typ = method.parent.to_data(reader)?;
        let type_name = typ.name.to_data(reader)?.value;

        // Enumerate over namespaces
        let mut ns_handle = typ.namespace_definition.to_base();
        let mut ns_names = Vec::new();

        loop {
            if ns_handle.handle_type() != Some(HandleType::NamespaceDefinition) {
                break;
            }

            let namespace = ns_handle
                .to_handle::<NamespaceDefinitionHandle>()?
                .to_data(reader)?;

            if namespace.name.is_nil() {
                break;
            }

            ns_names.push(namespace.name.to_data(reader)?.value);
            ns_handle = namespace.parent_scope_or_namespace;
        }

        Ok(format!(
            "{}.{type_name}.{method_name}",
            ns_names.into_iter().rev().collect::<Vec<_>>().join(".")
        ))
    }

    fn get_type_methods<'a>(
        reader: MetadataReader<'a>,
        typ: TypeDefinition<'a>,
    ) -> Result<Vec<MethodDef<'a>>> {
        let mut methods = typ
            .methods
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
            .map(|method| MethodDef {
                method,
                parent: typ.handle(),
            })
            .collect::<Vec<_>>();

        for typ in typ
            .nested_types
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_type_methods(reader, typ)?);
        }

        Ok(methods)
    }

    fn get_namespace_methods<'a>(
        reader: MetadataReader<'a>,
        namespace: NamespaceDefinition<'a>,
    ) -> Result<Vec<MethodDef<'a>>> {
        let mut methods = Vec::new();

        for typ in namespace
            .type_definitions
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_type_methods(reader, typ)?);
        }

        for ns in namespace
            .namespace_definitions
            .iter()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(reader))
        {
            methods.extend(get_namespace_methods(reader, ns)?);
        }

        Ok(methods)
    }

    let invoke_data = std::fs::read("blobs/6_InvokeMap.blob").unwrap();
    let invoke_reader = NativeReader::new(&invoke_data)?;
    let invoke_parser = NativeParser::new(invoke_reader, 0);
    let invoke_table = NativeHashtable::new(invoke_parser)?;

    // Common Fixups
    let fixup_data = std::fs::read("blobs/8_CommonFixupsTable.blob").unwrap();

    // EmbeddedMetadata
    let meta_data = std::fs::read("blobs/13_EmbeddedMetadata.blob").unwrap();
    let meta_reader = MetadataReader::new(&meta_data)?;

    // Step 1: Locate *all* methods, store their info by their handle
    let mut method_map = HashMap::new();

    for scope in meta_reader
        .header()
        .scope_definitions()
        .iter()?
        .flatten()
        .flat_map(|hdl| hdl.to_data(meta_reader))
    {
        if scope.root_namespace_definition.is_nil() {
            continue;
        }

        let ns_root = scope.root_namespace_definition.to_data(meta_reader)?;
        let methods = get_namespace_methods(meta_reader, ns_root)?;

        for method in methods {
            println!("{}", get_method_full_name(meta_reader, &method)?);
            method_map.insert(method.handle(), method);
        }
    }

    return Ok(());

    // Step 2: Iterate over the InvokeMap and find the full definition for each method
    for mut parser in invoke_table.enumerate_all()? {
        let invoke_flags = parser.get_unsigned()?;
        let meta_handle = BaseHandle::from_raw(parser.get_unsigned()?);
        let _entry_type = parser.get_unsigned()?;
        let fixup_idx = parser.get_unsigned()? as usize;

        if (invoke_flags & 32) == 0 {
            continue;
        }

        let method_handle = meta_handle.to_handle::<MethodHandle>()?;
        let Some(method) = method_map.get(&method_handle) else {
            let method = method_handle.to_data(meta_reader)?;

            println!(
                "Definition for method '{}' not found",
                method.name.to_data(meta_reader)?.value
            );

            continue;
        };

        let rel_ptr = &fixup_data[fixup_idx * 4..fixup_idx * 4 + 4];
        let rel32 = i32::from_le_bytes(rel_ptr.try_into().unwrap());

        println!(
            "#{fixup_idx} {} is located at relative offset {}",
            get_method_full_name(meta_reader, method)?,
            if rel32 < 0 {
                format!("-0x{:X} ({rel32:#X})", rel32.abs())
            } else {
                format!("0x{:X}", rel32)
            }
        );
    }

    Ok(())
}

// 13: EmbeddedMetadata
fn test_embedded_metadata() -> Result<()> {
    let data = std::fs::read("blobs/13_EmbeddedMetadata.blob").unwrap();
    let reader = MetadataReader::new(&data)?;

    for def in reader
        .header()
        .scope_definitions()
        .iter()?
        .flatten()
        .flat_map(|hdl| hdl.to_data(reader))
    {
        let root = def.root_namespace_definition.to_data(reader)?;

        let Some(typ) = root.find_type("HytaleClient.Application.Program") else {
            continue;
        };

        println!("{typ:#?}");
        println!("{}", typ.name.to_data(reader).unwrap().value);

        println!("Found type");
    }

    Ok(())
}
