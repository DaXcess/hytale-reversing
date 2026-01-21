pub mod headers {
    pub mod mt;
    pub mod rtr;
}

use std::{
    collections::{HashMap, hash_map::Entry},
    rc::Rc,
};

use anyhow::{Result, bail};
use binary_rw::{BinaryReader, Endian, SeekStream};
use pelite::pe64::{Pe, PeFile, PeObject};

use crate::{
    binary::headers::{
        mt::{ElementType, MethodTable},
        rtr::ReadyToRunHeader,
    },
    native_format::View,
};

pub struct NativeAotBinary<'a> {
    pe: PeFile<'a>,

    rtr: ReadyToRunHeader<'a>,
}

// Initialization
impl<'a> NativeAotBinary<'a> {
    const CANDIDATE_DATA_SECTIONS: &'static [&'static str] = &[".rdata", ".pdata", ".data"];

    // Loads the NativeAOT binary given a known RTR header address
    pub fn from_pe(pe: PeFile<'a>, rtr_address: u64) -> Result<Self> {
        let mut view = View::new(pe, rtr_address);
        let rtr = ReadyToRunHeader::parse(&mut view)?;

        Ok(Self { pe, rtr })
    }

    // Loads the NativeAOT binary by scanning for an RTR header
    pub fn load_pe(pe: PeFile<'a>) -> Result<Self> {
        for sect_name in Self::CANDIDATE_DATA_SECTIONS {
            let Some(sect) = pe.section_headers().by_name(sect_name) else {
                continue;
            };

            for offset in sect.file_range().step_by(8) {
                let offset = offset as usize;
                let signature =
                    u32::from_le_bytes(pe.image()[offset..offset + 4].try_into().unwrap());

                if headers::rtr::Signature::try_from(signature).is_ok() {
                    let Ok(va) = pe
                        .file_offset_to_rva(offset)
                        .and_then(|rva| pe.rva_to_va(rva))
                    else {
                        continue;
                    };

                    let mut view = View::new(pe, va);
                    if let Ok(rtr) = ReadyToRunHeader::parse(&mut view) {
                        return Ok(Self { pe, rtr });
                    }
                }
            }
        }

        bail!("Unable to locate ReadyToRun header");
    }
}

// RTR stuff
impl<'a> NativeAotBinary<'a> {
    pub fn rtr_header(&self) -> &ReadyToRunHeader<'a> {
        &self.rtr
    }
}

/// Scanning implementation
impl<'a> NativeAotBinary<'a> {
    pub fn scan_method_tables(&self) -> Result<Vec<MethodTable<'a>>> {
        let mut tables = HashMap::new();

        // Step 1.
        // Find System.Object MethodTable
        let object_table = self.find_object_mt()?;
        tables.insert(object_table.view.va(), object_table);

        let mut min = u32::MAX;
        let mut max = u32::MIN;

        for sect_name in Self::CANDIDATE_DATA_SECTIONS {
            let sect = self
                .pe
                .section_headers()
                .by_name(sect_name)
                .ok_or(pelite::Error::Bounds)?;

            if sect.VirtualAddress < min {
                min = sect.VirtualAddress;
            }

            if sect.VirtualAddress + sect.VirtualSize > max {
                max = sect.VirtualAddress + sect.VirtualSize;
            }
        }

        // Store all addresses, we'll need to crawl them all
        let mut unmatched = (min..max).step_by(8).collect::<Vec<_>>();

        loop {
            let agenda = unmatched.clone();

            // We'll be refilling unmatched back up with unknown addresses
            unmatched.clear();

            for &ptr in &agenda {
                let Ok(va) = self.pe.rva_to_va(ptr) else {
                    continue;
                };

                let mut view = View::new(self.pe, va);
                let mut reader = BinaryReader::new(&mut view, Endian::Little);

                // Our goal is that `view` points to a MethodTable we already know
                reader.seek(0x8)?; // baseType is located at +0x8
                let Ok(base_type_va) = reader.read_u64() else {
                    continue;
                };
                reader.seek(0)?;

                let Ok(rva) = self.pe.va_to_rva(base_type_va) else {
                    continue;
                };

                if rva < min || rva >= max {
                    continue;
                }

                // Check if this is a known method table
                let Some(related_type) = tables.get(&base_type_va).cloned() else {
                    unmatched.push(ptr);
                    continue;
                };

                // Create (or update) MethodTable
                let mut entry = match tables.entry(va) {
                    Entry::Occupied(entry) => entry,
                    Entry::Vacant(entry) => {
                        let Ok(mt) = MethodTable::parse(&mut view) else {
                            continue;
                        };

                        entry.insert_entry(mt)
                    }
                };
                let mt = entry.get_mut();
                mt.related_type = Some(Rc::new(related_type));

                let iface_vas = mt.iface_addresses.clone();
                let mut interfaces = Vec::new();

                for &va in iface_vas.iter() {
                    if va == 0 {
                        continue;
                    }

                    let mut view = View::new(self.pe, va);
                    let interface = match tables.entry(va) {
                        Entry::Occupied(entry) => entry.get().clone(),
                        Entry::Vacant(entry) => {
                            let Ok(interface) = MethodTable::parse(&mut view) else {
                                continue;
                            };

                            entry.insert(interface).clone()
                        }
                    };

                    interfaces.push(interface);
                }

                if let Some(mt) = tables.get_mut(&base_type_va) {
                    mt.interfaces.borrow_mut().extend(interfaces);
                }
            }

            if unmatched.len() >= agenda.len() {
                break;
            }
        }

        return Ok(tables.into_values().collect());
    }

    pub fn find_object_mt(&self) -> Result<MethodTable<'a>> {
        let scan_section = |name: &str| -> Result<Option<MethodTable<'a>>> {
            let section = self
                .pe
                .section_headers()
                .by_name(name)
                .ok_or(pelite::Error::Bounds)?;

            'out: for offset in section.file_range().step_by(8) {
                let offset = offset as usize;
                let va =
                    u64::from_le_bytes(self.pe.image()[offset..offset + 8].try_into().unwrap());
                let mut view = View::new(self.pe, va);

                let Ok(mt) = MethodTable::parse(&mut view) else {
                    continue;
                };

                if mt.element_type != ElementType::Class {
                    continue;
                }

                if mt.base_size != 0x18 {
                    continue;
                }

                if mt.related_type_address != 0 {
                    continue;
                }

                if mt.vtable_addresses.len() != 3 {
                    continue;
                }

                if !mt.iface_addresses.is_empty() {
                    continue;
                }

                for &va in mt.vtable_addresses.iter() {
                    let Ok(rva) = self.pe.va_to_rva(va) else {
                        continue 'out;
                    };
                    if self
                        .pe
                        .section_headers()
                        .by_rva(rva)
                        .and_then(|s| s.name().ok())
                        != Some(".text")
                    {
                        continue 'out;
                    }
                }

                return Ok(Some(mt));
            }

            Ok(None)
        };

        for sect_name in Self::CANDIDATE_DATA_SECTIONS {
            if let Some(table) = scan_section(sect_name)? {
                return Ok(table);
            }
        }

        bail!("MethodTable not found or present in binary");
    }
}
