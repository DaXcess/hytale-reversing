use crate::{
    embedded_meta::{
        MetadataReader, NamespaceDefinition, ScopeDefinition, TypeDefinition,
        handles::{Handle, NamespaceDefinitionHandle},
    },
    error::Result,
};

use super::handles::HandleType;

// Helper functions for ScopeDefinitions
impl<'a> ScopeDefinition<'a> {
    pub fn get_all_types(&self) -> Result<Vec<TypeDefinition<'a>>> {
        let mut types = vec![];
        let mut stack = vec![];

        stack.push(self.root_namespace_definition);

        while let Some(ns_handle) = stack.pop() {
            let Ok(ns) = ns_handle.to_data(self.reader) else {
                continue;
            };

            let Ok(type_iter) = ns.type_definitions.iter() else {
                continue;
            };

            let Ok(ns_iter) = ns.namespace_definitions.iter() else {
                continue;
            };

            types.extend(type_iter.flatten().flat_map(|hdl| hdl.to_data(self.reader)));
            stack.extend(ns_iter.flatten());
        }

        Ok(types)
    }
}

// Helper functions for NamespaceDefinitions
impl<'a> NamespaceDefinition<'a> {
    pub fn find_type(&self, name: &str) -> Option<TypeDefinition<'a>> {
        let mut segments = name.split(".").peekable();
        let mut current_ns = self.handle;

        while segments.peek().is_some() && segments.clone().count() > 1 {
            let segment = segments.next().unwrap();
            let ns = current_ns.to_data(self.reader).ok()?;

            let mut found = None;

            for child_handle in ns.namespace_definitions.iter().ok()?.flatten() {
                let child_ns = child_handle.to_data(self.reader).ok()?;

                if child_ns.name.is_nil() {
                    continue;
                }

                let child_name = child_ns.name.to_data(self.reader).ok()?.value;

                if child_name == segment {
                    found = Some(child_handle);
                    break;
                }
            }

            current_ns = found?;
        }

        let type_name = segments.next().unwrap();
        let ns = current_ns.to_data(self.reader).ok()?;

        for ty in ns
            .type_definitions
            .iter()
            .ok()?
            .flatten()
            .flat_map(|hdl| hdl.to_data(self.reader))
        {
            let ty_name = ty.name.to_data(self.reader).ok()?;

            if ty_name.value == type_name {
                return Some(ty);
            }
        }

        None
    }
}

// Helper functions for TypeDefinitions
impl<'a> TypeDefinition<'a> {
    pub fn get_full_name(&self) -> Result<String> {
        let type_name = self.name.to_data(self.reader)?.value;

        // Enumerate over namespaces
        let mut ns_handle = self.namespace_definition.to_base();
        let mut ns_names = Vec::new();

        loop {
            if ns_handle.handle_type() != Some(HandleType::NamespaceDefinition) {
                break;
            }

            let namespace = ns_handle
                .to_handle::<NamespaceDefinitionHandle>()?
                .to_data(self.reader)?;

            if namespace.name.is_nil() {
                break;
            }

            ns_names.push(namespace.name.to_data(self.reader)?.value);
            ns_handle = namespace.parent_scope_or_namespace;
        }

        Ok(format!(
            "{}.{type_name}",
            ns_names.into_iter().rev().collect::<Vec<_>>().join(".")
        ))
    }
}
