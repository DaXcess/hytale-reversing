use crate::{
    embedded_meta::{
        MetadataReader, TypeDefinition,
        handles::{Handle, NamespaceDefinitionHandle},
    },
    error::Result,
};

use super::handles::HandleType;

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
