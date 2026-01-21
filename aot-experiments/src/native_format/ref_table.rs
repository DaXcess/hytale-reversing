use std::io::Read;

use pelite::pe64::Va;

use crate::native_format::View;

#[derive(Debug, Clone, Copy)]
pub struct ExternalReferencesTable<'a> {
    view: View<'a>,
    count: usize,
}

/// This implementation assumes `MethodTable.SupportsRelativePointers == true`
impl<'a> ExternalReferencesTable<'a> {
    pub fn new(view: View<'a>, size: u64) -> Self {
        Self {
            view,
            count: size as usize / std::mem::size_of::<u32>(),
        }
    }

    pub fn get_va_from_index(&self, index: u32) -> Option<Va> {
        if index as usize > self.count {
            return None;
        }

        let mut view = self.view.with_offset(index as Va * 4);
        let mut bytes = [0; 4];
        view.read_exact(&mut bytes).ok()?;

        Some((view.base as i64 + i32::from_le_bytes(bytes) as i64) as Va)
    }
}
