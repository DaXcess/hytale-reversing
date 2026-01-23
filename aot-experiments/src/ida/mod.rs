use serde::Serialize;

#[derive(Serialize, Default)]
pub struct HytaleDefinition {
    mt_structs: Vec<MtStruct>,
    functions: Vec<Function>,
}

#[derive(Serialize)]
struct MtStruct {
    name: Vec<String>,
    vtables: u16,
    ifaces: u16,
    address: u64,
}

#[derive(Serialize)]
struct Function {
    name: String,
    address: u64,
}

impl HytaleDefinition {
    pub fn create_mt_struct<S: AsRef<str>>(
        &mut self,
        address: u64,
        name: S,
        vtables: u16,
        ifaces: u16,
    ) {
        let name = name.as_ref().replace("|", "_");
        let parts = name.split(".").map(str::to_string).collect::<Vec<_>>();

        self.mt_structs.push(MtStruct {
            name: parts,
            vtables,
            ifaces,
            address,
        })
    }

    pub fn create_function<S: Into<String>>(&mut self, address: u64, name: S) {
        self.functions.push(Function {
            name: name.into().replace("|", "_").replace(".", "_"),
            address,
        });
    }
}
