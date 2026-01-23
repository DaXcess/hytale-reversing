import json
import ida_kernwin
import ida_dirtree
import ida_bytes
import idc

from pydantic import BaseModel
from typing import List, Optional

class HytaleDefinition(BaseModel):
    mt_structs: List[MtStruct]
    functions: List[Function]

class MtStruct(BaseModel):
    name: List[str]
    vtables: int
    ifaces: int
    address: int

class Function(BaseModel):
    name: str
    address: int

def load_json() -> Optional[HytaleDefinition]:
    json_path = ida_kernwin.ask_file(0, "*.json", "Select JSON file to parse")

    if not json_path:
        print("[!] No file selected. Aborting.")
        return

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return HytaleDefinition.model_validate_json(f.read())
    except Exception as e:
        print(f"[!] Error parsing JSON: {str(e)}")

def create_mt_struct(struct_name: List[str], num_vtable=0, num_interface=0):
    # Actual type name will be the full name including namespace
    full_name = "_".join(struct_name)

    # Return early if struct already exists
    sid = idc.get_struc_id(f"{full_name}")
    if sid != idc.BADADDR:
        return sid

    # Create subdirs
    type_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_LOCAL_TYPES)
    path = "NativeAOT/MethodTables/"
    if len(struct_name) > 1:
        for item in struct_name[:-1]:
            path = f"{path}{item}/"
            type_dir.mkdir(path)

    ptr_size = 8
    ptr_flag = idc.FF_QWORD

    sid = idc.add_struc(idc.BADADDR, f"{full_name}", False)

    if sid == -1:
        return -1
    
    idc.add_struc_member(sid, "uFlags", -1, idc.FF_DWORD, -1, 4)
    idc.add_struc_member(sid, "uBaseSize", -1, idc.FF_DWORD, -1, 4)
    idc.add_struc_member(sid, "relatedType", -1, idc.FF_QWORD | idc.FF_0OFF, -1, 8)
    idc.add_struc_member(sid, "usNumVtableSlots", -1, idc.FF_WORD, -1, 2)
    idc.add_struc_member(sid, "usNumInterfaceSlots", -1, idc.FF_WORD, -1, 2)
    idc.add_struc_member(sid, "uHashCode", -1, idc.FF_DWORD, -1, 4)

    if num_vtable > 0:
        idc.add_struc_member(sid, "vtable_slots", -1, idc.FF_QWORD | idc.FF_0OFF, -1, 8 * num_vtable)

    if num_interface > 0:
        idc.add_struc_member(sid, "interface_slots", -1, idc.FF_QWORD | idc.FF_0OFF, -1, 8 * num_interface)

    type_dir.rename(f"{full_name}", f"{path}{full_name}")

    return sid

def create_method(name: str, address: int):
    idc.set_name(address, name, idc.SN_NOCHECK | 0x800)
    pass

def main():
    parsed_data = load_json()
    if parsed_data == None:
        return

    type_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_LOCAL_TYPES)
    type_dir.mkdir("NativeAOT")
    type_dir.mkdir("NativeAOT/MethodTables")
    type_dir.mkdir("NativeAOT/Structs")

    for mt in parsed_data.mt_structs:
        sid = create_mt_struct(mt.name, mt.vtables, mt.ifaces)
        if sid == -1:
            print(f"Failed to create struct {mt.name}")
            continue

        ida_bytes.create_data(mt.address, ida_bytes.FF_STRUCT, idc.get_struc_size(sid), sid)

    for fn in parsed_data.functions:
        create_method(fn.name, fn.address)

if __name__ == '__main__':
    main()
