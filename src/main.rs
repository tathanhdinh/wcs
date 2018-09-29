use lief_sys;

use chrono::NaiveDateTime;
use scroll::Pread;
use scroll_derive::Pread;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    mem, path, ptr, slice,
};
use structopt::StructOpt;
use tabwriter::TabWriter;

#[repr(C, packed)]
#[derive(Copy, Clone, Default, Pread)]
struct ImageLoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalog_offset: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Pread)]
struct ImageLoadConfigDirectory32 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u32,
    de_commit_total_free_threshold: u32,
    lock_prefix_table: u32,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u32,
    security_cookie: u32,
    se_handler_table: u32,
    se_handle_count: u32,
    guard_cf_check_function_pointer: u32,
    guard_cf_dispatch_function_pointer: u32,
    guard_cf_function_table: u32,
    guard_cf_function_count: u32,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u32,
    guard_address_taken_iat_entry_count: u32,
    guard_long_jump_target_table: u32,
    guard_long_jump_target_count: u32,
    dynamic_value_reloc_table: u32,
    chpe_metadata_pointer: u32,
    guard_rf_failure_routine: u32,
    guard_rf_failure_routine_function_pointer: u32,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u32,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u32,
    volatile_metadata_pointer: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Pread)]
struct ImageLoadConfigDirectory64 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u64,
    de_commit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u64,
    guard_address_taken_iat_entry_count: u64,
    guard_long_jump_target_table: u64,
    guard_long_jump_target_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata_pointer: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_function_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u64,
    volatile_metadata_pointer: u64,
}

type ImageLoadConfigDirectory = ImageLoadConfigDirectory64;

impl From<ImageLoadConfigDirectory32> for ImageLoadConfigDirectory {
    fn from(dir32: ImageLoadConfigDirectory32) -> Self {
        ImageLoadConfigDirectory {
            size: dir32.size,
            time_date_stamp: dir32.time_date_stamp,
            major_version: dir32.major_version,
            minor_version: dir32.minor_version,
            global_flags_clear: dir32.global_flags_clear,
            global_flags_set: dir32.global_flags_set,
            critical_section_default_timeout: dir32.critical_section_default_timeout,
            de_commit_free_block_threshold: dir32.de_commit_free_block_threshold as _,
            de_commit_total_free_threshold: dir32.de_commit_total_free_threshold as _,
            lock_prefix_table: dir32.lock_prefix_table as _,
            maximum_allocation_size: dir32.maximum_allocation_size as _,
            virtual_memory_threshold: dir32.virtual_memory_threshold as _,
            process_affinity_mask: dir32.process_affinity_mask as _,
            process_heap_flags: dir32.process_heap_flags,
            csd_version: dir32.csd_version,
            dependent_load_flags: dir32.dependent_load_flags,
            edit_list: dir32.edit_list as _,
            security_cookie: dir32.security_cookie as _,
            se_handler_table: dir32.se_handler_table as _,
            se_handler_count: dir32.se_handle_count as _,
            guard_cf_check_function_pointer: dir32.guard_cf_check_function_pointer as _,
            guard_cf_dispatch_function_pointer: dir32.guard_cf_dispatch_function_pointer as _,
            guard_cf_function_table: dir32.guard_cf_function_table as _,
            guard_cf_function_count: dir32.guard_cf_function_count as _,
            guard_flags: dir32.guard_flags,
            code_integrity: dir32.code_integrity,
            guard_address_taken_iat_entry_table: dir32.guard_address_taken_iat_entry_table as _,
            guard_address_taken_iat_entry_count: dir32.guard_address_taken_iat_entry_count as _,
            guard_long_jump_target_table: dir32.guard_long_jump_target_table as _,
            guard_long_jump_target_count: dir32.guard_long_jump_target_count as _,
            dynamic_value_reloc_table: dir32.dynamic_value_reloc_table as _,
            chpe_metadata_pointer: dir32.chpe_metadata_pointer as _,
            guard_rf_failure_routine: dir32.guard_rf_failure_routine as _,
            guard_rf_failure_routine_function_pointer: dir32
                .guard_rf_failure_routine_function_pointer
                as _,
            dynamic_value_reloc_table_offset: dir32.dynamic_value_reloc_table_offset,
            dynamic_value_reloc_table_section: dir32.dynamic_value_reloc_table_section,
            reserved2: dir32.reserved2,
            guard_rf_verify_stack_pointer_function_pointer: dir32
                .guard_rf_verify_stack_pointer_function_pointer
                as _,
            hot_patch_table_offset: dir32.hot_patch_table_offset,
            reserved3: dir32.reserved3,
            enclave_configuration_pointer: dir32.enclave_configuration_pointer as _,
            volatile_metadata_pointer: dir32.volatile_metadata_pointer as _,
        }
    }
}

#[derive(StructOpt)]
#[structopt(name = "wcs", about = "Security checker for PE")]
struct Args {
    #[structopt(name = "PE file", parse(from_os_str))]
    input: path::PathBuf,
}

fn main() {
    let args = Args::from_args();

    let tabbed_stdout = io::stdout();
    let mut tabbed_stdout = {
        let w = tabbed_stdout.lock();
        let w = io::BufWriter::new(w);
        TabWriter::new(w)
    };

    let pe_name = args.input.to_string_lossy().into_owned();

    let raw_pe;
    let pe = {
        let input = CString::new(pe_name.clone()).unwrap();

        raw_pe = unsafe { lief_sys::pe_parse(input.as_ptr()) };
        if raw_pe.is_null() {
            panic!("Unable to parse PE file");
        }
        unsafe { *raw_pe }
    };

    let pe_header = &pe.header;
    let img_crs = pe_header.characteristics;

    let optional_header = &pe.optional_header;

    let data_dirs = pe.data_directories;
    let data_dir_count = optional_header.numberof_rva_and_size;

    let clr_data_dir_idx: u32 =
        unsafe { mem::transmute(lief_sys::LIEF_PE_DATA_DIRECTORY::LIEF_PE_CLR_RUNTIME_HEADER) };
    let clr_data_dir = if clr_data_dir_idx + 1 > data_dir_count {
        None
    } else {
        let clr_data_dir: *mut lief_sys::Pe_DataDirectory_t =
            unsafe { *data_dirs.offset(clr_data_dir_idx as isize) };
        if clr_data_dir.is_null() {
            None
        } else {
            Some(unsafe { *clr_data_dir })
        }
    };

    let img_load_cfg_dir_idx: u32 =
        unsafe { mem::transmute(lief_sys::LIEF_PE_DATA_DIRECTORY::LIEF_PE_LOAD_CONFIG_TABLE) };

    let img_load_cfg_dir: Option<ImageLoadConfigDirectory> = if img_load_cfg_dir_idx + 1
        > data_dir_count
    {
        None
    } else {
        let load_cfg_data_dir: *mut lief_sys::Pe_DataDirectory_t =
            unsafe { *data_dirs.offset(img_load_cfg_dir_idx as isize) };

        if load_cfg_data_dir.is_null() {
            None
        } else {
            let load_cfg_data_dir = unsafe { *load_cfg_data_dir };

            if load_cfg_data_dir.rva == 0 || load_cfg_data_dir.size == 0 {
                None
            } else {
                let section_count = pe_header.numberof_sections;
                let sections = pe.sections;
                let sections = unsafe { slice::from_raw_parts(sections, section_count as usize) };

                let mut sec_of_img_load_cfg_dir = ptr::null_mut();
                for sec in sections {
                    let sec = *sec;

                    if sec.is_null() {
                        continue;
                    }

                    let sec_data = unsafe { *sec };
                    let rva = load_cfg_data_dir.rva.into();
                    if sec_data.virtual_address < rva
                        && rva < sec_data.virtual_address + sec_data.size
                    {
                        sec_of_img_load_cfg_dir = sec;
                        break;
                    }
                }

                if sec_of_img_load_cfg_dir.is_null() {
                    None
                } else {
                    let sec_of_img_load_cfg_dir = unsafe { *sec_of_img_load_cfg_dir };
                    let img_load_cfg_offset = load_cfg_data_dir.rva
                        - sec_of_img_load_cfg_dir.virtual_address as u32
                        + sec_of_img_load_cfg_dir.pointerto_relocation;

                    let mut pe_file = File::open(&pe_name).unwrap();
                    pe_file
                        .seek(SeekFrom::Start(img_load_cfg_offset as u64))
                        .expect("IMAGE_LOAD_CONFIG_DIRECTORY unreachable");
                    let mut pe_file = BufReader::new(pe_file);

                    // Try to "guess" the correct IMAGE_LOAD_CONFIG_DIRECTORY from magic
                    use lief_sys::LIEF_PE_PE_TYPES::*;
                    match optional_header.magic {
                        LIEF_PE_PE32 => {
                            let mut buffer =
                                Vec::with_capacity(mem::size_of::<ImageLoadConfigDirectory32>());
                            pe_file
                                .read_exact(&mut buffer)
                                .expect("Unable to read IMAGE_LOAD_CONFIG_DIRECTORY32");
                            let cfg: ImageLoadConfigDirectory32 = buffer.pread(0).unwrap();
                            Some(ImageLoadConfigDirectory::from(cfg))
                        }

                        LIEF_PE_PE32_PLUS => {
                            let mut buffer =
                                Vec::with_capacity(mem::size_of::<ImageLoadConfigDirectory64>());
                            pe_file
                                .read_exact(&mut buffer)
                                .expect("Unable to read IMAGE_LOAD_CONFIG_DIRECTORY64");
                            // let cfg: ImageLoadConfigDirectory64 = buffer.pread(0).unwrap();
                            Some(buffer.pread(0).unwrap())
                        }
                    }
                }
            }
        }
    };

    // let sec_of_img_load_cfg_dir = if let Some(load_cfg_data_dir) = load_cfg_data_dir {

    // } else {
    //     None
    // };

    // let img_load_cfg_dir = {
    //     if let Some(sec_of_img_load_cfg_dir) = sec_of_img_load_cfg_dir {
    //         let img_load_cfg_dir_offset =
    //     }
    // };

    let dll_crs = optional_header.dll_characteristics;

    let is_dynamic_base = {
        let dll_crs_dyn_base: u32 = unsafe {
            mem::transmute(lief_sys::LIEF_PE_DLL_CHARACTERISTICS::LIEF_PE_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)
        };
        dll_crs | dll_crs_dyn_base != 0
    };

    // let is_dotnet = {
    //     if let Some(load_cfg_data_dir) = load_cfg_data_dir {
    //         clr_data_dir.
    //     } else {
    //         false
    //     }
    // }

    // let section_count = pe_header.numberof_sections;
    // let sections = pe.sections;
    // let sections = unsafe { slice::from_raw_parts(sections, section_count as usize) };
    // for sec in sections {
    //     let sec = *sec;

    //     if sec.is_null() {
    //         continue
    //     }

    //     let sec_data = unsafe { *sec };
    //     if sec_data.virtual_address < load_cfg_data_dir
    // }
}
