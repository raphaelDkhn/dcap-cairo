use std::{fs, path::PathBuf};

use cairo1_run::{cairo_run_program, error::Error, Cairo1RunConfig, FuncArg};
use cairo_lang_sierra::program::{Program, VersionedProgram};
use cairo_vm::types::layout_name::LayoutName;

pub(super) fn cairo_run(inputs: Vec<FuncArg>, sierra_file: PathBuf) -> Result<bool, Error> {
    let program = load_sierra_file(sierra_file)?;

    let config = Cairo1RunConfig {
        args: Default::default(),
        serialize_output: true,
        trace_enabled: false,
        relocate_mem: false,
        layout: LayoutName::all_cairo,
        proof_mode: false,
        finalize_builtins: false,
        append_return_values: false,
        dynamic_layout_params: None,
    };

    let (runner, return_values, serialized_output) = cairo_run_program(&program, config)?;

    println!("Res: {:?}", serialized_output);

    Ok(true)
}

fn load_sierra_file(file_path: PathBuf) -> Result<Program, Error> {
    let content = fs::read(&file_path)
        .map_err(|e| Error::SierraCompilation(format!("Failed to read file: {:?}", e)))?;

    let versioned_program = serde_json::from_slice::<VersionedProgram>(&content)
        .map_err(|e| Error::SierraCompilation(format!("Failed to deserialize file: {:?}", e)))?;

    let program = versioned_program
        .into_v1()
        .map_err(|_| Error::SierraCompilation("Version conversion failed".into()))?
        .program;

    Ok(program)
}
