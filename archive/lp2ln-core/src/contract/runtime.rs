use crate::db::{P2PDatabase, ContractMetadata};
use bincode;
use wasmtime::*;

pub fn execute_contract_with_payload(
    path: &str,
    function_name: &str,
    payload: &[u8],
    db: &P2PDatabase,
) -> Result<Vec<u8>, String> {
    let engine = Engine::default();
    let module = match Module::from_file(&engine, path) {
        Ok(m) => m,
        Err(e) => {
            return Err(format!("Failed to load contract: {}", e));
        }
    };

    let mut store = Store::new(&engine, ());
    let instance = match Instance::new(&mut store, &module, &[]) {
        Ok(i) => i,
        Err(e) => {
            return Err(format!("Failed to create instance: {}", e));
        }
    };

    let memory = match instance.get_memory(&mut store, "memory") {
        Some(m) => m,
        None => {
            return Err("Memory not found".to_string());
        }
    };

    let offset = 1024;
    if let Err(e) = memory.write(&mut store, offset, payload) {
        return Err(format!("Failed to write payload to memory: {}", e));
    }

    let execute = match instance.get_typed_func::<(i32, i32), i32>(&mut store, function_name) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!("Failed to get function {}: {}", function_name, e));
        }
    };

    let result_offset = match execute.call(&mut store, (offset as i32, payload.len() as i32)) {
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Contract execution failed: {}", e));
        }
    };

    let mut result_buffer = vec![0u8; 1024];
    if let Err(e) = memory.read(&mut store, result_offset as usize, &mut result_buffer) {
        return Err(format!("Failed to read result from memory: {}", e));
    }

    let result_size = result_buffer
        .iter()
        .position(|&x| x == 0)
        .unwrap_or(result_buffer.len());
    let result = result_buffer[..result_size].to_vec();

    // Сохраняем метаданные контракта
    if let Ok(metadata) = bincode::deserialize::<ContractMetadata>(&result) {
        if let Err(_e) = db.save_contract_metadata(&metadata) {
            // Метаданные не удалось сохранить, но это не критично
        }
    }

    Ok(result)
}