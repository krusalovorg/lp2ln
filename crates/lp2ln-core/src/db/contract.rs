use bincode;

use crate::db::models::ContractMetadata;

use super::db::P2PDatabase;
use super::tables;

impl P2PDatabase {
    pub fn get_contract_metadata(&self, contract_id: &str) -> Result<Option<ContractMetadata>, String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        let read_txn = db.begin_read().map_err(|e| e.to_string())?;
        
        let table = read_txn.open_table(tables::CONTRACT_METADATA_TABLE)
            .map_err(|e| e.to_string())?;
        
        if let Some(data) = table.get(contract_id).map_err(|e| e.to_string())? {
            let metadata: ContractMetadata = bincode::deserialize(data.value())
                .map_err(|e| e.to_string())?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    pub fn save_contract_metadata(&self, metadata: &ContractMetadata) -> Result<(), String> {
        let db = self.db.lock().map_err(|e| e.to_string())?;
        let write_txn = db.begin_write().map_err(|e| e.to_string())?;
    
        {
            let mut table = write_txn
                .open_table(crate::db::tables::CONTRACT_METADATA_TABLE)
                .map_err(|e| e.to_string())?;
        
            let serialized = bincode::serialize(metadata).map_err(|e| e.to_string())?;
        
            table
                .insert(metadata.contract_id.as_str(), serialized.as_slice())
                .map_err(|e| e.to_string())?;
        }
    
        write_txn.commit().map_err(|e| e.to_string())?;
        Ok(())
    }
    
}
