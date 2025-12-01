use super::peer_api::PeerAPI;

#[derive(Debug, Clone)]
pub struct FileGroup {
    pub name: String,
    pub files: Vec<String>,
    pub tags: Vec<String>,
}

impl PeerAPI {
    pub fn add_to_group(&self, group_name: &str, file_hash: &str, tags: Vec<String>) -> Result<(), String> {
        let files = self.db.get_my_fragments().map_err(|e| e.to_string())?;
        
        if !files.iter().any(|f| f.file_hash == file_hash) {
            return Err(format!("Файл с хешем {} не найден", file_hash));
        }

        self.db.add_file_to_group(group_name, file_hash, tags).map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn remove_from_group(&self, group_name: &str, file_hash: &str) -> Result<(), String> {
        self.db.remove_file_from_group(group_name, file_hash).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_groups(&self) -> Result<Vec<String>, String> {
        let groups = self.db.get_all_groups().map_err(|e| e.to_string())?;
        Ok(groups)
    }

    pub fn get_group_files(&self, group_name: &str) -> Result<Vec<String>, String> {
        let files = self.db.get_files_by_group(group_name).map_err(|e| e.to_string())?;
        Ok(files.into_iter().map(|f| f.file_hash).collect())
    }
} 