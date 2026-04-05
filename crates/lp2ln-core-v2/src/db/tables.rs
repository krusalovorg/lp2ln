use redb::TableDefinition;

pub const STORAGE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("storage");
pub const PEER_INFO_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("peer_info");
pub const PEER_DESCRIPTOR_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("peer_descriptors");
pub const PEER_SCORE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("peer_scores");

pub const PEER_SCORE_SNAPSHOT_KEY: &str = "_snapshot_v1";
