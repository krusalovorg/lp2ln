use redb::TableDefinition;

/// Content-addressed block blobs. Key = hex ContentId.
pub const BLOCK_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blocks");

/// Replica leases. Key = `{content_id_hex}:{holder_peer_id}`.
pub const LEASE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("replica_leases");
