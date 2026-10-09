// SPDX-FileCopyrightText: 2026 Lunia
// SPDX-License-Identifier: Apache-2.0

//! Subset of system/update_engine/update_metadata.proto needed for extraction.

#[derive(Clone, PartialEq, prost::Message)]
pub struct Extent {
    #[prost(uint64, optional, tag = "1")]
    pub start_block: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    pub num_blocks: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PartitionInfo {
    #[prost(uint64, optional, tag = "1")]
    pub size: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub hash: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum OpType {
    Replace = 0,
    ReplaceBz = 1,
    Move = 2,
    Bsdiff = 3,
    SourceCopy = 4,
    SourceBsdiff = 5,
    Zero = 6,
    Discard = 7,
    ReplaceXz = 8,
    Puffdiff = 9,
    BrotliBsdiff = 10,
    Zucchini = 11,
    Lz4diffBsdiff = 12,
    Lz4diffPuffdiff = 13,
}

impl OpType {
    pub fn needs_source(self) -> bool {
        !matches!(
            self,
            OpType::Replace
                | OpType::ReplaceBz
                | OpType::ReplaceXz
                | OpType::Zero
                | OpType::Discard
        )
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct InstallOperation {
    #[prost(enumeration = "OpType", required, tag = "1")]
    pub r#type: i32,
    #[prost(uint64, optional, tag = "2")]
    pub data_offset: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub data_length: Option<u64>,
    #[prost(message, repeated, tag = "4")]
    pub src_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "5")]
    pub src_length: Option<u64>,
    #[prost(message, repeated, tag = "6")]
    pub dst_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "7")]
    pub dst_length: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub data_sha256_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub src_sha256_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PartitionUpdate {
    #[prost(string, required, tag = "1")]
    pub partition_name: String,
    #[prost(message, optional, tag = "6")]
    pub old_partition_info: Option<PartitionInfo>,
    #[prost(message, optional, tag = "7")]
    pub new_partition_info: Option<PartitionInfo>,
    #[prost(message, repeated, tag = "8")]
    pub operations: Vec<InstallOperation>,
    #[prost(message, optional, tag = "10")]
    pub hash_tree_data_extent: Option<Extent>,
    #[prost(message, optional, tag = "11")]
    pub hash_tree_extent: Option<Extent>,
    #[prost(string, optional, tag = "12")]
    pub hash_tree_algorithm: Option<String>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub hash_tree_salt: Option<Vec<u8>>,
    #[prost(message, optional, tag = "14")]
    pub fec_data_extent: Option<Extent>,
    #[prost(message, optional, tag = "15")]
    pub fec_extent: Option<Extent>,
    #[prost(uint32, optional, tag = "16", default = "2")]
    pub fec_roots: Option<u32>,
    #[prost(string, optional, tag = "17")]
    pub version: Option<String>,
}

impl PartitionUpdate {
    pub fn is_delta(&self) -> bool {
        // prost's r#type() getter maps unknown values to REPLACE, so go through try_from.
        self.operations
            .iter()
            .any(|op| OpType::try_from(op.r#type).map_or(true, OpType::needs_source))
    }

    pub fn new_size(&self) -> u64 {
        self.new_partition_info
            .as_ref()
            .and_then(|i| i.size)
            .unwrap_or(0)
    }

    pub fn new_hash(&self) -> Option<&[u8]> {
        self.new_partition_info.as_ref()?.hash.as_deref()
    }

    pub fn old_hash(&self) -> Option<&[u8]> {
        self.old_partition_info.as_ref()?.hash.as_deref()
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeltaArchiveManifest {
    #[prost(uint32, optional, tag = "3", default = "4096")]
    pub block_size: Option<u32>,
    #[prost(uint64, optional, tag = "4")]
    pub signatures_offset: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub signatures_size: Option<u64>,
    #[prost(uint32, optional, tag = "12", default = "0")]
    pub minor_version: Option<u32>,
    #[prost(message, repeated, tag = "13")]
    pub partitions: Vec<PartitionUpdate>,
    #[prost(int64, optional, tag = "14")]
    pub max_timestamp: Option<i64>,
    #[prost(bool, optional, tag = "16")]
    pub partial_update: Option<bool>,
    #[prost(string, optional, tag = "18")]
    pub security_patch_level: Option<String>,
}

/// From external/puffin/src/puffin.proto.
pub mod puffin {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct BitExtent {
        #[prost(uint64, tag = "1")]
        pub offset: u64,
        #[prost(uint64, tag = "2")]
        pub length: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct StreamInfo {
        #[prost(message, repeated, tag = "1")]
        pub deflates: Vec<BitExtent>,
        #[prost(message, repeated, tag = "2")]
        pub puffs: Vec<BitExtent>,
        #[prost(uint64, tag = "3")]
        pub puff_length: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum PatchType {
        Bsdiff = 0,
        Zucchini = 1,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PatchHeader {
        #[prost(int32, tag = "1")]
        pub version: i32,
        #[prost(message, optional, tag = "2")]
        pub src: Option<StreamInfo>,
        #[prost(message, optional, tag = "3")]
        pub dst: Option<StreamInfo>,
        #[prost(enumeration = "PatchType", tag = "4")]
        pub r#type: i32,
    }
}
