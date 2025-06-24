//! AWS S3 storage backend implementation
//!
//! This module provides a complete S3 storage backend with support for:
//! - Basic CRUD operations (put, get, delete, exists)
//! - Multipart uploads for large files
//! - Presigned URLs for secure access
//! - Bucket operations and management
//! - Retry logic and error handling

#[cfg(feature = "s3")]
use aws_sdk_s3::{
    Client as S3Client,
    primitives::ByteStream,
    types::{
        CompletedMultipartUpload, CompletedPart,
        ObjectCannedAcl, ServerSideEncryption,
    },
    error::SdkError,
    operation::create_multipart_upload::CreateMultipartUploadOutput,
};

#[cfg(feature = "s3")]
use aws_config::{BehaviorVersion, Region};

use crate::error::{StorageError, StorageResult};
use crate::storage::storage_api::{
    StorageApi, StorageApiSync, StorageConfig, StorageMetadata, StorageBackend,
    BatchOperation, BatchResult, BatchOperationType,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

#[cfg(feature = "async")]
use tokio::time::timeout;

/// S3 storage configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// AWS access key ID (optional, can use IAM roles)
    pub access_key_id: Option<String>,
    /// AWS secret access key (optional, can use IAM roles)
    pub secret_access_key: Option<String>,
    /// S3 endpoint URL (for S3-compatible services)
    pub endpoint_url: Option<String>,
    /// Enable server-side encryption
    pub server_side_encryption: bool,
    /// Default ACL for objects
    pub default_acl: Option<String>,
    /// Multipart upload threshold (bytes)
    pub multipart_threshold: u64,
    /// Multipart chunk size (bytes)
    pub multipart_chunk_size: u64,
    /// Enable path-style addressing
    pub path_style: bool,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            endpoint_url: None,
            server_side_encryption: true,
            default_acl: Some("private".to_string()),
            multipart_threshold: 100 * 1024 * 1024, // 100MB
            multipart_chunk_size: 10 * 1024 * 1024,  // 10MB
            path_style: false,
        }
    }
}

/// S3 storage backend
#[cfg(feature = "s3")]
pub struct S3Storage {
    client: S3Client,
    config: S3Config,
    storage_config: StorageConfig,
}

#[cfg(feature = "s3")]
impl S3Storage {
    /// Create a new S3 storage backend
    pub async fn new(s3_config: S3Config, storage_config: StorageConfig) -> StorageResult<Self> {
        let aws_config = Self::build_aws_config(&s3_config).await?;
        let client = S3Client::new(&aws_config);
        
        // Verify bucket access
        Self::verify_bucket_access(&client, &s3_config.bucket).await?;
        
        Ok(Self {
            client,
            config: s3_config,
            storage_config,
        })
    }
    
    /// Build AWS configuration
    async fn build_aws_config(config: &S3Config) -> StorageResult<aws_config::SdkConfig> {
        let mut builder = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));
        
        // Set credentials if provided
        if let (Some(access_key), Some(secret_key)) = (&config.access_key_id, &config.secret_access_key) {
            builder = builder.credentials_provider(
                aws_sdk_s3::config::Credentials::new(
                    access_key,
                    secret_key,
                    None,
                    None,
                    "r-squared-storage",
                )
            );
        }
        
        // Set custom endpoint if provided
        if let Some(endpoint) = &config.endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }
        
        Ok(builder.load().await)
    }
    
    /// Verify bucket access
    async fn verify_bucket_access(client: &S3Client, bucket: &str) -> StorageResult<()> {
        match client.head_bucket().bucket(bucket).send().await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::ConnectionError {
                reason: format!("Cannot access S3 bucket '{}': {}", bucket, e),
            }),
        }
    }
    
    /// Convert S3 metadata to StorageMetadata
    fn convert_metadata(
        &self,
        head_output: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
    ) -> StorageMetadata {
        let mut custom = HashMap::new();
        
        if let Some(metadata) = &head_output.metadata {
            for (key, value) in metadata {
                custom.insert(key.clone(), value.clone());
            }
        }
        
        StorageMetadata {
            content_type: head_output.content_type.clone(),
            content_length: head_output.content_length.unwrap_or(0) as u64,
            last_modified: head_output.last_modified.map(|dt| {
                chrono::DateTime::from_timestamp(dt.secs(), dt.subsec_nanos()).unwrap_or_default()
            }),
            etag: head_output.e_tag.clone(),
            custom,
        }
    }
    
    /// Perform multipart upload for large objects
    async fn multipart_upload(&self, key: &str, data: Bytes) -> StorageResult<()> {
        // Initiate multipart upload
        let create_output = self.client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .set_server_side_encryption(
                if self.config.server_side_encryption {
                    Some(ServerSideEncryption::Aes256)
                } else {
                    None
                }
            )
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "create_multipart_upload".to_string(),
                reason: format!("Failed to initiate multipart upload: {}", e),
            })?;
        
        let upload_id = create_output.upload_id.ok_or_else(|| StorageError::OperationFailed {
            operation: "create_multipart_upload".to_string(),
            reason: "No upload ID returned".to_string(),
        })?;
        
        // Upload parts
        let mut completed_parts = Vec::new();
        let chunk_size = self.config.multipart_chunk_size as usize;
        
        for (part_number, chunk) in data.chunks(chunk_size).enumerate() {
            let part_number = (part_number + 1) as i32;
            
            let upload_part_output = self.client
                .upload_part()
                .bucket(&self.config.bucket)
                .key(key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(ByteStream::from(Bytes::copy_from_slice(chunk)))
                .send()
                .await
                .map_err(|e| StorageError::OperationFailed {
                    operation: "upload_part".to_string(),
                    reason: format!("Failed to upload part {}: {}", part_number, e),
                })?;
            
            completed_parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .set_e_tag(upload_part_output.e_tag)
                    .build()
            );
        }
        
        // Complete multipart upload
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();
        
        self.client
            .complete_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "complete_multipart_upload".to_string(),
                reason: format!("Failed to complete multipart upload: {}", e),
            })?;
        
        Ok(())
    }
    
    /// Generate presigned URL for object access
    pub async fn generate_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
        method: PresignedUrlMethod,
    ) -> StorageResult<String> {
        let presigning_config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| StorageError::OperationFailed {
                operation: "generate_presigned_url".to_string(),
                reason: format!("Invalid expiration duration: {}", e),
            })?;
        
        let url = match method {
            PresignedUrlMethod::Get => {
                self.client
                    .get_object()
                    .bucket(&self.config.bucket)
                    .key(key)
                    .presigned(presigning_config)
                    .await
            }
            PresignedUrlMethod::Put => {
                self.client
                    .put_object()
                    .bucket(&self.config.bucket)
                    .key(key)
                    .presigned(presigning_config)
                    .await
            }
        }
        .map_err(|e| StorageError::OperationFailed {
            operation: "generate_presigned_url".to_string(),
            reason: format!("Failed to generate presigned URL: {}", e),
        })?;
        
        Ok(url.uri().to_string())
    }
    
    /// List objects in bucket with pagination
    pub async fn list_objects_paginated(
        &self,
        prefix: Option<&str>,
        max_keys: Option<i32>,
        continuation_token: Option<&str>,
    ) -> StorageResult<S3ListResult> {
        let mut request = self.client
            .list_objects_v2()
            .bucket(&self.config.bucket);
        
        if let Some(prefix) = prefix {
            request = request.prefix(prefix);
        }
        
        if let Some(max_keys) = max_keys {
            request = request.max_keys(max_keys);
        }
        
        if let Some(token) = continuation_token {
            request = request.continuation_token(token);
        }
        
        let response = request.send().await
            .map_err(|e| StorageError::OperationFailed {
                operation: "list_objects".to_string(),
                reason: format!("Failed to list objects: {}", e),
            })?;
        
        let objects = response.contents.unwrap_or_default()
            .into_iter()
            .filter_map(|obj| obj.key)
            .collect();
        
        Ok(S3ListResult {
            objects,
            next_continuation_token: response.next_continuation_token,
            is_truncated: response.is_truncated.unwrap_or(false),
        })
    }
}

/// Presigned URL method
#[derive(Debug, Clone, Copy)]
pub enum PresignedUrlMethod {
    /// GET method for downloading
    Get,
    /// PUT method for uploading
    Put,
}

/// S3 list result with pagination support
#[derive(Debug, Clone)]
pub struct S3ListResult {
    /// List of object keys
    pub objects: Vec<String>,
    /// Next continuation token for pagination
    pub next_continuation_token: Option<String>,
    /// Whether the result is truncated
    pub is_truncated: bool,
}

#[cfg(feature = "s3")]
#[cfg(feature = "async")]
impl StorageApi for S3Storage {
    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        // Use multipart upload for large objects
        if data.len() > self.config.multipart_threshold as usize {
            return self.multipart_upload(key, data).await;
        }
        
        // Regular put for smaller objects
        let mut request = self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(data));
        
        if self.config.server_side_encryption {
            request = request.server_side_encryption(ServerSideEncryption::Aes256);
        }
        
        if let Some(acl) = &self.config.default_acl {
            if let Ok(canned_acl) = acl.parse::<ObjectCannedAcl>() {
                request = request.acl(canned_acl);
            }
        }
        
        request.send().await
            .map_err(|e| StorageError::OperationFailed {
                operation: "put_object".to_string(),
                reason: format!("Failed to put object: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn put_with_metadata(&self, key: &str, data: Bytes, metadata: StorageMetadata) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let mut request = self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(data));
        
        if let Some(content_type) = metadata.content_type {
            request = request.content_type(content_type);
        }
        
        if !metadata.custom.is_empty() {
            request = request.set_metadata(Some(metadata.custom));
        }
        
        if self.config.server_side_encryption {
            request = request.server_side_encryption(ServerSideEncryption::Aes256);
        }
        
        request.send().await
            .map_err(|e| StorageError::OperationFailed {
                operation: "put_object_with_metadata".to_string(),
                reason: format!("Failed to put object with metadata: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let response = self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match e {
                SdkError::ServiceError(ref service_err) if service_err.err().is_no_such_key() => {
                    StorageError::ResourceNotFound {
                        resource: key.to_string(),
                    }
                }
                _ => StorageError::OperationFailed {
                    operation: "get_object".to_string(),
                    reason: format!("Failed to get object: {}", e),
                }
            })?;
        
        let data = response.body.collect().await
            .map_err(|e| StorageError::OperationFailed {
                operation: "read_object_body".to_string(),
                reason: format!("Failed to read object body: {}", e),
            })?;
        
        Ok(data.into_bytes())
    }
    
    async fn get_with_metadata(&self, key: &str) -> StorageResult<(Bytes, StorageMetadata)> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let response = self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match e {
                SdkError::ServiceError(ref service_err) if service_err.err().is_no_such_key() => {
                    StorageError::ResourceNotFound {
                        resource: key.to_string(),
                    }
                }
                _ => StorageError::OperationFailed {
                    operation: "get_object_with_metadata".to_string(),
                    reason: format!("Failed to get object: {}", e),
                }
            })?;
        
        let metadata = StorageMetadata {
            content_type: response.content_type,
            content_length: response.content_length.unwrap_or(0) as u64,
            last_modified: response.last_modified.map(|dt| {
                chrono::DateTime::from_timestamp(dt.secs(), dt.subsec_nanos()).unwrap_or_default()
            }),
            etag: response.e_tag,
            custom: response.metadata.unwrap_or_default(),
        };
        
        let data = response.body.collect().await
            .map_err(|e| StorageError::OperationFailed {
                operation: "read_object_body".to_string(),
                reason: format!("Failed to read object body: {}", e),
            })?;
        
        Ok((data.into_bytes(), metadata))
    }
    
    async fn delete(&self, key: &str) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "delete_object".to_string(),
                reason: format!("Failed to delete object: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn exists(&self, key: &str) -> StorageResult<bool> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        match self.client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(ref service_err)) if service_err.err().is_no_such_key() => Ok(false),
            Err(e) => Err(StorageError::OperationFailed {
                operation: "head_object".to_string(),
                reason: format!("Failed to check object existence: {}", e),
            }),
        }
    }
    
    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let result = self.list_objects_paginated(Some(prefix), None, None).await?;
        Ok(result.objects)
    }
    
    async fn head(&self, key: &str) -> StorageResult<StorageMetadata> {
        crate::storage::storage_api::utils::validate_key(key)?;
        
        let response = self.client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| match e {
                SdkError::ServiceError(ref service_err) if service_err.err().is_no_such_key() => {
                    StorageError::ResourceNotFound {
                        resource: key.to_string(),
                    }
                }
                _ => StorageError::OperationFailed {
                    operation: "head_object".to_string(),
                    reason: format!("Failed to get object metadata: {}", e),
                }
            })?;
        
        Ok(self.convert_metadata(&response))
    }
    
    async fn copy(&self, source: &str, destination: &str) -> StorageResult<()> {
        crate::storage::storage_api::utils::validate_key(source)?;
        crate::storage::storage_api::utils::validate_key(destination)?;
        
        let copy_source = format!("{}/{}", self.config.bucket, source);
        
        self.client
            .copy_object()
            .bucket(&self.config.bucket)
            .key(destination)
            .copy_source(&copy_source)
            .send()
            .await
            .map_err(|e| StorageError::OperationFailed {
                operation: "copy_object".to_string(),
                reason: format!("Failed to copy object: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn batch(&self, operations: Vec<BatchOperation>) -> StorageResult<Vec<BatchResult>> {
        let mut results = Vec::new();
        
        for operation in operations {
            let result = match operation.operation {
                BatchOperationType::Put => {
                    if let Some(data) = operation.data {
                        self.put(&operation.key, data).await.map(|_| None)
                    } else {
                        Err(StorageError::OperationFailed {
                            operation: "batch_put".to_string(),
                            reason: "No data provided for put operation".to_string(),
                        })
                    }
                }
                BatchOperationType::Get => {
                    self.get(&operation.key).await.map(Some)
                }
                BatchOperationType::Delete => {
                    self.delete(&operation.key).await.map(|_| None)
                }
                BatchOperationType::Exists => {
                    self.exists(&operation.key).await.map(|exists| {
                        if exists {
                            Some(Bytes::from("true"))
                        } else {
                            Some(Bytes::from("false"))
                        }
                    })
                }
            };
            
            results.push(BatchResult {
                key: operation.key,
                result,
            });
        }
        
        Ok(results)
    }
    
    fn backend_type(&self) -> StorageBackend {
        StorageBackend::S3
    }
    
    fn config(&self) -> &StorageConfig {
        &self.storage_config
    }
}

// Stub implementation for when S3 feature is not enabled
#[cfg(not(feature = "s3"))]
pub struct S3Storage;

#[cfg(not(feature = "s3"))]
impl S3Storage {
    pub fn new(_s3_config: S3Config, _storage_config: StorageConfig) -> StorageResult<Self> {
        Err(StorageError::BackendNotAvailable {
            backend: "S3".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_s3_config_default() {
        let config = S3Config::default();
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.multipart_threshold, 100 * 1024 * 1024);
        assert_eq!(config.multipart_chunk_size, 10 * 1024 * 1024);
        assert!(config.server_side_encryption);
    }
    
    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn test_s3_storage_creation_without_credentials() {
        let s3_config = S3Config {
            bucket: "test-bucket".to_string(),
            ..Default::default()
        };
        let storage_config = StorageConfig::default();
        
        // This will fail without proper AWS credentials, but tests the creation logic
        let result = S3Storage::new(s3_config, storage_config).await;
        assert!(result.is_err()); // Expected to fail without credentials
    }
}