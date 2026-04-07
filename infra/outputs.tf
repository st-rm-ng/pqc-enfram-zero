output "table_arn" {
  description = "ARN of the PQC DynamoDB table"
  value       = aws_dynamodb_table.pqc_store.arn
}

output "table_name" {
  description = "Full name of the PQC DynamoDB table"
  value       = aws_dynamodb_table.pqc_store.name
}

output "iam_policy_arn" {
  description = "ARN of the IAM policy granting DynamoDB access to the framework client"
  value       = aws_iam_policy.pqc_dynamodb.arn
}

output "kms_key_id" {
  description = "KMS key ID for the PQC keystore"
  value       = aws_kms_key.pqc_keystore.key_id
}

output "kms_key_alias" {
  description = "KMS key alias for the PQC keystore (use this in the framework)"
  value       = aws_kms_alias.pqc_keystore.name
}
