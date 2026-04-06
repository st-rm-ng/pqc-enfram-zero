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
