variable "table_name" {
  type        = string
  description = "Base name of the DynamoDB table for PQC-encrypted items"
  default     = "pqc-items"
}

variable "environment" {
  type        = string
  description = "Deployment environment label (dev, staging, prod)"
  default     = "dev"
}

variable "region" {
  type        = string
  description = "AWS region for all resources"
  default     = "eu-central-1"
}
