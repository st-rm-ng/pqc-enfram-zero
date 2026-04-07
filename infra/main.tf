terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_dynamodb_table" "pqc_store" {
  name         = "${var.table_name}-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  tags = {
    Name        = "${var.table_name}-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "pqc-enfram-zero"
  }
}

resource "aws_kms_key" "pqc_keystore" {
  description             = "Encrypts the PQC framework client key bundle (ML-KEM + ML-DSA + AES DEK)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "pqc-enfram-zero"
  }
}

resource "aws_kms_alias" "pqc_keystore" {
  name          = "alias/pqc-keystore-${var.environment}"
  target_key_id = aws_kms_key.pqc_keystore.key_id
}

data "aws_iam_policy_document" "pqc_dynamodb" {
  statement {
    sid    = "AllowPqcDynamoDbAccess"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
    ]

    resources = [
      aws_dynamodb_table.pqc_store.arn,
    ]
  }

  statement {
    sid    = "AllowPqcKeystoreKms"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]

    resources = [
      aws_kms_key.pqc_keystore.arn,
    ]
  }
}

resource "aws_iam_policy" "pqc_dynamodb" {
  name        = "pqc-dynamodb-access-${var.environment}"
  description = "Grants the PQC framework client access to its DynamoDB table"
  policy      = data.aws_iam_policy_document.pqc_dynamodb.json

  tags = {
    Environment = var.environment
    Project     = "pqc-enfram-zero"
  }
}
