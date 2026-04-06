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
