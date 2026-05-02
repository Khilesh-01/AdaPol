# Sample Terraform infrastructure for AWS with security vulnerabilities
# This demonstrates privilege escalation and lateral movement risks

provider "aws" {
  region = "us-east-1"
}

# ============================================================================
# LAMBDA FUNCTIONS
# ============================================================================

resource "aws_lambda_function" "user_processor" {
  filename      = "lambda.zip"
  function_name = "user_processor"
  role          = aws_iam_role.user_processor_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  
  environment {
    variables = {
      DB_NAME = aws_dynamodb_table.users.name
    }
  }
}

resource "aws_lambda_function" "order_processor" {
  filename      = "lambda.zip"
  function_name = "order_processor"
  role          = aws_iam_role.order_processor_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  
  environment {
    variables = {
      BUCKET = aws_s3_bucket.orders.id
    }
  }
}

resource "aws_lambda_function" "admin_task" {
  filename      = "lambda.zip"
  function_name = "admin_task"
  role          = aws_iam_role.admin_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
}

# ============================================================================
# IAM ROLES AND POLICIES
# ============================================================================

# Overly permissive user processor role
resource "aws_iam_role" "user_processor_role" {
  name = "user_processor_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "user_processor_policy" {
  name = "user_processor_policy"
  role = aws_iam_role.user_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "dynamodb:*"  # VULNERABILITY: Wildcard on DynamoDB
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.orders.arn}/*"
      },
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"  # VULNERABILITY: Can assume other roles
        Resource = "*"
      }
    ]
  })
}

# Order processor role with cross-function access
resource "aws_iam_role" "order_processor_role" {
  name = "order_processor_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "order_processor_policy" {
  name = "order_processor_policy"
  role = aws_iam_role.order_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.orders.arn}/*"
      },
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"  # VULNERABILITY: Can invoke other functions
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"  # Can escalate to admin
        Resource = aws_iam_role.admin_role.arn
      }
    ]
  })
}

# Admin role - too permissive
resource "aws_iam_role" "admin_role" {
  name = "admin_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"  # Can be assumed from any role!
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "admin_policy" {
  name = "admin_policy"
  role = aws_iam_role.admin_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # CRITICAL: Full admin access
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# RESOURCES
# ============================================================================

resource "aws_dynamodb_table" "users" {
  name             = "users"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "user_id"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "user_id"
    type = "S"
  }

  tags = {
    Sensitivity = "HIGH"
    Data        = "PII"
  }
}

resource "aws_s3_bucket" "orders" {
  bucket = "company-orders-bucket-unique-${data.aws_caller_identity.current.account_id}"

  tags = {
    Sensitivity = "MEDIUM"
  }
}

resource "aws_s3_bucket_public_access_block" "orders" {
  bucket = aws_s3_bucket.orders.id

  block_public_acls       = true
  block_public_policy     = false  # VULNERABILITY: Allows public policy
  ignore_public_acls      = true
  restrict_public_buckets = false  # VULNERABILITY: Not restricted
}

resource "aws_rds_instance" "production_db" {
  identifier     = "production-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "production"
  username = "admin"
  password = "Change-Me-123!"  # VULNERABILITY: Should use secrets manager

  skip_final_snapshot = true

  tags = {
    Sensitivity = "CRITICAL"
    Data        = "CONFIDENTIAL"
  }
}

# ============================================================================
# DATA SOURCES
# ============================================================================

data "aws_caller_identity" "current" {}

# ============================================================================
# OUTPUTS
# ============================================================================

output "user_processor_arn" {
  value = aws_lambda_function.user_processor.arn
}

output "order_processor_arn" {
  value = aws_lambda_function.order_processor.arn
}

output "admin_task_arn" {
  value = aws_lambda_function.admin_task.arn
}
