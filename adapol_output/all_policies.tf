# AdaPol Generated Least-Privilege Policies
# Generated at: 2026-04-29T17:36:06.853428+00:00
# Total policies: 2

# Policy for order-processor
# Risk Reduction: 95.0%
# Rules: 18
resource "aws_iam_policy" "order_processor_least_privilege_policy" {
  name        = "order-processor-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for order-processor"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3.amazonaws.com"
      ],
      "Resource": [
        "GetObject:arn:aws:s3:::my-bucket/data-7.json",
        "PutObject:arn:aws:s3:::my-bucket/data-1.json",
        "PutObject:arn:aws:s3:::my-bucket/data-4.json",
        "PutObject:arn:aws:s3:::my-bucket/data-2.json"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com"
      ],
      "Resource": [
        "Query:arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
        "GetItem:arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com:GetItem"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3.amazonaws.com:PutObject"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb.amazonaws.com:Query"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3.amazonaws.com:GetObject"
      ],
      "Resource": [
        "aws_s3_bucket.data_bucket.bucket",
        "aws_dynamodb_table.orders.name",
        "aws_iam_role.lambda_role.arn"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "order-processor"
    RiskReduction = "95.0%"
  }
}

resource "aws_iam_role_policy_attachment" "order_processor_policy_attachment" {
  policy_arn = aws_iam_policy.order_processor_least_privilege_policy.arn
  role       = aws_iam_role.order_processor_execution_role.name
}

# Policy for notification-service
# Risk Reduction: 95.0%
# Rules: 2
resource "aws_iam_policy" "notification_service_least_privilege_policy" {
  name        = "notification-service-least-privilege-policy"
  description = "AdaPol generated least-privilege policy for notification-service"
  
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda.amazonaws.com"
      ],
      "Resource": [
        "InvokeFunction:arn:aws:lambda:us-east-1:123456789012:function:notification-service"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns.amazonaws.com"
      ],
      "Resource": [
        "Publish:arn:aws:sns:us-east-1:123456789012:order-notifications"
      ]
    }
  ]
})
  
  tags = {
    GeneratedBy = "AdaPol"
    Function    = "notification-service"
    RiskReduction = "95.0%"
  }
}

resource "aws_iam_role_policy_attachment" "notification_service_policy_attachment" {
  policy_arn = aws_iam_policy.notification_service_least_privilege_policy.arn
  role       = aws_iam_role.notification_service_execution_role.name
}
