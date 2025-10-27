resource "aws_s3_bucket" "raw_data" {
  bucket = "${var.project}-raw-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.raw_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.raw_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}
data "aws_caller_identity" "current" {}
# Restrict access to only VPC Endpoint
# resource "aws_s3_bucket_policy" "allow_role_user" {
#   bucket = aws_s3_bucket.raw_data.id

#   policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Sid = "AllowTerraformRoleAndUser",
#         Effect = "Allow",
#         Principal = {
#           AWS = [
#             "arn:aws:iam::580069881439:role/tfc-eks-execution-role",
#             "arn:aws:iam::580069881439:user/infra-architect-user"
#           ]
#         },
#         Action = "s3:*",
#         Resource = [
#           aws_s3_bucket.raw_data.arn,
#           "${aws_s3_bucket.raw_data.arn}/*"
#         ]
#       }
#     ]
#   })
# }
resource "aws_s3_bucket_policy" "allow_role_user" {
  bucket = aws_s3_bucket.raw_data.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Allow all actions for your role and user
      {
        Sid = "AllowTerraformRoleAndUser",
        Effect = "Allow",
        Principal = {
          AWS = [
            "arn:aws:iam::580069881439:role/tfc-eks-execution-role",
            "arn:aws:iam::580069881439:user/infra-architect-user"
          ]
        },
        Action = "s3:*",
        Resource = [
          aws_s3_bucket.raw_data.arn,
          "${aws_s3_bucket.raw_data.arn}/*"
        ]
      },
      # Deny any upload that does NOT use SSE-KMS encryption
      {
        Sid = "DenyUnencryptedPutObject",
        Effect = "Deny",
        Principal = "*",
        Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.raw_data.arn}/*",
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

