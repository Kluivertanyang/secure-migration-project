# iam.tf
data "aws_caller_identity" "me" {}

resource "aws_iam_role" "ec2_ssm_role" {
  name = "${var.project}-ec2-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

# Attach AWS managed SSM core policy (allows SSM agent to register)
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Inline policy for S3/KMS access (least privilege for uploader)
resource "aws_iam_policy" "ec2_s3_kms_policy" {
  name = "${var.project}-ec2-s3-kms-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowPutGetListRawBucket",
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = [
          "arn:aws:s3:::${var.raw_bucket_name}",
          "arn:aws:s3:::${var.raw_bucket_name}/*"
        ]
      },
      {
        Sid    = "AllowKMSUseForS3",
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = [
          aws_kms_key.s3_key.arn
        ]
        # depends_on = [module.kms]
      },
      {
        Sid    = "AllowCloudWatchLogs",
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowSSMSendCommandIfUsed",
        Effect = "Allow",
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_s3_kms" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = aws_iam_policy.ec2_s3_kms_policy.arn
}

# resource "aws_iam_instance_profile" "ec2_instance_profile" {
#   name = "${var.project}-ec2-profile"
#   role = aws_iam_role.ec2_ssm_role.name
# }
