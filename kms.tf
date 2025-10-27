resource "aws_kms_key" "s3_key" {
  description             = "KMS key for encrypting S3 data"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "s3_alias" {
  name          = var.kms_alias
  target_key_id = aws_kms_key.s3_key.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.s3_key.arn
}
