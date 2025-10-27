variable "region" {
  default = "ap-south-1"
}

variable "project" {
  default = "secure-dataflow"
}

variable "vpc_id" {
  default = "vpc-05172adce96edf32c"
}

variable "private_subnet_id" {
  description = "Private subnet where EC2 will reside"
  type        = string
}

variable "private_route_table_ids" {
  description = "Route table IDs for the private subnet"
  type        = list(string)
}

variable "kms_alias" {
  default = "alias/s3-secure-key"
}
variable "instance_type" {
  default = "t2.micro"
  type    = string
}
variable "raw_bucket_name" {
  default = "secure-dataflow-raw-bucket"
  type    = string
}
variable "ACCOUNT_ID" {
  description = "AWS Account ID"
  type        = string
}
