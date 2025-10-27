provider "aws" {
  region = "ap-south-1"

  assume_role {
    role_arn = "arn:aws:iam::580069881439:role/tfc-eks-execution-role"
  }
}
