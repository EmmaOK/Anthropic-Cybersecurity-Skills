terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.40" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # Recommended: remote state. Fill in and uncomment.
  # backend "s3" {
  #   bucket = "my-tf-state"
  #   key    = "phantom/terraform.tfstate"
  #   region = "us-east-1"
  #   dynamodb_table = "my-tf-locks"
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "phantom", ManagedBy = "terraform", Environment = var.environment }
  }
}
