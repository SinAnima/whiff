terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.0"
    }
  }

  backend "s3" {
    bucket = "saltmere-terraform-state"
    key    = "harbour/terraform.tfstate"
    region = "eu-west-2"
  }
}

provider "aws" {
  region = var.region
}

# Tide gauge readings.
resource "aws_s3_bucket" "gauge" {
  bucket = "saltmere-tide-gauge"
  tags = {
    Harbour = "Saltmere"
  }
}

resource "aws_s3_bucket_versioning" "gauge" {
  bucket = aws_s3_bucket.gauge.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

data "aws_caller_identity" "current" {}

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
  name    = "harbour"
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "gauge_token" {
  type      = string
  sensitive = true
}

locals {
  policy = <<EOT
{ "Version": "2012-10-17" }
EOT
}

output "bucket" {
  value = aws_s3_bucket.gauge.bucket
}
