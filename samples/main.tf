terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

variable "environment" {
  type    = string
  default = "staging"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name   = "app-${var.environment}"
  cidr   = "10.0.0.0/16"
}

resource "aws_security_group" "web" {
  name   = "web-${var.environment}"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "primary" {
  identifier        = "app-db-${var.environment}"
  engine            = "postgres"
  instance_class    = "db.t4g.medium"
  storage_encrypted = false
  password          = "SuperSecretProdPass99!"
  vpc_security_group_ids = [aws_security_group.web.id]
}

output "db_endpoint" {
  value = aws_db_instance.primary.endpoint
}
