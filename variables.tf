# Terraform provisioning is constrained to a single AWS account and region
variable "aws_region" {
  type = string
  default = "us-east-1"
}

# Manual assignment of the RDS VPC where the databases to monitor are located and where, by default,
# the ECS cluster and services will be provisioned
variable "rds_vpc_id" {
  type = string
  default = "vpc-0b54f6bbcb3b174f2"
}

# Manual assignment of CIDR block for the public ECS subnet where agents will run
variable "ecs_cidr_block" {
  type = string
  default = "10.0.4.0/24"
}

# When set to true, provision for Datadog autodiscovery (which currently does NOT work)
variable "autodiscovery_enabled" {
  type = bool
  default = false
}

# When set to true, provision a separate VPC to contain the ECS subnet and keep outbound Internet
# traffic off of the RDS VPC (e.g., as a method for tracking via Flow Logs)
variable "dedicated_vpc_flag" {
  type = bool
  default = false
}

# When string is populated, use as a tag filter to only select databases for monitoring if named tag
# is set to true (default value matches the behavior of Datadog autodiscovery)
variable "monitoring_tag_flag" {
  type = string
  default = "datadoghq.com/scrape"
}

# Specifications for ECS tasks - defaults probably would not require any change
variable "task_specs" {
  type = map(object({
    count = number
    vcpu = number
    memory_mb = number
  }))
  default = {
    agent = {
      count = 1
      vcpu = 256
      memory_mb = 512
    }
  }
}

# Datadog agent container image details, including version to be kept up-to-date over time
variable "container_image" {
  type = map(object({
    image_name = string
    image_version = string
  }))
  default = {
    agent = {
      image_name = "gcr.io/datadoghq/agent"
      image_version = "7.69.3-rc.1-linux"
    }
  }
}

# Username for agent authentication to Postgres databases (password to be kept in Secrets Manager)
variable "dd_db_username" {
  type = string
  default = "datadog"
}

# API endpoint for Datadog
variable "dd_api_endpoint" {
  type = string
  default = "https://us3.datadoghq.com"
}

