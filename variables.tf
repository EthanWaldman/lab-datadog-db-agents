variable "aws_region" {
  type = string
  default = "us-east-1"
}
variable "autodiscovery_enabled" {
  type = bool
  default = false
}
variable "dedicated_vpc_flag" {
  type = bool
  default = false
}
variable "rds_vpc_id" {
  type = string
  default = "vpc-0b54f6bbcb3b174f2"
}
variable "ecs_cidr_block" {
  type = string
  default = "10.0.4.0/24"
}
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

variable "dd_db_username" {
  type = string
  default = "datadog"
}
variable "dd_api_endpoint" {
  type = string
  default = "https://us3.datadoghq.com"
}

variable "postgres_db_list" {
  type = map(object({
    rds_endpoint = string
    rds_port = string
    rds_region = string
  }))
  default = {
    lab = {
      rds_endpoint = "labdb.clgyiws0up99.us-east-1.rds.amazonaws.com"
      rds_port = "5432"
      rds_region = "us-east-1"
    }
  }
}

