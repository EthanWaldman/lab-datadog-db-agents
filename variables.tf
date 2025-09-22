variable "aws_region" {
  type = string
  default = "us-east-1"
}
variable "lab_vpc_id" {
  type = string
  default = "vpc-0bd55969a85ec8720"
}
variable "cidr_block_range_1a" {
  type = string
  default = "172.31.98.0/24"
}
variable "cidr_block_range_1b" {
  type = string
  default = "172.31.99.0/24"
}
variable "task_count" {
  type = number
  default = 1
}
variable "task_cpu_units" {
  type = number
  default = 256
}
variable "task_memory_mb" {
  type = number
  default = 512
}
variable "dd_container_image" {
  type = string
  default = "gcr.io/datadoghq/agent"
}
variable "dd_container_version" {
  type = string
  default = "7.69.3-rc.1-linux"
}
variable "ecs_subnet" {
  type = string
  default = "subnet-058cd8b1961070b9b"
}
variable "ecs_security_group" {
  type = string
  default = "sg-07d3da5d3e3c948f3"
}

variable "postgres_db_list" {
  type = map(object({
    rds_endpoint = string
    rds_port = string
    rds_region = string
  }))
  default = {
    lab = {
      rds_endpoint = "ddlabdb.clgyiws0up99.us-east-1.rds.amazonaws.com"
      # rds_endpoint = "labdb.clgyiws0up99.us-east-1.rds.amazonaws.com"
      rds_port = "5432"
      rds_region = "us-east-1"
    }
  }
}

