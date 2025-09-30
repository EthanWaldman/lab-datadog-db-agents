# Define the Datadog configuration templates to be inserted into the agent containers at deployment time
locals {
  dd_autodiscovery_postgres_config_yaml = <<EOI
ad_identifiers:
  - _dbm_postgres
init_config:
instances:
  - dbm: true
    host: "%%host%%"
    port: "%%port%%"
    username: "%%env_DD_RDS_DB_USERNAME%%"
    password: "%%env_DD_RDS_DB_PASSWORD%%"
    database_autodiscovery:
      enabled: true
    collect_schemas:
      enabled: true
EOI

  dd_static_postgres_config_yaml = <<EOI
init_config:
instances:
  - dbm: true
    host: "%%env_DD_RDS_ENDPOINT%%"
    port: "%%env_DD_RDS_PORT%%"
    username: "%%env_DD_RDS_DB_USERNAME%%"
    password: "%%env_DD_RDS_DB_PASSWORD%%"
    aws:
      instance_endpoint: "%%env_DD_RDS_ENDPOINT%%"
      region: "%%env_DD_RDS_REGION%%"
    collect_schemas:
      enabled: true
EOI

  dd_datadog_config_yaml = <<EOI
ec2_prefer_imdsv2: true
cloud_provider_metadata:
  - aws
  - ecs
database_monitoring:
  autodiscovery:
    rds:
      enabled: true
      discovery_interval: 300
      tags: []
EOI

  postgres_config_yaml = var.autodiscovery_enabled ? local.dd_autodiscovery_postgres_config_yaml : local.dd_static_postgres_config_yaml

  entry_point_command = var.autodiscovery_enabled ? "echo $CONFIGFILE_POSTGRES | base64 -d > /etc/datadog-agent/conf.d/postgres.d/conf.yaml;echo $CONFIGFILE_DATADOG | base64 -d > /etc/datadog-agent/datadog.yaml; entrypoint.sh" : "echo $CONFIGFILE_POSTGRES | base64 -d > /etc/datadog-agent/conf.d/postgres.d/conf.yaml; entrypoint.sh"
}

# Retrieve Datadog API Key from AWS Secrets Manager
data "aws_secretsmanager_secret" "dd_api_key" {
  name = "lab_dd_api_key"
}
data "aws_secretsmanager_secret_version" "dd_api_key" {
  secret_id = data.aws_secretsmanager_secret.dd_api_key.id
}

# Retrieve Postgresql password for datadog user from AWS Secrets Manager
data "aws_secretsmanager_secret" "dd_db_password" {
  name = "lab_dd_db_password"
}
data "aws_secretsmanager_secret_version" "dd_db_password" {
  secret_id = data.aws_secretsmanager_secret.dd_db_password.id
}

# KNOWN ISSUE: The autodiscovery functionality for Datadog agents does not work when running on Fargate
#              due to lack of access to the AWS IMDS API; Datadog documentation indicates this problem
#              and there are suggested fixes that have not proven to work so this is still under
#              investigation
# Work-around: Use Terraform to scan the AWS RDS inventory and provision static agents in order
#              to avoid manually configuring every database (i.e., "poor man's autodiscovery")
data "aws_rds_clusters" "rds_cluster_list" {
  region = var.aws_region
}
data "aws_rds_cluster" "rds_cluster_list" {
  for_each = toset(data.aws_rds_clusters.rds_cluster_list.cluster_identifiers)

  cluster_identifier = each.value
}
data "aws_db_instances" "rds_instance_list" {
  region = var.aws_region
}
data "aws_db_instance" "rds_instance_list" {
  for_each = toset(data.aws_db_instances.rds_instance_list.instance_identifiers)

  db_instance_identifier = each.value
}
# Terraform inventory discovery will filter on the basis of a tag set to true (default is
# datadoghq.com/scrape to match real autodiscovery default behavior); when the monitoring_tag_flag
# is set to an empty string, no filtering will take place and all discovered databases will be monitored
locals {
  rds_aurora_cluster_list = var.monitoring_tag_flag == "" ? {
    for dbkey,dbdetails in data.aws_rds_cluster.rds_cluster_list:
    dbkey => ({"endpoint" = dbdetails.endpoint, "port" = dbdetails.port, "engine" = dbdetails.engine})
  } : {
    for dbkey,dbdetails in data.aws_rds_cluster.rds_cluster_list:
    dbkey => ({"endpoint" = dbdetails.endpoint, "port" = dbdetails.port, "engine" = dbdetails.engine}) if try(dbdetails.tags[var.monitoring_tag_flag],"") == "true"
  }
  rds_db_instance_list = var.monitoring_tag_flag == "" ? {
    for dbkey,dbdetails in data.aws_db_instance.rds_instance_list:
    dbkey => ({"endpoint" = split(":",dbdetails.endpoint)[0], "port" = dbdetails.port, "engine" = dbdetails.engine}) if startswith(dbdetails.engine,"postgres")
  } : {
    for dbkey,dbdetails in data.aws_db_instance.rds_instance_list:
    dbkey => ({"endpoint" = split(":",dbdetails.endpoint)[0], "port" = dbdetails.port, "engine" = dbdetails.engine}) if startswith(dbdetails.engine,"postgres") && try(dbdetails.tags[var.monitoring_tag_flag],"") == "true"
  }
  postgres_db_list = merge(local.rds_aurora_cluster_list,local.rds_db_instance_list)
}
output "postgres_db_list" {
  value = local.postgres_db_list
}

# Default behavio will be to use the same VPC where RDS databases are located, but if the
# dedicated_vpc_flag is set, a separate VPC for monitoring will be provisioned instead
resource "aws_vpc" "monitoring" {
  count = var.dedicated_vpc_flag ? 1 : 0

  cidr_block = "172.32.0.0/16"
  enable_dns_hostnames = true

  tags = {
    name = "Monitoring VPC"
  }
}
locals {
  monitoring_vpc_id = var.dedicated_vpc_flag ? aws_vpc.monitoring[0].id : var.rds_vpc_id
}

# A separate public subnet for ECS will be provisioned for the Datadog agents since they need
# outbound access to the Internet to reach Datadog APIs but we want to keep RDS isolated
resource "aws_subnet" "ecs_public" {
  vpc_id            = local.monitoring_vpc_id
  cidr_block        = var.ecs_cidr_block
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    subnet_function = "Monitoring"
  }
}

# Provision the ECS Cluster on Fargate to run the Datadog agents
resource "aws_ecs_cluster" "dd_fargate_cluster" {
  name = "dd-fargate-cluster"
}

# Because the ECS subnet will need Internet access, provision an Internet Gateway
resource "aws_internet_gateway" "monitoring_igw" {
  count = var.dedicated_vpc_flag ? 1 : 0

  vpc_id = aws_vpc.monitoring[0].id
}
data "aws_internet_gateway" "rds_igw" {
  filter {
    name = "attachment.vpc-id"
    values = [var.rds_vpc_id]
  }
}
locals {
  monitoring_igw = var.dedicated_vpc_flag ? aws_internet_gateway.monitoring_igw[0].id : data.aws_internet_gateway.rds_igw.id
}

# Provision the default route to the Internet for the ECS public subnet
resource "aws_route_table" "monitoring" {
  vpc_id = local.monitoring_vpc_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = local.monitoring_igw
  }
}
resource "aws_route_table_association" "public_1a_assoc" {
  subnet_id      = aws_subnet.ecs_public.id
  route_table_id = aws_route_table.monitoring.id
}
resource "aws_security_group" "ecs_service_sg" {
  name   = "dd-ecs-service-sg"
  vpc_id = local.monitoring_vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create a clean IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "dd-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Attach to the clean IAM role standard ECS task execution permissions
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
# Additionally attach the permissions required for auto-discovery (which currently is not used)
resource "aws_iam_role_policy_attachment" "rds_readonly_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

# # Attach Service policy to the execution role
# resource "aws_iam_role_policy_attachment" "ecs_service_role_policy" {
#   role       = aws_iam_role.ecs_task_execution_role.name
#   policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy"
# }

# Create Service policy to also attach to the IAM role (intent is narrower permissions than default policy)
resource "aws_iam_role_policy" "ecs_service_policy" {
  name = "dd-ecs-service-policy"
  role = aws_iam_role.ecs_task_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
                "ec2:AttachNetworkInterface",
                "ec2:CreateNetworkInterface",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteNetworkInterfacePermission",
                "ec2:Describe*",
                "ec2:DetachNetworkInterface",
                "servicediscovery:DeregisterInstance",
                "servicediscovery:Get*",
                "servicediscovery:List*",
                "servicediscovery:RegisterInstance",
                "servicediscovery:UpdateInstanceCustomHealthStatus",
                "secretsmanager:Get*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create an additional policy for ECS Exec in ECS containers - this is needed only for troubleshooting
# Note: This may not be compliant with corporate security standards so it probably should be removed
resource "aws_iam_role_policy" "ecs_exec_policy" {
  name = "dd-ecs-exec-policy"
  role = aws_iam_role.ecs_task_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create a CloudWatch Log Group for Datadog agent container logs
resource "aws_cloudwatch_log_group" "dd_app_logs" {
  name              = "/ecs/dd-ecs-app"
  retention_in_days = 3
}

# If autodiscovery is enabled (currently does not work) then create a single task definition to discover
# all database targets in the current AWS account and in the assigned region
resource "aws_ecs_task_definition" "postgres_dd_agent_autodiscovery" {
  count = var.autodiscovery_enabled ? 1 : 0

  family                   = "dd-agent-postgres-task"
  cpu                      = var.task_specs["agent"].vcpu
  memory                   = var.task_specs["agent"].memory_mb
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = jsonencode([
    {
      name  = "datadog-agent-postgresql"
      image = "${var.container_image["agent"].image_name}:${var.container_image["agent"].image_version}"
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dd_app_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent"
        }
      }
      command = [
        "sh",
        "-c",
        local.entry_point_command
      ]
      secrets = [
        { name = "DD_API_KEY", valueFrom = data.aws_secretsmanager_secret_version.dd_api_key.arn },
        { name = "DD_RDS_DB_PASSWORD", valueFrom = data.aws_secretsmanager_secret_version.dd_db_password.arn }
      ]
      environment = [
        { name = "DD_DD_URL", value = var.dd_api_endpoint },
#        { name = "DD_EC2_PREFER_IMDSV2", value = "true" },
        { name = "AWS_EC2_METADATA_DISABLED", value = "true" },
        { name = "DD_LOG_LEVEL", value = "debug" },
        { name = "ECS_FARGATE", value = "true"  },
        { name = "AWS_REGION", value = "us-east-1"  },
#        { name = "DD_COLLECT_ECS_METADATA", value = "true"  },
        { name = "CONFIGFILE_POSTGRES", value = base64encode(local.postgres_config_yaml) },
        { name = "CONFIGFILE_DATADOG", value = base64encode(local.dd_datadog_config_yaml) },
        { name = "DD_RDS_DB_USERNAME", value = var.dd_db_username },
      ]
    }
  ])
}
# When NOT using autodiscovery (only option currently working) then use the previously discovered
# list of RDS and Aurora databases to configure one task definition per database monitoring target
resource "aws_ecs_task_definition" "postgres_dd_agent_static" {
  for_each                 = var.autodiscovery_enabled ? {} : local.postgres_db_list

  family                   = "dd-agent-postgres-task"
  cpu                      = var.task_specs["agent"].vcpu
  memory                   = var.task_specs["agent"].memory_mb
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = jsonencode([
    {
      name  = "datadog-agent-postgresql"
      image = "${var.container_image["agent"].image_name}:${var.container_image["agent"].image_version}"
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dd_app_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "${each.key}"
        }
      }
      command = [
        "sh",
        "-c",
        local.entry_point_command
      ]
      secrets = [
        { name = "DD_API_KEY", valueFrom = data.aws_secretsmanager_secret_version.dd_api_key.arn },
        { name = "DD_RDS_DB_PASSWORD", valueFrom = data.aws_secretsmanager_secret_version.dd_db_password.arn }
      ]
      environment = [
        { name = "DD_DD_URL", value = var.dd_api_endpoint },
        { name = "CONFIGFILE_POSTGRES", value = base64encode(local.postgres_config_yaml) },
        { name = "DD_RDS_ENDPOINT", value = "${each.value.endpoint}" },
        { name = "DD_RDS_PORT", value = "${tostring(each.value.port)}" },
        { name = "DD_RDS_DB_USERNAME", value = var.dd_db_username },
        { name = "DD_RDS_REGION", value = var.aws_region },
      ]
    }
  ])
}

# If autodiscovery is enabled (currently does not work) then create a single ECS service to discover
# all database targets in the current AWS account and in the assigned region
resource "aws_ecs_service" "postgres_dd_agent_autodiscovery" {
  count = var.autodiscovery_enabled ? 1 : 0

#  for_each        = var.postgres_db_list

#  name            = "dd-agent-${each.key}"
  name            = "dd-agent"
  cluster         = aws_ecs_cluster.dd_fargate_cluster.id
#  task_definition = aws_ecs_task_definition.postgres_dd_agent[each.key].arn
  task_definition = aws_ecs_task_definition.postgres_dd_agent_autodiscovery[0].arn
  launch_type     = "FARGATE"
  desired_count   = var.task_specs["agent"].count
  enable_execute_command = true
  # iam_role        = aws_iam_role.ecs_task_execution_role.arn
  depends_on      = [
                      aws_iam_role_policy_attachment.ecs_task_execution_role_policy,
                    ]

  network_configuration {
    subnets         = [aws_subnet.ecs_public.id]
    security_groups = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = true
  }
}
# When NOT using autodiscovery (only option currently working) then use the previously discovered
# list of RDS and Aurora databases to provisoin ECS service per database monitoring target
resource "aws_ecs_service" "postgres_dd_agent_static" {
  for_each        = var.autodiscovery_enabled ? {} : local.postgres_db_list

  name            = "dd-agent-${each.key}"
  cluster         = aws_ecs_cluster.dd_fargate_cluster.id
  task_definition = aws_ecs_task_definition.postgres_dd_agent_static[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = var.task_specs["agent"].count
  enable_execute_command = true
  # iam_role        = aws_iam_role.ecs_task_execution_role.arn
  depends_on      = [
                      aws_iam_role_policy_attachment.ecs_task_execution_role_policy,
                    ]

  network_configuration {
    subnets         = [aws_subnet.ecs_public.id]
    security_groups = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = true
  }
}

