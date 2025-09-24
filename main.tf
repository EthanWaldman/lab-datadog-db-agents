locals {
  dd_postgres_config_json = <<EOI
{
  "postgres": {
    "init_config": {},
    "instances": [
      {
        "dbm": true,
        "host": "%%env_DD_RDS_ENDPOINT%%",
        "port": "%%env_DD_RDS_PORT%%",
        "username": "datadog",
        "password": "%%env_DD_RDS_DB_PASSWORD%%",
        "aws": {
          "instance_endpoint": "%%env_DD_RDS_ENDPOINT%%",
          "region": "%%env_DD_RDS_REGION%%"
        },
        "tags": [
          "dbinstanceidentifier:postgres"
        ],
        "collect_schemas": {
          "enabled": true
        }
      }
    ]
  }
}
EOI
}

resource "aws_vpc" "monitoring" {
  cidr_block = "172.32.0.0/16"
  enable_dns_hostnames = true

  tags = {
    name = "Monitoring VPC"
  }
}

resource "aws_subnet" "ecs_public" {
  vpc_id            = aws_vpc.monitoring.id
  cidr_block        = "172.32.1.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
}
### resource "aws_subnet" "rds_private_1" {
###   vpc_id            = aws_vpc.monitoring.id
###   cidr_block        = "172.32.2.0/24"
###   availability_zone = "us-east-1a"
### }
### resource "aws_subnet" "rds_private_2" {
###   vpc_id            = aws_vpc.monitoring.id
###   cidr_block        = "172.32.3.0/24"
###   availability_zone = "us-east-1b"
### }
### resource "aws_security_group" "dd_ec2_sg" {
###   vpc_id = aws_vpc.monitoring.id
###   ingress {
###     from_port   = 22
###     to_port     = 22
###     protocol    = "tcp"
###     cidr_blocks = ["0.0.0.0/0"]
###   }
###   egress {
###     from_port   = 443
###     to_port     = 443
###     protocol    = "tcp"
###     cidr_blocks = ["0.0.0.0/0"]
###   }
###   egress {
###     from_port   = 5432
###     to_port     = 5432
###     protocol    = "tcp"
###     cidr_blocks = [aws_subnet.rds_private_1.cidr_block, aws_subnet.rds_private_2.cidr_block]
###   }
### }
### resource "aws_security_group" "dd_rds_sg" {
###   vpc_id = aws_vpc.monitoring.id
###   ingress {
###     from_port   = 5432
###     to_port     = 5432
###     protocol    = "tcp"
###     cidr_blocks = [
###       aws_subnet.ec2_public.cidr_block,
###       var.cidr_block_range_1a,
###       var.cidr_block_range_1b
###     ]
###   }
### }
### resource "aws_db_subnet_group" "rds_subnet_group" {
###   name       = "rds-subnet-group"
###   subnet_ids = [aws_subnet.rds_private_1.id, aws_subnet.rds_private_2.id]
### }
### resource "aws_db_instance" "ddlabdb" {
###   identifier              = "ddlabdb"
###   engine                 = "postgres"
###   engine_version         = "16.9"
###   instance_class         = "db.t3.micro"
###   allocated_storage       = 20
###   username               = "postgres"
###   password               = "SecretSecret"  # Change to a secure password
###   db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
###   vpc_security_group_ids = [aws_security_group.dd_rds_sg.id]
###   skip_final_snapshot    = true
### }
### resource "aws_instance" "dd_ec2" {
###   ami           = "ami-00ca32bbc84273381"  # Change to a valid AMI ID
###   instance_type = "t2.micro"
###   subnet_id     = aws_subnet.ec2_public.id
###   vpc_security_group_ids = [aws_security_group.dd_ec2_sg.id]
###   tags = {
###     Name = "DDLabEC2Instance"
###   }
### }


# Create an ECS Cluster
resource "aws_ecs_cluster" "dd_fargate_cluster" {
  name = "dd-fargate-cluster"
}

### resource "aws_internet_gateway" "igw" {
###   vpc_id = data.aws_vpc.main.id
### }
### resource "aws_route_table" "public" {
###   vpc_id = data.aws_vpc.main.id
### 
###   route {
###     cidr_block = "0.0.0.0/0"
###     gateway_id = aws_internet_gateway.igw.id
###   }
### }
### resource "aws_subnet" "public_1a" {
###   vpc_id                  = data.aws_vpc.main.id
###   cidr_block              = var.cidr_block_range_1a
###   availability_zone       = "us-east-1a"
###   map_public_ip_on_launch = true
### 
###   tags = {
###     Name = "dd-agent-subnet-1a"
###   }
### }
### resource "aws_subnet" "public_1b" {
###   vpc_id                  = data.aws_vpc.main.id
###   cidr_block              = var.cidr_block_range_1b
###   availability_zone       = "us-east-1b"
###   map_public_ip_on_launch = true
### 
###   tags = {
###     Name = "dd-agent-subnet-1b"
###   }
### }

resource "aws_internet_gateway" "monitoring_igw" {
  vpc_id = aws_vpc.monitoring.id
}
resource "aws_route_table" "monitoring" {
  vpc_id = aws_vpc.monitoring.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.monitoring_igw.id
  }
}
resource "aws_route_table_association" "public_1a_assoc" {
  subnet_id      = aws_subnet.ecs_public.id
  route_table_id = aws_route_table.monitoring.id
}
resource "aws_security_group" "ecs_service_sg" {
  name   = "dd-ecs-service-sg"
  vpc_id = aws_vpc.monitoring.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create an IAM Role for ECS Task Execution
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

# Attach Task Execution policy to the execution role
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# # Attach Service policy to the execution role
# resource "aws_iam_role_policy_attachment" "ecs_service_role_policy" {
#   role       = aws_iam_role.ecs_task_execution_role.name
#   policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy"
# }

# Create Service policy to the execution role
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
                "servicediscovery:UpdateInstanceCustomHealthStatus"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create policy for ECS Exec in ECS containers
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

# Create a CloudWatch Log Group for container logs
resource "aws_cloudwatch_log_group" "dd_app_logs" {
  name              = "/ecs/dd-ecs-app"
  retention_in_days = 3
}

# Define an ECS Task Definition for Fargate
resource "aws_ecs_task_definition" "postgres_dd_agent" {
  for_each                 = var.postgres_db_list

  family                   = "dd-agent-postgres-task"
  cpu                      = "${var.task_cpu_units}"
  memory                   = "${var.task_memory_mb}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = jsonencode([
    {
      name  = "datadog-agent-postgresql"
      image = "${var.dd_container_image}:${var.dd_container_version}"
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dd_app_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "${each.key}"
        }
      }
      dockerLabels = {
        "com.datadoghq.ad.checks" = local.dd_postgres_config_json
      }
      environment = [
        { name = "DD_API_KEY", value = "10991f6198ef2d574ceffe57a44de06f" },
        { name = "DD_DD_URL", value = "https://us3.datadoghq.com" },
        { name = "DD_RDS_ENDPOINT", value = "${each.value.rds_endpoint}" },
        { name = "DD_RDS_PORT", value = "${each.value.rds_port}" },
        { name = "DD_RDS_DB_USERNAME", value = "datadog" },
        { name = "DD_RDS_DB_PASSWORD", value = "KindaSecret" },
        { name = "DD_RDS_REGION", value = "${each.value.rds_region}" },
      ]
    }
  ])
}

# Define an ECS Service
resource "aws_ecs_service" "postgres_dd_agent" {
  for_each        = var.postgres_db_list

  name            = "dd-agent-${each.key}"
  cluster         = aws_ecs_cluster.dd_fargate_cluster.id
  task_definition = aws_ecs_task_definition.postgres_dd_agent[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = var.task_count
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

resource "aws_ecs_task_definition" "debug_task" {
  for_each                 = var.postgres_db_list

  family                   = "debug-task"
  cpu                      = "${var.task_cpu_units}"
  memory                   = "${var.task_memory_mb}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn
  container_definitions    = jsonencode([
    {
      name  = "debug-container"
      image = "busybox:latest"
      command = [ "sleep", "3600" ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dd_app_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "${each.key}"
        }
      }
      dockerLabels = {
        "com.datadoghq.ad.checks" = local.dd_postgres_config_json
      }
      environment = [
        { name = "DD_API_KEY", value = "10991f6198ef2d574ceffe57a44de06f" },
        { name = "DD_DD_URL", value = "https://us3.datadoghq.com" },
        { name = "DD_RDS_ENDPOINT", value = "${each.value.rds_endpoint}" },
        { name = "DD_RDS_PORT", value = "${each.value.rds_port}" },
        { name = "DD_RDS_DB_USERNAME", value = "datadog" },
        { name = "DD_RDS_DB_PASSWORD", value = "KindaSecret" },
        { name = "DD_RDS_REGION", value = "${each.value.rds_region}" },
      ]
    }
  ])
}

# Define an ECS Service
resource "aws_ecs_service" "debug_task" {
  for_each        = var.postgres_db_list

  name            = "debug-${each.key}"
  cluster         = aws_ecs_cluster.dd_fargate_cluster.id
  task_definition = aws_ecs_task_definition.debug_task[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = var.task_count
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
