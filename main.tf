data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_availability_zones" "azs" {
  filter {
    name   = "zone-type"
    values = [
      "availability-zone"
    ]
  }
}

data "aws_vpc" "vpc" {
  filter {
    name   = "tag:Name"
    values = [
      local.vpc_name
    ]
  }
}

data "aws_subnets" "db_subnets" {
  filter {
    name   = "vpc-id"
    values = [
      data.aws_vpc.vpc.id
    ]
  }

  filter {
    name   = "tag:Name"
    values = [
      local.subnets_pattern
    ]
  }
}

data "aws_rds_engine_version" "engine_versions" {
  engine  = local.engine
  version = var.engine_version
}

data "aws_rds_orderable_db_instance" "orderable_instances" {
  for_each = local.instances

  engine         = local.engine
  engine_version = data.aws_rds_engine_version.engine_versions.version
  instance_class =  each.value.instance_class
  storage_type   = var.storage_type
}

locals {
  aws_region                        = data.aws_region.current.name
  account_id                        = data.aws_caller_identity.current.account_id

  create                            = var.create
  create_db_subnet_group            = true
  create_db_cluster_parameter_group = true
  create_db_parameter_group         = true
  create_security_group             = true
  create_cloudwatch_log_group       = true


  name                          = "${var.project_name}-${var.env_group}-${var.env}-${var.name}"
  vpc_name                      = "${var.project_name}${var.env_group == null ? "" : format("-%s", var.env_group)}"
  vpc_id                        = data.aws_vpc.vpc.id
  availability_zones            = data.aws_availability_zones.azs.names
  subnets                       = data.aws_subnets.db_subnets.ids
  network_type                  = "IPV4"
  port                          = coalesce(var.port, (local.engine == "aurora-postgresql" || local.engine == "postgres" ? 5432 : 3306))
  internal_db_subnet_group_name = try(coalesce(local.db_subnet_group_name, var.name), "")
  db_subnet_group_name          = "${local.name}-${var.subnet_group_name}"
  subnets_pattern               = "*${var.subnet_group_name}*"
  security_group_name           = local.name
  security_group_description    = null
  enable_http_endpoint          = false
  publicly_accessible           = false

  engine                        = "aurora-postgresql"  // Q: What's the difference between aurora-postgresql and postgres engines?  A: postgres is multi-AZ, non-aurora DB
  engine_mode                   = "provisioned"
  cluster_members               = null
  db_cluster_instance_class     = null // Set in instances
  is_serverless                 = local.engine_mode == "serverless" // Always false, for the moment.
  instances                     = { for i in range(1, var.num_instances + 1): i => {
    instance_class      = var.instance_class
    publicly_accessible = local.publicly_accessible
    availability_zone   = local.availability_zones[(i - 1) % length(local.availability_zones)]
  }}
  // It would be quicker to not do this but we'll keep it for if the instance class becomes variable again.
  validated_instances           = { for k, v in local.instances: k => merge(v, { instance_class = data.aws_rds_orderable_db_instance.orderable_instances[k].instance_class }) }
  iops                          = null
  allocated_storage             = null // Storage is managed automatically by Aurora
  master_username               = "postgres"
  master_password               = null
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_alias.master_password[0].arn
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.storage[0].arn
  backtrack_window              = (local.engine == "aurora-mysql" || local.engine == "aurora") && local.engine_mode != "serverless" ? var.backtrack_window : 0

  performance_insights_enabled    = var.performance_insights_enabled == null ? false : var.performance_insights_enabled
  performance_insights_kms_key_id = aws_kms_key.performance_insights[0].arn

  db_cluster_db_instance_parameter_group_name = local.name
  db_cluster_parameter_group_name             = local.name
  db_cluster_parameter_group_family           = data.aws_rds_engine_version.engine_versions.parameter_group_family
  db_cluster_parameter_group_description      = "${local.name} parameter group"
  cluster_parameter_group_name                = try(coalesce(local.db_cluster_parameter_group_name, local.name), null)
  db_parameter_group_name                     = local.name
  db_parameter_group_family                   = data.aws_rds_engine_version.engine_versions.parameter_group_family
  db_parameter_group_description              = "${local.name} parameter group"
  enabled_cloudwatch_logs_exports             = data.aws_rds_engine_version.engine_versions.exportable_log_types

  common_tags  = {
    Name              = local.name
    Cluster-Name      = var.name
    Project           = var.project_name
    Environment-Group = var.env_group
    environment       = var.env
    cost-centre       = var.cost_centre
    application       = var.application
    owner             = var.owner
  }
  cluster_tags = merge(var.cluster_tags, local.common_tags)
  tags         = merge(var.tags, local.common_tags)
}

################################################################################
# DB Subnet Group
################################################################################

resource "aws_db_subnet_group" "this" {
  count = local.create && local.create_db_subnet_group ? 1 : 0

  name        = local.internal_db_subnet_group_name
  description = "For Aurora cluster ${local.name}"
  subnet_ids  = local.subnets

  tags = merge(local.tags, {
    Name = local.internal_db_subnet_group_name
  })
}

################################################################################
# Cluster
################################################################################

resource "aws_rds_cluster" "this" {
  count = local.create ? 1 : 0

  allocated_storage                   = local.allocated_storage
  allow_major_version_upgrade         = var.allow_major_version_upgrade
  apply_immediately                   = var.apply_immediately
  availability_zones                  = local.availability_zones
  backup_retention_period             = var.backup_retention_period
  backtrack_window                    = local.backtrack_window
  cluster_identifier                  = var.cluster_use_name_prefix ? null : local.name
  cluster_identifier_prefix           = var.cluster_use_name_prefix ? "${local.name}-" : null
  cluster_members                     = local.cluster_members
  copy_tags_to_snapshot               = var.copy_tags_to_snapshot
  database_name                       = var.is_primary_cluster ? var.database_name : null
  db_cluster_instance_class           = local.db_cluster_instance_class
  db_cluster_parameter_group_name     = local.create_db_cluster_parameter_group ? aws_rds_cluster_parameter_group.this[0].id : local.db_cluster_parameter_group_name
  db_instance_parameter_group_name    = var.allow_major_version_upgrade ? local.db_cluster_db_instance_parameter_group_name : null
  db_subnet_group_name                = local.db_subnet_group_name
  deletion_protection                 = var.deletion_protection
  enable_global_write_forwarding      = var.enable_global_write_forwarding
  enabled_cloudwatch_logs_exports     = local.enabled_cloudwatch_logs_exports
  enable_http_endpoint                = local.enable_http_endpoint
  engine                              = local.engine
  engine_mode                         = local.engine_mode
  engine_version                      = var.engine_version
  final_snapshot_identifier           = var.final_snapshot_identifier
  global_cluster_identifier           = var.global_cluster_identifier
  iam_database_authentication_enabled = var.iam_database_authentication_enabled
  # iam_roles has been removed from this resource and instead will be used with aws_rds_cluster_role_association below to avoid conflicts per docs
  iops                          = local.iops
  kms_key_id                    = local.kms_key_id
  manage_master_user_password   = var.global_cluster_identifier == null && local.manage_master_user_password ? local.manage_master_user_password : null
  master_user_secret_kms_key_id = var.global_cluster_identifier == null && local.manage_master_user_password ? local.master_user_secret_kms_key_id : null
  master_password               = var.is_primary_cluster && !local.manage_master_user_password ? local.master_password : null
  master_username               = var.is_primary_cluster ? local.master_username : null
  network_type                  = local.network_type
  port                          = local.port
  preferred_backup_window       = local.is_serverless ? null : var.preferred_backup_window
  preferred_maintenance_window  = local.is_serverless ? null : var.preferred_maintenance_window
  replication_source_identifier = var.replication_source_identifier

  dynamic "restore_to_point_in_time" {
    for_each = length(var.restore_to_point_in_time) > 0 ? [var.restore_to_point_in_time] : []

    content {
      restore_to_time            = try(restore_to_point_in_time.value.restore_to_time, null)
      restore_type               = try(restore_to_point_in_time.value.restore_type, null)
      source_cluster_identifier  = restore_to_point_in_time.value.source_cluster_identifier
      use_latest_restorable_time = try(restore_to_point_in_time.value.use_latest_restorable_time, null)
    }
  }

  dynamic "s3_import" {
    for_each = length(var.s3_import) > 0 && !local.is_serverless ? [var.s3_import] : []

    content {
      bucket_name           = s3_import.value.bucket_name
      bucket_prefix         = try(s3_import.value.bucket_prefix, null)
      ingestion_role        = s3_import.value.ingestion_role
      source_engine         = "mysql"
      source_engine_version = s3_import.value.source_engine_version
    }
  }

  dynamic "scaling_configuration" {
    for_each = length(var.scaling_configuration) > 0 && local.is_serverless ? [var.scaling_configuration] : []

    content {
      auto_pause               = try(scaling_configuration.value.auto_pause, null)
      max_capacity             = try(scaling_configuration.value.max_capacity, null)
      min_capacity             = try(scaling_configuration.value.min_capacity, null)
      seconds_until_auto_pause = try(scaling_configuration.value.seconds_until_auto_pause, null)
      timeout_action           = try(scaling_configuration.value.timeout_action, null)
    }
  }

  dynamic "serverlessv2_scaling_configuration" {
    for_each = length(var.serverlessv2_scaling_configuration) > 0 && local.engine_mode == "provisioned" ? [var.serverlessv2_scaling_configuration] : []

    content {
      max_capacity = serverlessv2_scaling_configuration.value.max_capacity
      min_capacity = serverlessv2_scaling_configuration.value.min_capacity
    }
  }

  skip_final_snapshot    = var.skip_final_snapshot
  snapshot_identifier    = var.snapshot_identifier
  source_region          = var.source_region
  storage_encrypted      = local.storage_encrypted
  storage_type           = var.storage_type
  tags                   = merge(local.tags, local.cluster_tags)
  vpc_security_group_ids = compact(concat([try(aws_security_group.this[0].id, "")], var.vpc_security_group_ids))

  timeouts {
    create = try(var.cluster_timeouts.create, null)
    update = try(var.cluster_timeouts.update, null)
    delete = try(var.cluster_timeouts.delete, null)
  }

  lifecycle {
    ignore_changes = [
      # See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#replication_source_identifier
      # Since this is used either in read-replica clusters or global clusters, this should be acceptable to specify
      replication_source_identifier,
      # See docs here https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_global_cluster#new-global-cluster-from-existing-db-cluster
      global_cluster_identifier,
      snapshot_identifier,
    ]
  }

  depends_on = [aws_cloudwatch_log_group.this]
}

################################################################################
# Cluster Instance(s)
################################################################################

resource "aws_rds_cluster_instance" "this" {
  for_each = { for k, v in local.instances : k => v if local.create && !local.is_serverless }

  apply_immediately                     = try(each.value.apply_immediately, var.apply_immediately)
  auto_minor_version_upgrade            = try(each.value.auto_minor_version_upgrade, var.auto_minor_version_upgrade)
  availability_zone                     = try(each.value.availability_zone, null)
  ca_cert_identifier                    = var.ca_cert_identifier
  cluster_identifier                    = aws_rds_cluster.this[0].id
  copy_tags_to_snapshot                 = try(each.value.copy_tags_to_snapshot, var.copy_tags_to_snapshot)
  db_parameter_group_name               = local.create_db_parameter_group ? aws_db_parameter_group.this[0].id : local.db_parameter_group_name
  db_subnet_group_name                  = local.db_subnet_group_name
  engine                                = local.engine
  engine_version                        = var.engine_version
  identifier                            = var.instances_use_identifier_prefix ? null : try(each.value.identifier, "${local.name}-${each.key}")
  identifier_prefix                     = var.instances_use_identifier_prefix ? try(each.value.identifier_prefix, "${local.name}-${each.key}-") : null
  instance_class                        = try(each.value.instance_class, var.instance_class)
  monitoring_interval                   = try(each.value.monitoring_interval, var.monitoring_interval)
  monitoring_role_arn                   = var.create_monitoring_role ? try(aws_iam_role.rds_enhanced_monitoring[0].arn, null) : var.monitoring_role_arn
  performance_insights_enabled          = try(each.value.performance_insights_enabled, local.performance_insights_enabled)
  performance_insights_kms_key_id       = try(each.value.performance_insights_enabled, local.performance_insights_enabled) ? local.performance_insights_kms_key_id : null
  performance_insights_retention_period = try(each.value.performance_insights_retention_period, var.performance_insights_retention_period)
  # preferred_backup_window - is set at the cluster level and will error if provided here
  preferred_maintenance_window = try(each.value.preferred_maintenance_window, var.preferred_maintenance_window)
  promotion_tier               = try(each.value.promotion_tier, null)
  publicly_accessible          = try(each.value.publicly_accessible, local.publicly_accessible)
  tags                         = merge(local.tags, try(each.value.tags, {}), {
    Name = "${local.name}-${each.key}"
  })

  timeouts {
    create = try(var.instance_timeouts.create, null)
    update = try(var.instance_timeouts.update, null)
    delete = try(var.instance_timeouts.delete, null)
  }
}

################################################################################
# Cluster Endpoint(s)
################################################################################

resource "aws_rds_cluster_endpoint" "this" {
  for_each = { for k, v in var.endpoints : k => v if local.create && !local.is_serverless }

  cluster_endpoint_identifier = each.value.identifier
  cluster_identifier          = aws_rds_cluster.this[0].id
  custom_endpoint_type        = each.value.type
  excluded_members            = try(each.value.excluded_members, null)
  static_members              = try(each.value.static_members, null)
  tags                        = merge(local.tags, try(each.value.tags, {}))

  depends_on = [
    aws_rds_cluster_instance.this
  ]
}

################################################################################
# Cluster IAM Roles
################################################################################

resource "aws_rds_cluster_role_association" "this" {
  for_each = { for k, v in var.iam_roles : k => v if local.create }

  db_cluster_identifier = aws_rds_cluster.this[0].id
  feature_name          = each.value.feature_name
  role_arn              = each.value.role_arn
}

################################################################################
# Enhanced Monitoring
################################################################################

locals {
  create_monitoring_role = local.create && var.create_monitoring_role && var.monitoring_interval > 0
}

data "aws_iam_policy_document" "monitoring_rds_assume_role" {
  count = local.create_monitoring_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = local.create_monitoring_role ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : var.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${var.iam_role_name}-" : null
  description = var.iam_role_description
  path        = var.iam_role_path

  assume_role_policy    = data.aws_iam_policy_document.monitoring_rds_assume_role[0].json
  managed_policy_arns   = var.iam_role_managed_policy_arns
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = var.iam_role_force_detach_policies
  max_session_duration  = var.iam_role_max_session_duration

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = local.create_monitoring_role ? 1 : 0

  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

################################################################################
# Autoscaling
################################################################################

resource "aws_appautoscaling_target" "this" {
  count = local.create && var.autoscaling_enabled && !local.is_serverless ? 1 : 0

  max_capacity       = var.autoscaling_max_capacity
  min_capacity       = var.autoscaling_min_capacity
  resource_id        = "cluster:${aws_rds_cluster.this[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"

  tags = local.tags
}

resource "aws_appautoscaling_policy" "this" {
  count = local.create && var.autoscaling_enabled && !local.is_serverless ? 1 : 0

  name               = var.autoscaling_policy_name
  policy_type        = "TargetTrackingScaling"
  resource_id        = "cluster:${aws_rds_cluster.this[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = var.predefined_metric_type
    }

    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
    target_value       = var.predefined_metric_type == "RDSReaderAverageCPUUtilization" ? var.autoscaling_target_cpu : var.autoscaling_target_connections
  }

  depends_on = [
    aws_appautoscaling_target.this
  ]
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "this" {
  count = local.create && local.create_security_group ? 1 : 0

  name        = var.security_group_use_name_prefix ? null : local.security_group_name
  name_prefix = var.security_group_use_name_prefix ? "${local.security_group_name}-" : null
  vpc_id      = local.vpc_id
  description = coalesce(local.security_group_description, "Control traffic to/from RDS Aurora ${local.name}")

  tags = merge(local.tags, var.security_group_tags, {
    Name = local.security_group_name
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "this" {
  for_each = { for k, v in var.security_group_rules : k => v if local.create && local.create_security_group }

  # required
  type              = try(each.value.type, "ingress")
  from_port         = try(each.value.from_port, local.port)
  to_port           = try(each.value.to_port, local.port)
  protocol          = try(each.value.protocol, "tcp")
  security_group_id = aws_security_group.this[0].id

  # optional
  cidr_blocks              = try(each.value.cidr_blocks, null)
  description              = try(each.value.description, null)
  ipv6_cidr_blocks         = try(each.value.ipv6_cidr_blocks, null)
  prefix_list_ids          = try(each.value.prefix_list_ids, null)
  source_security_group_id = try(each.value.source_security_group_id, null)
}

################################################################################
# Cluster Parameter Group
################################################################################

resource "aws_rds_cluster_parameter_group" "this" {
  count = local.create && local.create_db_cluster_parameter_group ? 1 : 0

  name        = var.db_cluster_parameter_group_use_name_prefix ? null : local.cluster_parameter_group_name
  name_prefix = var.db_cluster_parameter_group_use_name_prefix ? "${local.cluster_parameter_group_name}-" : null
  description = local.db_cluster_parameter_group_description
  family      = local.db_cluster_parameter_group_family

  dynamic "parameter" {
    for_each = var.db_cluster_parameter_group_parameters

    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = try(parameter.value.apply_method, "immediate")
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

################################################################################
# DB Parameter Group
################################################################################

resource "aws_db_parameter_group" "this" {
  count = local.create && local.create_db_parameter_group ? 1 : 0

  name        = var.db_parameter_group_use_name_prefix ? null : local.db_parameter_group_name
  name_prefix = var.db_parameter_group_use_name_prefix ? "${local.db_parameter_group_name}-" : null
  description = local.db_parameter_group_description
  family      = local.db_parameter_group_family

  dynamic "parameter" {
    for_each = var.db_parameter_group_parameters

    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = try(parameter.value.apply_method, "immediate")
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

################################################################################
# CloudWatch Log Group
################################################################################

# Log groups will not be created if using a cluster identifier prefix
resource "aws_cloudwatch_log_group" "this" {
  for_each = toset([for log in local.enabled_cloudwatch_logs_exports : log if local.create && local.create_cloudwatch_log_group && !var.cluster_use_name_prefix])

  name              = "/aws/rds/cluster/${local.name}/${each.value}"  // TODO this needs to be changed.
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id

  tags = local.tags
}

################################################################################
# CloudWatch Log KMS Key
################################################################################

// TODO confirm this is needed

################################################################################
# Master Password KMS Key
################################################################################

resource "aws_kms_key" "master_password" {
  count = local.create && local.manage_master_user_password ? 1 : 0

  description         = "KMS key used to encrypt the master password for Aurora cluster ${local.name}"
  enable_key_rotation = true

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM user permissions"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action    = [
          "kms:*",
        ]
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = {
          AWS = "*"
        }
        Action    = [
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "rds.${local.aws_region}.amazonaws.com"
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "Allow IAM roles use of the CMK"
        Effect    = "Allow"
        Principal = {
          AWS = [
            "*"  // TODO is this statement redundant?
          ]
        }
        Action    = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource  = "*"
      },
    ]
  }) // TODO Need to check that this isn't too broad.

  tags = local.tags
}

resource "aws_kms_alias" "master_password" {
  count = local.create && local.manage_master_user_password ? 1 : 0

  name          = "alias/${var.project_name}/${var.env_group}/${var.env}/rds/${local.engine}/${var.name}/master-password"
  target_key_id = aws_kms_key.master_password[0].key_id
}

################################################################################
# Storage KMS Key
################################################################################

resource "aws_kms_key" "storage" {
  count = local.create ? 1 : 0

  description         = "KMS key used to encrypt storage for Aurora cluster ${local.name}."
  enable_key_rotation = true

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM user permissions"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action    = [
          "kms:*",
        ]
        Resource  = "*"
      },
      {
        Sid       = "Allow access through RDS for all principals in the account that are authorized to use RDS",
        Effect    = "Allow"
        Principal = {
          AWS = "*"
        }
        Action    = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:DescribeKey"
        ]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "rds.${local.aws_region}.amazonaws.com"
            "kms:CallerAccount" = local.account_id
          }
        }
      },
    ]
  })

  tags = local.tags
}

resource "aws_kms_alias" "storage" {
  count = local.create ? 1 : 0

  name          = "alias/${var.project_name}/${var.env_group}/${var.env}/rds/${local.engine}/${var.name}/storage"
  target_key_id = aws_kms_key.storage[0].key_id
}

################################################################################
# Performance Insights KMS Key
################################################################################

// TODO We might consider creating IAM roles for the DB cluster.  See https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.access-control.html
resource "aws_kms_key" "performance_insights" {
  count = local.create ? 1 : 0

  description         = "KMS key used to encrypt storage for Aurora cluster ${local.name}."
  enable_key_rotation = true

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM user permissions"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action    = [
          "kms:*",
        ]
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = {
          AWS = "*"
        }
        Action    = [
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "rds.${local.aws_region}.amazonaws.com"
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "Allow IAM roles use of the CMK"
        Effect    = "Allow"
        Principal = {
          AWS = [
            "*"  // TODO Restrict to a particular role?
          ]
        }
        Action    = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource  = "*"
      },
    ]
  })

  tags = local.tags
}

resource "aws_kms_alias" "performance_insights" {
  count = local.create ? 1 : 0

  name          = "alias/${var.project_name}/${var.env_group}/${var.env}/rds/${local.engine}/${var.name}/performance-insights"
  target_key_id = aws_kms_key.performance_insights[0].key_id
}

################################################################################
# SSM Parameter Store Resources
################################################################################

# The writer end-point.
resource "aws_ssm_parameter" "aurora_writer_endpoint" {
  count = local.create ? 1 : 0

  name  = "/${var.project_name}/${var.env_group}/${var.env}/rds/${local.engine}/${var.name}/endpoint-w"
  type  = "String"
  value = try(aws_rds_cluster.this[0].endpoint, null)

  tags = local.tags
}

# The read-only end-point.
resource "aws_ssm_parameter" "aurora_readonly_endpoint" {
  count = local.create ? 1 : 0

  name  = "/${var.project_name}/${var.env_group}/${var.env}/rds/${local.engine}/${var.name}/endpoint-ro"
  type  = "String"
  value = try(aws_rds_cluster.this[0].reader_endpoint, null)

  tags = local.tags
}

