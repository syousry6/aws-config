###################################################################################################################
# Filename   : variables.tf
# Summary    : Variables for the Config module used by Onica to create an AWS Foundation
# Author     : Sherif ElTammimy
# Notes      : 
###################################################################################################################

variable "aws_region" {
  type        = string
  default     = "us-east-2"
  description = "The AWS region to deploy module into"
}


# ----------------------------------------------------------------------------------------------------------------------
# Platform Standard Variables
# ----------------------------------------------------------------------------------------------------------------------
# Recommended

# variable "namespace" {
#   type        = string
#   default     = ""
#   description = "Namespace, which could be your organization abbreviation, client name, etc. (e.g. Gravicore 'grv', HashiCorp 'hc')"
# }

# variable "environment" {
#   type        = string
#   default     = ""
#   description = "The isolated environment the module is associated with (e.g. Shared Services `shared`, Application `app`)"
# }

# variable "stage" {
#   type        = string
#   default     = ""
#   description = "The development stage (i.e. `dev`, `stg`, `prd`)"
# }

# variable "repository" {
#   type        = string
#   default     = ""
#   description = "The repository where the code referencing the module is stored"
# }

# variable "account_id" {
#   type        = string
#   default     = ""
#   description = "The AWS Account ID that contains the calling entity"
# }

# variable "master_account_id" {
#   type        = string
#   default     = ""
#   description = "The Master AWS Account ID that owns the associate AWS account"
# }


variable "profile" {
  default = "user1"
}


variable "account_name" {
  default = "648251276612"
}

# variable "config_bucket_name" {
# default = "648251276612"}


variable "config_recorder_name" {
  default = "celink-config-recorder"
}


variable "developer_email" {
  description = "An email to send aws config details through sns"
  default = "sherif.eltammimy@rackspace.com"
}


variable "check_cloudwatch_log_group_encrypted" {
  description = "Enable cloudwatch-log-group-encryption rule"
  type        = bool
  default     = true
}


variable "check_ec2_encrypted_volumes" {
  description = "Enable ec2-encrypted-volumes rule"
  type        = bool
  default     = true
}


variable "check_iam_root_access_key" {
  description = "Enable iam-root-access-key rule"
  type        = bool
  default     = true
}


variable "check_rds_public_access" {
  description = "Enable rds-instance-public-access-check rule"
  type        = bool
  default     = false
}


variable "check_ec2_volume_inuse_check" {
  description = "Enable ec2-volume-inuse-check rule"
  type        = bool
  default     = true
}

variable "check_root_account_mfa_enabled" {
  description = "Enable root-account-mfa-enabled rule"
  type        = bool
  default     = false
}


variable "check_instances_in_vpc" {
  description = "Enable instances-in-vpc rule"
  type        = bool
  default     = true
}


variable "check_eip_attached" {
  description = "Enable eip-attached rule"
  type        = bool
  default     = false
}

variable "check_iam_user_no_policies_check" {
  description = "Enable iam-user-no-policies-check rule"
  type        = bool
  default     = true
}

variable "check_rds_storage_encrypted" {
  description = "Enable rds-storage-encrypted rule"
  type        = bool
  default     = true
}

# ----------------------------------------------------------------------------------------------------------------------
# Module Standard Variables
# ----------------------------------------------------------------------------------------------------------------------


variable "name" {
  type        = string
  default     = "aws-config"
  description = "The name of the module"
}

variable terraform_module {
  type        = string
  default     = "gravicore/terraform-gravicore-modules/aws/aws-config"
  description = "The owner and name of the Terraform module"
}

variable "create" {
  type        = bool
  default     = true
  description = "Set to false to prevent the module from creating any resources"
}

# ----------------------------------------------------------------------------------------------------------------------
# Platform Standard Variables
# ----------------------------------------------------------------------------------------------------------------------

# Recommended

variable "namespace" {
  type        = string
  default     = "Gravicore"
  description = "Namespace, which could be your organization abbreviation, client name, etc. (e.g. Gravicore 'grv', HashiCorp 'hc')"
}

variable "environment" {
  type        = string
  default     = "shared"
  description = "The isolated environment the module is associated with (e.g. Shared Services `shared`, Application `app`)"
}

variable "stage" {
  type        = string
  default     = "dev"
  description = "The development stage (i.e. `dev`, `stg`, `prd`)"
}

variable "repository" {
  type        = string
  default     = ""
  description = "The repository where the code referencing the module is stored"
}

variable "account_id" {
  type        = string
  default     = "648251276612"
  description = "The AWS Account ID that contains the calling entity"
}

variable "master_account_id" {
  type        = string
  default     = ""
  description = "The Master AWS Account ID that owns the associate AWS account"
}

# Optional

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional map of tags (e.g. business_unit, cost_center)"
}

variable "desc_prefix" {
  type        = string
  default     = "Gravicore:"
  description = "The prefix to add to any descriptions attached to resources"
}

variable "environment_prefix" {
  type        = string
  default     = "Gravicore Shared"
  description = "Concatenation of `namespace` and `environment`"
}

variable "stage_prefix" {
  type        = string
  default     = ""
  description = "Concatenation of `namespace`, `environment` and `stage`"
}

variable "module_prefix" {
  type        = string
  default     = ""
  description = "Concatenation of `namespace`, `environment`, `stage` and `name`"
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter to be used between `namespace`, `environment`, `stage`, `name`"
}

# Derived

data "aws_caller_identity" "current" {
  count = var.account_id == "" ? 1 : 0
}

locals {
  account_id = var.account_id == "" ? data.aws_caller_identity.current[0].account_id : var.account_id

  environment_prefix = coalesce(var.environment_prefix, join(var.delimiter, compact([var.namespace, var.environment])))
  stage_prefix       = coalesce(var.stage_prefix, join(var.delimiter, compact([local.environment_prefix, var.stage])))
  module_prefix      = coalesce(var.module_prefix, join(var.delimiter, compact([local.stage_prefix, var.name])))

  business_tags = {
    namespace          = var.namespace
    environment        = var.environment
    environment_prefix = local.environment_prefix
  }
  technical_tags = {
    stage             = var.stage
    module            = var.name
    repository        = var.repository
    master_account_id = var.master_account_id
    account_id        = local.account_id
    aws_region        = var.aws_region
  }
  automation_tags = {
    terraform_module = var.terraform_module
    stage_prefix     = local.stage_prefix
    module_prefix    = local.module_prefix
  }
  security_tags = {}

  tags = merge(
    local.business_tags,
    local.technical_tags,
    local.automation_tags,
    local.security_tags,
    var.tags
  )
}