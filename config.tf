###################################################################################################################
# Filename      : config.tf
# Description   : Terraform Base template for AWS config for Celink | MAP-32
# Author        : Sherif ElTammimy
# Notes         : Used to create AWS built-in config rules to monitor the accounts
###################################################################################################################

terraform {
  required_version = ">= 0.12"
}

provider "aws" {
  region = var.aws_region
  profile = var.profile
}

###################################################################################################################
# S3 Bucket
###################################################################################################################
resource "aws_s3_bucket" "config_bucket" {
  bucket = "celink-config-bucket"
  acl    = "private"
  
  versioning {
         enabled = true
  }

  tags = {
    Name        = "celink_config_bucket"
    Environment = "celink_test"
  }
}
###################################################################################################################
# IAM Roles
###################################################################################################################

resource "aws_iam_role" "aws-config-celink" {
  name = "awsconfig-celink"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}


##Attaching policy to the above role
resource "aws_iam_role_policy_attachment" "aws-config" {
  role     = aws_iam_role.aws-config-celink.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}


##Adding a policy for s3 delivery channel to the above role
resource "aws_iam_role_policy" "aws-config-policy" { 
  name = "awsconfig-celink-policy"
  role = aws_iam_role.aws-config-celink.name

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
           "s3:*"
       ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.config_bucket.arn}",
        "${aws_s3_bucket.config_bucket.arn}/*"
      ]
    }
  ]
}
POLICY
}
###################################################################################################################
# Config Rules
###################################################################################################################
resource "aws_config_config_rule" "ACCESS_KEYS_ROTATED" {
  name = format(
    "%s-%s",
    upper(var.account_name),
    "ACCESS_KEYS_ROTATED",
  )
  description = "Checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is non-compliant if the access keys have not been rotated for more than maxAccessKeyAge number of days."

  input_parameters = <<PARAMETERS
  {
    "maxAccessKeyAge": "90"
  }
  PARAMETERS

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_config_rule" "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" {
  name = format(
    "%s-%s",
    upper(var.account_name),
    "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS",
  )
  description = "Checks whether any security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. The rule is NON_COMPLIANT when a security group with inbound 0.0.0.0/0 has a port accessible which is not specified in the rule parameters."

  source {
    owner             = "AWS"
    source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}


 resource "aws_config_config_rule" "S3_bucket_versioning_enabled" {
   name = format(
     "%s-%s",
     upper(var.account_name),
     "S3_bucket_versioning_enabled",
   )
  description = "Checks whether versioning is enabled for your S3 buckets."

   source {
     owner             = "AWS"
     source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
   }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
 }



# resource "aws_config_config_rule" "EC2_INSTANCE_MANAGED_BY_SSM" {
#   name = format(
#     "%s-%s",
#     upper(var.account_name),
#     "EC2_INSTANCE_MANAGED_BY_SSM",
#   )

#   source {
#     owner             = "AWS"
#     source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
#   }

#   depends_on = [aws_config_configuration_recorder.config_recorder]
# }

resource "aws_config_config_rule" "EC2_VOLUME_INUSE_CHECK" {
#  count       = var.check_ec2_volume_inuse_check ? 1 : 0
  name = format(
    "%s-%s",
    upper(var.account_name),
    "EC2_VOLUME_INUSE_CHECK",
  )
  description = "Checks whether EBS volumes are attached to EC2 instances."
  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_config_rule" "CLOUD_TRAIL_ENABLED" {
  name = format(
    "%s-%s",
    upper(var.account_name),
    "CLOUD_TRAIL_ENABLED",
  )
  description = "Checks whether AWS CloudTrail is enabled in your AWS account."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_config_rule" "EC2_REQUIRED_TAGS" {
  name = format(
    "%s-%s",
    upper(var.account_name),
    "EC2_REQUIRED_TAGS",
  )
  description = "Checks whether your resources have the tags that you specify."

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }

  input_parameters = <<EOF
{
    "tag1Key": "CreatedBy",
    "tag2Key": "backup",
    "tag3Key": "Owner",
    "tag4Key": "Environment"
}
EOF
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_config_rule" "VPC_FLOW_LOGS_ENABLED" {
  name = format(
    "%s-%s",
    upper(var.account_name),
    "VPC_FLOW_LOGS_ENABLED",
  )
  description = "Checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC."

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_config_rule" "ROOT_ACCOUNT_MFA_ENABLED" {
# count       = var.check_root_account_mfa_enabled ? 1 : 0
  name = format(
    "%s-%s",
    upper(var.account_name),
    "ROOT_ACCOUNT_MFA_ENABLED",
  )
  description = "Checks whether the root user of your AWS account requires multi-factor authentication for console sign-in."

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

 resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_READ_CHECKER" {
  name = format(
     "%s-%s",
     upper(var.account_name),
     "S3_BUCKET_PUBLIC_READ_PROHIBITED",
   )
  description = "Checks that your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

   source {
     owner             = "AWS"
     source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
   }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
 }

 resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_WRITE_CHECKER" {
   name = format(
     "%s-%s",
     upper(var.account_name),
     "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
   )
  description = "Checks that your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

   source {
     owner             = "AWS"
     source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
   }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
 }



 resource "aws_config_config_rule" "ec2-encrypted-volumes" {
# count       = var.check_ec2_encrypted_volumes ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "ec2-volumes-must-be-encrypted",
   )

  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
 }


resource "aws_config_config_rule" "cloudwatch_log_group_encrypted" {
# count = var.check_cloudwatch_log_group_encrypted ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "cloudwatch_log_group-encrypted",
   )
  description = "Checks whether a log group in Amazon CloudWatch Logs is encrypted. The rule is NON_COMPLIANT if CloudWatch Logs has a log group without encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }
  
  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}



resource "aws_config_config_rule" "iam_root_access_key" {
# count = var.check_iam_root_access_key ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "iam-root-access-key",
   )
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}


resource "aws_config_config_rule" "rds-instance-public-access-check" {
#  count       = var.check_rds_public_access ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "rds-instance-public-access-check",
   )
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item."

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}


resource "aws_config_config_rule" "rds-storage-encrypted" {
  count       = var.check_rds_storage_encrypted ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "rds-storage-encrypted",
   )
  description = "Checks whether storage encryption is enabled for your RDS DB instances."

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  tags = local.tags

  depends_on = [aws_config_configuration_recorder.config_recorder]
}


resource "aws_config_config_rule" "instances-in-vpc" {
  count       = var.check_instances_in_vpc ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "instances-in-vpc",
   )
  description = "Ensure all EC2 instances run in a VPC"

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  tags = local.tags
  depends_on = [aws_config_configuration_recorder.config_recorder]
}


resource "aws_config_config_rule" "eip_attached" {
  count       = var.check_eip_attached ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "eip-attached",
   )
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  tags = local.tags

  depends_on = [aws_config_configuration_recorder.config_recorder]
}


resource "aws_config_config_rule" "iam-user-no-policies-check" {
  count       = var.check_iam_user_no_policies_check ? 1 : 0
  name = format(
     "%s-%s",
     upper(var.account_name),
     "iam-user-no-policies-check",
   )
  description = "Ensure that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  tags = local.tags

  depends_on = [aws_config_configuration_recorder.config_recorder]
}


###################################################################################################################
# Config Recorder
###################################################################################################################
resource "aws_config_configuration_recorder" "config_recorder" {
  count = var.config_recorder_name != "None" ? 0 : 1

  name     = "${var.account_name}-config-recorder"
  #role_arn = var.role_arn
  role_arn = aws_iam_role.aws-config-celink.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}



resource "aws_config_configuration_recorder_status" "config_recorder_status" {
  count = var.config_recorder_name != "None" ? 0 : 1

  name       = var.config_recorder_name != "None" ? var.config_recorder_name : aws_config_configuration_recorder.config_recorder[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.config_delivery_channel]
}

resource "aws_config_delivery_channel" "config_delivery_channel" {
  count = var.config_recorder_name != "None" ? 0 : 1
  
  name           = "config_delivery_channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket
  sns_topic_arn  = aws_sns_topic.aws_config_alerts.arn
  depends_on = [aws_config_configuration_recorder.config_recorder]
}

###################################################################################################################
# Notifications
###################################################################################################################
resource "aws_cloudwatch_event_rule" "console" {
  name        = "aws_config_compliance_rule"
  description = "Alert on out of AWS Config compliance alerts"
  event_pattern = <<PATTERN
{
    "source": [
        "aws.config"
    ],
    "detail-type": [
        "Config Rules Compliance Change"
    ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "cloudwatch_event_target" {
  rule      = aws_cloudwatch_event_rule.console.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.aws_config_alerts.arn
}


#-----------------------------------------------------------------------------------------------------------------------
# Optionally create an SNS topic and subscriptions
#-----------------------------------------------------------------------------------------------------------------------
resource "aws_sns_topic" "aws_config_alerts" {
  name = "aws_config_alerts"
}

resource "aws_cloudformation_stack" "stack" {
  name = "subscription-stack-celink"

  template_body = <<STACK
{
  "Resources" : {
    "MySubscription" : {
  "Type" : "AWS::SNS::Subscription",
  "Properties" : {
    "Endpoint" : "${var.developer_email}",
    "Protocol" : "email",
    "TopicArn" : "${aws_sns_topic.aws_config_alerts.arn}"
  }
      }
   }
}
STACK
}

resource "aws_sns_topic_policy" "sns_topic_policy" {
  arn    = aws_sns_topic.aws_config_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy_doc.json
}

data "aws_iam_policy_document" "sns_topic_policy_doc" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.aws_config_alerts.arn]
  }
}

