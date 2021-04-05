
# AWS Config Terraform module

Enables AWS Config, deploys Config rules and creates necessary resources for notifications per region.



#### Terraform Resources

- Config Recorder (Recorder + Recorder Status)
- Config Delivery Channel
- Config Rules (multiple)
- Cloudwatch Event Rule
- Cloudwatch Event Target
- SNS Topic
- SNS Topic Policy
- IAM Policy Document


## Supported AWS Config Rules

### VPC

* EIP_ATTACHED: Checks whether all EIP addresses that are allocated to a VPC are attached to EC2 or in-use ENIs.
* INSTANCES_IN_VPC: Ensure all EC2 instances run in a VPC.
* VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS: Checks whether any security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. The rule is NON_COMPLIANT when a security group with inbound 0.0.0.0/0 has a port accessible which is not specified in the rule parameters.


### CloudTrail

* CLOUD_TRAIL_ENABLED: Ensure CloudTrail is enabled.

### CloudWatch Logs

* CLOUDWATCH_LOG_GROUP_ENCRYPTED: Checks whether a log group in Amazon CloudWatch Logs is encrypted. The rule is NON_COMPLIANT if CloudWatch Logs has a log group without encryption enabled

### EC2

* ENCRYPTED_VOLUMES: Evaluates whether EBS volumes that are in an attached state are encrypted.
* EC2_VOLUME_INUSE_CHECK: Checks whether EBS volumes are attached to EC2 instances.
* EC2_REQUIRED_TAGS: Checks whether your resources have the tags that you specify.

### IAM

* IAM_USER_NO_POLICIES_CHECK: Ensure that none of your IAM users have policies attached; IAM users must inherit permissions from IAM groups or roles.
* ROOT_ACCOUNT_MFA_ENABLED: Ensure root AWS account has MFA enabled.
* IAM_ROOT_ACCESS_KEY_CHECK: Ensure root AWS account does not have Access Keys.

### Tagging

* required-tags: Checks if resources are deployed with configured tags.

### RDS

* RDS_INSTANCE_PUBLIC_ACCESS_CHECK: Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible.
* RDS_STORAGE_ENCRYPTED: Checks whether storage encryption is enabled for your RDS DB instances.

### S3
* S3_BUCKET_VERSIONING_ENABLED: Ensures that all of your S3 buckets has versioning enabeled. 
* S3_BUCKET_PUBLIC_READ_PROHIBITED: Checks that your S3 buckets do not allow public read access.
* S3_BUCKET_PUBLIC_WRITE_PROHIBITED: Checks that your S3 buckets do not allow public write access.

## Terraform Versions

Terraform 0.13 and newer. Pin module version to ~> 4.x. Submit pull-requests to master branch.

Terraform 0.12. Pin module version to ~> 3.0. Submit pull-requests to terraform012 branch.

## Usage

**Note: This module sets up AWS IAM Roles and Policies, which are globally namespaced. If you plan to have multiple instances of AWS Config, make sure they have unique values for `config_name`.**

**Note: If you use this module in multiple regions, be sure to disable duplicative checks and global resource types.**

```hcl
module "aws_config" {
  source = "gravicore/terraform-gravicore-modules/aws/aws-config"
}
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.12.7 |
| aws | >= 2.70 |
| template | >= 2.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 2.70 |
| template | >= 2.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| check\_cloud\_trail\_encryption | Enable cloud-trail-encryption-enabled rule | `bool` | `false` | no |
| check\_cloud\_trail\_log\_file\_validation | Enable cloud-trail-log-file-validation-enabled rule | `bool` | `false` | no |
| check\_cloudtrail\_enabled | Enable cloudtrail-enabled rule | `bool` | `true` | no |
| check\_cloudwatch\_log\_group\_encrypted | Enable cloudwatch-log-group-encryption rule | `bool` | `true` | no |
| check\_ec2\_encrypted\_volumes | Enable ec2-encrypted-volumes rule | `bool` | `true` | no |
| check\_ec2\_volume\_inuse\_check | Enable ec2-volume-inuse-check rule | `bool` | `true` | no |
| check\_eip\_attached | Enable eip-attached rule | `bool` | `false` | no |
| check\_iam\_group\_has\_users\_check | Enable iam-group-has-users-check rule | `bool` | `true` | no |
| check\_iam\_root\_access\_key | Enable iam-root-access-key rule | `bool` | `true` | no |
| check\_iam\_user\_no\_policies\_check | Enable iam-user-no-policies-check rule | `bool` | `true` | no |
| check\_instances\_in\_vpc | Enable instances-in-vpc rule | `bool` | `true` | no |
| check\_mfa\_enabled\_for\_iam\_console\_access | Enable mfa-enabled-for-iam-console-access rule | `bool` | `false` | no |
| check\_rds\_public\_access | Enable rds-instance-public-access-check rule | `bool` | `false` | no |
| check\_rds\_snapshots\_public\_prohibited | Enable rds-snapshots-public-prohibited rule | `bool` | `true` | no |
| check\_rds\_storage\_encrypted | Enable rds-storage-encrypted rule | `bool` | `true` | no |
| check\_required\_tags | Enable required-tags rule | `bool` | `false` | no |
| check\_root\_account\_mfa\_enabled | Enable root-account-mfa-enabled rule | `bool` | `false` | no |
| check\_s3\_bucket\_public\_write\_prohibited | Enable s3-bucket-public-write-prohibited rule | `bool` | `true` | no |
| check\_vpc\_default\_security\_group\_closed | Enable vpc-default-security-group-closed rule | `bool` | `true` | no |
| config\_delivery\_frequency | The frequency with which AWS Config delivers configuration snapshots. | `string` | `"Six_Hours"` | no |
| config\_logs\_bucket | The S3 bucket for AWS Config logs. If you have set enable\_config\_recorder to false then this can be an empty string. | `string` | n/a | yes |
| config\_logs\_prefix | The S3 prefix for AWS Config logs. | `string` | `"config"` | no |
| config\_max\_execution\_frequency | The maximum frequency with which AWS Config runs evaluations for a rule. | `string` | `"TwentyFour_Hours"` | no |
| config\_name | The name of the AWS Config instance. | `string` | `"aws-config"` | no |
| config\_sns\_topic\_arn | An SNS topic to stream configuration changes and notifications to. | `string` | `null` | no |
| enable\_config\_recorder | Enables configuring the AWS Config recorder resources in this module. | `bool` | `true` | no |
| include\_global\_resource\_types | Specifies whether AWS Config includes all supported types of global resources with the resources that it records. | `bool` | `true` | no |
| required\_tags | A map of required resource tags. Format is tagNKey, tagNValue, where N is int. Values are optional. | `map(string)` | `{}` | no |
| required\_tags\_resource\_types | Resource types to check for tags. | `list(string)` | `[]` | no |
| tags | Tags to apply to AWS Config resources | `map(string)` | `{}` | no |
