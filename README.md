audit-aws-ec2-aws-linux-check
============================
This composite ensures that all running EC2 instances are based on the latest AWS Linux AMI


## Description
This composite ensures that all running EC2 instances are based on the latest AWS Linux AMI


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-aws-linux-check/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_EC2_LINUX_CHECK_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1.
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `HTML_REPORT_SUBJECT`:
  * description: Enter a custom report subject name.

### `AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `AWS_LINUX_AMI`:
  * description: The ami id for latest AWS Linux.

### `AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME`:
  * description: Enter S3 bucket name to upload reports. (Optional)

## Tags
1. Operations
1. AMI
1. AWS Linux

## Categories
1. AWS Operations Automation



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-aws-linux-check/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-aws-linux-check/master/images/icon.png "icon")

