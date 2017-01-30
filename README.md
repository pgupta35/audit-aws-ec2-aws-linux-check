audit-aws-ec2-samples
============================



## Description
This repo is designed to work with CloudCoreo. This composite is a collection of sample EC2 definitions that have been requested by our customers and should be considered a starting point for building your own composites from.


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/hierarchy.png "composite inheritance hierarchy")



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
  * default: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1

### `AUDIT_AWS_EC2_LINUX_CHECK_ROLLUP_REPORT`:
  * description: Would you like to send a rollup report? This is a short email that summarizes the number of checks performed and the number of violations found. Options - notify / nothing. Default is nothing.
  * default: nothing

### `AUDIT_AWS_EC2_LINUX_CHECK_HTML_REPORT`:
  * description: Would you like to send a full report? This is an email that details any violations found and includes a list of the violating cloud objects. Options - notify / nothing. Default is nothing.
  * default: nothing


## Optional variables with default

### `AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `AWS_LINUX_AMI`:
  * description: The ami id for latest AWS Linux.

## Tags
1. Audit
1. Best Practices
1. Alert
1. EC2

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-samples/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-aws-linux-check/master/images/icon.png "icon")

