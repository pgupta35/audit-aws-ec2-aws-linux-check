audit RDS
============================
This stack will monitor RDS and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor RDS against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;RDS&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/STACK/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT`:
  * description: email recipient for notification


## Required variables with default

### `AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY`:
  * description: receive empty reports?
  * default: false

### `AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS`:
  * description: the tag we want to see on instances
  * default: "EXAMPLE_TAG_1", "EXAMPLE_TAG_2"

### `AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC`:
  * description: "or" or "and"
  * default: "and"

### `AUDIT_AWS_EC2_TAG_EXAMPLE_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1, us-west-1, us-west-2


## Optional variables with no default

**None**


## Optional variables with default

**None**

## Tags
1. Audit
1. Best Practices
1. Alert
1. RDS

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/STACK/master/images/diagram.png "diagram")


## Icon


