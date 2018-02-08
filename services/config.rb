coreo_aws_rule "ec2-aws-linux-latest-not" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-amazon-linux-not-latest.html"
  display_name "Not Latest AWS Linux AMI Instance"
  description "Alerts on EC2 instances that were not launched from the latest AWS Linux AMI."
  category "Security"
  suggested_action "If you run Amazon Linux, verify that you launch instances from the latest Amazon Linux AMIs."
  level "Informational"
  objectives ["instances"]
  audit_objects ["object.reservation_set.instances_set.image_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

coreo_uni_util_variables "ec2-aws-linux-check-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.number_violations' => '0'}
            ])
end

coreo_aws_rule_runner_ec2 "advise-ec2-samples-2" do
  rules ["ec2-aws-linux-latest-not"]
  action :run
  regions ${AUDIT_AWS_EC2_LINUX_CHECK_REGIONS}
end


coreo_uni_util_variables "ec2-aws-linux-check-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-samples-2.report'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-samples-2.number_violations'},

            ])
end


coreo_uni_util_jsrunner "jsrunner-get-not-aws-linux-ami-latest" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-samples-2.report'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');

// Get document, or throw exception on error
    try {
        var properties = yaml.safeLoad(fs.readFileSync('./config.yaml', 'utf8'));
        console.log(properties);
    } catch (e) {
        console.log(e);
    }

    var result = {};
    for (var region in json_input) {
        result[region] = {};
        for (var inputKey in json_input[region]) {
            var thisKey = inputKey;
            var candidate = json_input[region][thisKey];
            var ami_id = json_input[region][thisKey]["violations"]["ec2-aws-linux-latest-not"]["result_info"][0]["object"]["image_id"];
            var cases = properties["variables"]["AWS_LINUX_AMI"]["cases"];
            var is_violation = true;
            for (var key in cases) {
                value = cases[key];
                if (ami_id === value) {
                    is_violation = false;
                    break;
                }
            }
            if (is_violation === true) {
               result[region][thisKey]=candidate;
            }else{
               candidate["violations"]["ec2-aws-linux-using-latest-ami"]=candidate["violations"]["ec2-aws-linux-latest-not"];
               candidate["violations"]["ec2-aws-linux-using-latest-ami"].display_name="Latest AWS Linux AMI Instance"; 
               candidate["violations"]["ec2-aws-linux-using-latest-ami"].description="Alerts on EC2 instances that were launched from the latest AWS Linux AMI."; 
               candidate["violations"]["ec2-aws-linux-using-latest-ami"].suggested_action="If you run Amazon Linux, verify that you launch instances from the latest Amazon Linux AMIs."; 
               delete candidate["violations"]["ec2-aws-linux-latest-not"];
               result[region][thisKey]=candidate;
            }
        }
    }

    callback(result);

EOH
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta65"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

const alertListArray = ["ec2-aws-linux-latest-not"];
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');

function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

coreo_uni_util_variables "ec2-aws-linux-check-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2-samples-2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.table'}
            ])
end


coreo_uni_util_jsrunner "tags-rollup-ec2" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end


coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action((("${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action((("${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-rds.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}', :subject => 'CloudCoreo rds rule results on PLAN::stack_name :: PLAN::name'
  })
end


coreo_aws_s3_policy "cloudcoreo-audit-aws-ec2-aws-linux-check-policy" do
  action((("${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::bucket-${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::bucket-${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "bucket-${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-ec2-aws-linux-check-policy"]
end

coreo_uni_util_notify "cloudcoreo-audit-aws-ec2-aws-linux-check-s3" do
  action((("${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.report'
  endpoint ({
      object_name: 'ec2-aws-linux-check-json',
      bucket_name: 'bucket-${AUDIT_AWS_EC2-AWS-LINUX_CHECK_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 'ec2-aws-linux-check/PLAN::name',
      properties: {}
  })
end
