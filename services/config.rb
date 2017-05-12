
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
  audit_objects ["reservation_set.instances_set.image_id"]
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
            var ami_id = json_input[region][thisKey]["violations"]["ec2-aws-linux-latest-not"]["result_info"][0]["object"]["image_id"];
    
            var cases = properties["variables"]["AWS_LINUX_AMI"]["cases"];
            var is_violation = true;
            for (var key in cases) {
                value = cases[key];
                if (ami_id === value) {
                    is_violation = false;
                }
            }
            if (is_violation === true) {
                result[region][thisKey] = json_input[region][thisKey];
            }
        }
    }

    var rtn = result;

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
                   :version => "1.8.4"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return}'
  function <<-EOH
  


function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: ", e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "['ec2-aws-linux-latest-not']";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "mihail@cloudcoreo.com";
const OWNER_TAG = "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG,
  ALLOW_EMPTY, SEND_ON,
  SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2_LINUX_CHECK = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);


const JSONReportAfterGeneratingSuppression = AuditEC2_LINUX_CHECK.getJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(JSONReportAfterGeneratingSuppression));

const notifiers = AuditEC2_LINUX_CHECK.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_variables "ec2-aws-linux-check-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-aws-linux-check-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.table'}
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
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end


coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action((("mihail@cloudcoreo.com".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action((("mihail@cloudcoreo.com".length > 0) and (! "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
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
      :to => 'mihail@cloudcoreo.com', :subject => 'CloudCoreo rds rule results on PLAN::stack_name :: PLAN::name'
  })
end
