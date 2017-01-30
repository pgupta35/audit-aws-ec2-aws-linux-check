###########################################
# User Visible Rule Definitions
###########################################


# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#

coreo_aws_advisor_alert "ec2-aws-linux-latest-not" do
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
  alert_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

###########################################
# Compsite-Internal Resources follow until end
#   (Resources used by the system for execution and display processing)
###########################################

coreo_aws_advisor_ec2 "advise-ec2-samples-2" do
  alerts ["ec2-aws-linux-latest-not"]
  action :advise
  regions ${AUDIT_AWS_EC2_LINUX_CHECK_REGIONS}
end

# the jsrunner will now allow all regions to be specified in the above advisor instead of a single region

# it will also allow the specification of a convention file in the composite to specify violation suppressions

coreo_uni_util_jsrunner "jsrunner-get-not-aws-linux-ami-latest" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.report'
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
    for (var inputKey in json_input) {
        var thisKey = inputKey;
        var ami_id = json_input[thisKey]["violations"]["ec2-aws-linux-latest-not"]["violating_object"]["0"]["object"]["image_id"];

        var cases = properties["variables"]["AWS_LINUX_AMI"]["cases"];
        var is_violation = true;
        for (var key in cases) {
            value = cases[key];
            if (ami_id === value) {
                is_violation = false;
            }
        }
        if (is_violation === true) {
            result[thisKey] = json_input[thisKey];
        }
    }

    var rtn = result;

    callback(result);

EOH
end


coreo_uni_util_jsrunner "jsrunner-process-suppression" do
  action :run
  provide_composite_access true
  json_input '{"violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  var fs = require('fs');
  var yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  var violations = json_input.violations;
  var result = {};
    var file_date = null;
    for (var violator_id in violations) {
        result[violator_id] = {};
        result[violator_id].tags = violations[violator_id].tags;
        result[violator_id].violations = {}
        for (var rule_id in violations[violator_id].violations) {
            is_violation = true;
 
            result[violator_id].violations[rule_id] = violations[violator_id].violations[rule_id];
            for (var suppress_rule_id in suppression) {
                for (var suppress_violator_num in suppression[suppress_rule_id]) {
                    for (var suppress_violator_id in suppression[suppress_rule_id][suppress_violator_num]) {
                        file_date = null;
                        var suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                        if (rule_id === suppress_rule_id) {
 
                            if (violator_id === suppress_violator_id) {
                                var now_date = new Date();
 
                                if (suppress_obj_id_time === "") {
                                    suppress_obj_id_time = new Date();
                                } else {
                                    file_date = suppress_obj_id_time;
                                    suppress_obj_id_time = file_date;
                                }
                                var rule_date = new Date(suppress_obj_id_time);
                                if (isNaN(rule_date.getTime())) {
                                    rule_date = new Date(0);
                                }
 
                                if (now_date <= rule_date) {
 
                                    is_violation = false;
 
                                    result[violator_id].violations[rule_id]["suppressed"] = true;
                                    if (file_date != null) {
                                        result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                        result[violator_id].violations[rule_id]["suppression_expired"] = false;
                                    }
                                }
                            }
                        }
                    }
 
                }
            }
            if (is_violation) {
 
                if (file_date !== null) {
                    result[violator_id].violations[rule_id]["suppressed_until"] = file_date;
                    result[violator_id].violations[rule_id]["suppression_expired"] = true;
                } else {
                    result[violator_id].violations[rule_id]["suppression_expired"] = false;
                }
                result[violator_id].violations[rule_id]["suppressed"] = false;
            }
        }
    }
 
    var rtn = result;
  
  var rtn = result;
  
  callback(result);
  EOH
end


coreo_uni_util_jsrunner "jsrunner-process-table" do
  action :run
  provide_composite_access true
  json_input '{"violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end


coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.6.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression.return}'
  function <<-EOH
  
const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON}";
const AUDIT_NAME = 'ec2-samples';
const TABLES = json_input['table'];
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const WHAT_NEED_TO_SHOWN_ON_TABLE = {
    OBJECT_ID: { headerName: 'AWS Object ID', isShown: true},
    REGION: { headerName: 'Region', isShown: true },
    AWS_CONSOLE: { headerName: 'AWS Console', isShown: true },
    TAGS: { headerName: 'Tags', isShown: true },
    AMI: { headerName: 'AMI', isShown: true },
    KILL_SCRIPTS: { headerName: 'Kill Cmd', isShown: false }
};

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, AUDIT_NAME,
    WHAT_NEED_TO_SHOWN_ON_TABLE, ALLOW_EMPTY, SEND_ON,
    undefined, undefined, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2_LINUX_CHECK = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES, TABLES);
const notifiers = AuditEC2_LINUX_CHECK.getNotifiers();
callback(notifiers);
  EOH
end

## Send Notifiers
coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action :${AUDIT_AWS_EC2_LINUX_CHECK_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end


coreo_uni_util_jsrunner "tags-rollup-ec2" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end


coreo_uni_util_notify "advise-ec2-rollup" do
  action :${AUDIT_AWS_EC2_LINUX_CHECK_ROLLUP_REPORT}
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
      :to => '${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}', :subject => 'CloudCoreo rds advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
