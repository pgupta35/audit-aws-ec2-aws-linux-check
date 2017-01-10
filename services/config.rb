
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
end

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
            console.log(value);
            if (ami_id === value) {
                console.log("got a match - this is not a violation");
                is_violation = false;
            }
        }
        if (is_violation === true) {
            console.log("no match - this is a violation so copy to result structure");
            result[thisKey] = json_input[thisKey];
        }
    }

    var rtn = result;

    callback(result);

EOH
end

coreo_uni_util_jsrunner "jsrunner-process-suppressions" do
  action :run
  provide_composite_access true
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-get-not-aws-linux-ami-latest.return'
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
        var suppressions = yaml.safeLoad(fs.readFileSync('./suppressions.yaml', 'utf8'));
        console.log(suppressions);
    } catch (e) {
        console.log(e);
    }

    var result = {};
    for (var inputKey in json_input) {
        var thisKey = inputKey;
        var inst_id = inputKey;
        is_violation = true;
        for (var suppression in suppressions["suppressions"]["ec2-aws-linux-latest-not"]) {
            value = suppressions["suppressions"]["ec2-aws-linux-latest-not"][suppression];
            if (value === inst_id) {
                console.log("got a match - this violation is suppressed");
                is_violation = false;
            }

        }
        if (is_violation === true) {
            console.log("no match - this is a violation so copy to result structure");
            result[thisKey] = json_input[thisKey];
        }
    }

    var rtn = result;

    callback(result);


EOH
end

coreo_uni_util_variables "update-advisor-output" do
  action :set
  variables([
       {'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return'}
      ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.3.9"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppressions.return}'
  function <<-EOH
  
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_LINUX_CHECK_ALLOW_EMPTY}"; // true or false
const SEND_ON = "${AUDIT_AWS_EC2_LINUX_CHECK_SEND_ON}"; // always or change
const AUDIT_NAME = 'ec2-samples';


const ARE_KILL_SCRIPTS_SHOWN = false;
const EC2_LOGIC = "or"; // you can choose 'and' or 'or';
const EXPECTED_TAGS = ['EXAMPLE_TAG_2', 'example_1'];

const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: true,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: true,
    },
    AMI: {
        headerName: 'AMI',
        isShown: true,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};


const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN,
    ALLOW_EMPTY,
    SEND_ON
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditLinux = new CloudCoreoJSRunner(JSON, VARIABLES);
const notifiers = AuditLinux.getNotifiers();
callback(notifiers);
  EOH
end

## Send Notifiers
coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action :notify
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end
