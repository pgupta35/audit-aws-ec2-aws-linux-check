
# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#

coreo_aws_advisor_alert "ec2-aws-linux-latest-not" do
  action :define
  service :ec2
  display_name "Not Latest AWS Linux AMI Instances"
  description "Alerts on EC2 instances that were not launched from the latest AWS Linux AMI."
  category "TBS"
  suggested_action "TBS"
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

coreo_uni_util_jsrunner "jsrunner-composite-access" do
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
    for (var key in json_input['violations']) {
    }

    var cases = properties["variables"]["AWS_LINUX_AMI"]["cases"];
    for (var key in cases) {
        value = cases[key];
        console.log(value);
    }

    callback(json_input["hi always"]);
});
  EOH
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.1.7"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.report}'
  function <<-EOH
  
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}";
const AUDIT_NAME = 'ec2-samples';
const IS_KILL_SCRIPTS_SHOW = false;
const EC2_LOGIC = ''; // you can choose 'and' or 'or';
const EXPECTED_TAGS = [];

const VARIABLES = {
    'NO_OWNER_EMAIL': NO_OWNER_EMAIL,
    'OWNER_TAG': OWNER_TAG,
    'AUDIT_NAME': AUDIT_NAME,
    'IS_KILL_SCRIPTS_SHOW': IS_KILL_SCRIPTS_SHOW,
    'EC2_LOGIC': EC2_LOGIC,
    'EXPECTED_TAGS': EXPECTED_TAGS
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
