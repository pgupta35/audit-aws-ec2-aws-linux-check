
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
  operators ["!="]
  alert_when ["${AWS_LINUX_AMI}"]
end

coreo_aws_advisor_ec2 "advise-ec2-samples-2" do
  alerts ["ec2-aws-linux-latest-not"]
  action :advise
  regions ["${REGION}"]
end

# the jsrunner will now allow all regions to be specified in the above advisor instead of a single region

# coreo_uni_util_jsrunner "jsrunner-composite-access" do
#   action :run
#   provide_composite_access true
#   json_input '{ "hi always": [ {"this": "resource"}, {"always": "runs"} ] }'
#   function <<-EOH
# var fs = require('fs');

# var path = '.';
# console.log('XXXXX listing dir now XXXXXX');
# fs.readdir(path, function(err, items) {
#     console.log(items);

#     for (var i=0; i<items.length; i++) {
#         console.log(items[i]);
#     }
#     callback(json_input["hi always"]);
# });

#   EOH
# end

coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.1.2"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_EC2_LINUX_CHECK_RECIPIENT}", "${AUDIT_AWS_EC2_LINUX_CHECK_OWNER_TAG}", 'ec2-samples');
const notifiers = AuditCloudtrail.getNotifiers();
callback(notifiers);
  EOH
end


## Send Notifiers
coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action :notify
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end
