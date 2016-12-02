
# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#
coreo_aws_advisor_alert "ec2-get-all-instances-older-than" do
  action :define
  service :ec2
  display_name "Alert to Kill"
  description "EC2 instance was launched within the last 5 minutes that violates tag policy (does not have the necessary tags)."
  category "Policy"
  suggested_action "Review instance tags and terminate the instance if it does not comply to tagging policy."
  level "Warning"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.launch_time"]
  operators ["<"]
  alert_when ["5.minutes.ago"]
end

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

# this resource simply executes the alert that was defined above
#
coreo_aws_advisor_ec2 "advise-ec2-samples" do
  alerts ["ec2-get-all-instances-older-than"]
  action :${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_ADVISE}
  regions ${AUDIT_AWS_EC2_SAMPLES_REGIONS}
end

coreo_aws_advisor_ec2 "advise-ec2-samples-2" do
  alerts ["ec2-aws-linux-latest-not"]
  action :${AUDIT_AWS_EC2_SAMPLES_LATEST_AWS_LINUX_ADVISE}
  regions ["${REGION}"]
end

# coreo_uni_util_jsrunner "advisor-output-conditional" do
#   action :run
#   data_type "json"
#   json_input 'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report'
#   function <<-EOH
# console.log('advisor-output-conditional is running');
# return_value = "";
# if (null === json_input) {
#   return "{}";
# else {
#   return(json_input);
# }
# callback(return_value);
#   EOH
# end

# coreo_uni_util_jsrunner "tags-to-notifiers-array-ec2-samples" do
#   action :run
#   data_type "json"
#   packages([
#                {
#                    :name => "cloudcoreo-jsrunner-commons",
#                    :version => "1.1.2"
#                }       ])
#   json_input '{ "composite name":"PLAN::stack_name",
#                 "plan name":"PLAN::name",
#                 "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_checks",
#                 "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_violations",
#                 "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_ignored_violations",
#                 "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report}'
#   function <<-EOH
# const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
# const AuditCloudtrail = new CloudCoreoJSRunner(json_input, true, "${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_RECIPIENT}", "${AUDIT_AWS_EC2_SAMPLES_OWNER_TAG}", 'ec2-samples');
# const notifiers = AuditCloudtrail.getNotifiers();
# callback(notifiers);
#   EOH
# end

# Send ec2-samples for email
# coreo_uni_util_notify "advise-ec2-samples-to-tag-values" do
#   action :${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_NOTIF}
#   notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-samples.return'
# end

# coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than-kill-all-script" do
#   action :run
#   data_type "text"
#   packages([
#                {
#                    :name => "cloudcoreo-jsrunner-commons",
#                    :version => "1.1.2"
#                }       ])
#   json_input '{ "composite name":"PLAN::stack_name",
#                 "plan name":"PLAN::name",
#                 "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_checks",
#                 "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_violations",
#                 "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_ignored_violations",
#                 "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report}'
#   function <<-EOH
# const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
# const AuditCloudtrail = new CloudCoreoJSRunner(json_input, true, "${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_RECIPIENT}", "${AUDIT_AWS_EC2_SAMPLES_OWNER_TAG}", 'ec2-samples');
# const HTMLKillScripts = AuditCloudtrail.getHTMLKillScripts();
# callback(HTMLKillScripts)
#   EOH
# end

# coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
#   action :${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_NOTIF}
#   type 'email'
#   allow_empty ${AUDIT_AWS_EC2_SAMPLES_ALLOW_EMPTY}
#   send_on "${AUDIT_AWS_EC2_SAMPLES_SEND_ON}"
#   payload 'COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'
#   payload_type "html"
#   endpoint ({
#       :to => '${AUDIT_AWS_EC2_SAMPLES_ALERT_TO_KILL_RECIPIENT}', :subject => 'Untagged EC2 Instances kill script: PLAN::stack_name :: PLAN::name'
#   })
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
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_EC2_SAMPLES_LATEST_AWS_LINUX_RECIPIENT}", "${AUDIT_AWS_EC2_SAMPLES_OWNER_TAG}", 'ec2-samples');
const notifiers = AuditCloudtrail.getNotifiers();
callback(notifiers);
  EOH
end


## Send Notifiers
coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action :${AUDIT_AWS_EC2_SAMPLES_LATEST_AWS_LINUX_NOTIF}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end
