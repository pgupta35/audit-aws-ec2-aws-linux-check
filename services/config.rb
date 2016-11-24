
# defines as the alert any EC2 instances that were launched more than 5 minutes ago
# this set will be post-processed by the jsrunner below to examine the tags - nothing is directly
# alerted on from this definition
#
coreo_aws_advisor_alert "ec2-get-all-instances-older-than" do
  action :define
  service :ec2
  description "EC2 instance was launched within the last 5 minutes that violates tag policy (does not have the necessary tags)."
  category "Policy"
  suggested_action "Review instance tags and terminate the instance if it does not comply to tagging policy."
  level "Warning"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.launch_time"]
  operators ["<"]
  alert_when ["5.minutes.ago"]
end


#
coreo_aws_advisor_alert "ec2-aws-linux-latest-not" do
  action :define
  service :ec2
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
  action :advise
  regions ${AUDIT_AWS_EC2_TAG_EXAMPLE_REGIONS}
end

coreo_aws_advisor_ec2 "advise-ec2-samples-2" do
  alerts ["ec2-aws-linux-latest-not"]
  action :advise
  regions ["${REGION}"]
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-ec2-samples" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.0.5"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, true, "${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_NO_OWNER_RECIPIENT}", "${AUDIT_AWS_EC2_TAG_EXAMPLE_OWNER_TAG}");
const notifiers = AuditCloudtrail.getNotifiers();
callback(notifiers);
  EOH
end



# Send ec2-samples for email
coreo_uni_util_notify "advise-ec2-samples-to-tag-values" do
  action :${AUDIT_AWS_EC2_TAG_EXAMPLE_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-ec2-samples.return'
end

coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than-kill-all-script" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report'
  function <<-EOH
required_tags = [
    ${AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS}
];
// implement case-insensitive
required_tags_lower = [];
for (var i = 0; i < required_tags.length; i++) {
  required_tags_lower.push(required_tags[i].toLowerCase());
};
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
if (logic == "") {logic = "and";}
ret_alerts = {};
var BreakException = {};
kill_all_script = "";
num_violations = 0;
num_instances = 0;

for (instance_id in json_input) {
    num_instances++;
    console.log("examining instance: " + instance_id);
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        //console.log ("  has tag: " + tags[i]['key']);
        // implement case-insensitive
        inst_tag = tags[i]['key'];
        inst_tag = inst_tag.toLowerCase();
        tag_names.push(inst_tag)
    }
    num_required = 0;
    num_present = 0;

    try {
        for(var i = 0; i < required_tags_lower.length; i++){
            //console.log("    does it have tag " + required_tags_lower[i] + "?");
            if(tag_names.indexOf(required_tags_lower[i]) == -1) {
                //console.log("      it does not.");              
            } else {
              num_present++;
              //console.log("      it does! num_present is now: " + num_present);
            }
        }
        if (logic == "and") {
          needed = required_tags_lower.length;
        } else {
          needed = 1;  
        }
        if (num_present >= needed) {
          console.log("      instance has enough tags to pass. Need: " + needed + " and it has: " + num_present);          
        } else {
          num_violations++;
          kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
          kill_all_script = kill_all_script + kill_cmd + "\\n";
          console.log("      instance is in violation: " + instance_id);
        
        }
        throw BreakException;
      } catch (e) {
        if (e !== BreakException) throw e;
    }
}
if (kill_all_script.length > 0) {
  kill_all_script = "#!/bin/bash\\n\\n# number of instances: " + num_instances + "\\n# number in violation: " + num_violations + "\\n\\n" + kill_all_script;
} else {
  kill_all_script = "# number of instances: " + num_instances + "\\n# no instances are in violation\\n\\n";
}
callback(kill_all_script)
  EOH
end



coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'
  payload_type "text"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'Untagged EC2 Instances kill script: PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-2" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.0.5"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_NO_OWNER_RECIPIENT}", "${AUDIT_AWS_EC2_TAG_EXAMPLE_OWNER_TAG}");
const notifiers = AuditCloudtrail.getNotifiers();
callback(notifiers);
  EOH
end


## Send Notifiers
coreo_uni_util_notify "advise-ec2-notify-non-current-aws-linux-instance-2" do
  action :${AUDIT_AWS_EC2_TAG_EXAMPLE_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-2.return'
end



coreo_uni_util_notify "advise-ec2-samples-2-json" do
  action :${AUDIT_AWS_EC2_TAG_EXAMPLE_FULL_JSON_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on 'always'
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples-2.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report}'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2-samples-2 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end