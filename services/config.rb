
coreo_aws_advisor_alert "ec2-get-all-instances-older-than" do
  action :define
  service :ec2
  description "find all EC2 instances that were launched prior to the specified time that do not have the specified tag"
  category "cost"
  suggested_action "terminate the instance"
  level "warning"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.launch_time"]
  operators ["<"]
  alert_when ["5.minutes.ago"]
end

coreo_aws_advisor_ec2 "advise-ec2-get-all-instances-older-than" do
  alerts ["ec2-get-all-instances-older-than"]
  action :advise
  regions ${AUDIT_AWS_EC2_TAG_EXAMPLE_REGIONS}
end

# ################################################################
# ## parse tags
# ################################################################
coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than" do
  action :run
  json_input 'STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.report'
  function <<-EOH
required_tags = [
    'MISSING_TAG'
];

ret_alerts = {};
var BreakException = {};

for (instance_id in json_input) {
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        tag_names.push(tags[i]['key'])
    }
    try {
        for(var i = 0; i < required_tags.length; i++){
            if(tag_names.indexOf(required_tags[i]) == -1) {
                ret_alerts[instance_id] = json_input[instance_id];
                console.log("instance is in violation: " + instance_id);
                throw BreakException;
            }
        }
    } catch (e) {
        if (e !== BreakException) throw e;
    }
}

callback(ret_alerts)
  EOH
end

coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
#  payload '{"stack name":"INSTANCE::stack_name",
#  "instance name":"INSTANCE::name",
#  "number_of_checks":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_checks",
#  "number_of_violations":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_violations",
#  "number_violations_ignored":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_ignored_violations",
#  "violations": STACK::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than.return }'
  payload 'STACK::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than.return'
#  payload_type "${AUDIT_AWS_EC2_TAG_EXAMPLE_PAYLOAD_TYPE}"
  payload_type "text"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end
