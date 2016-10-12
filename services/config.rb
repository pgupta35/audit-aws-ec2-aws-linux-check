
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
    ${AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS}
];
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
ret_alerts = {};
var BreakException = {};
kill_all_script = [];

for (instance_id in json_input) {
    console.log("examining instance: " + instance_id);
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        tag_names.push(tags[i]['key'])
        console.log ("  has tag: " + tags[i]['key']);
    }
    num_required = 0;
    num_present = 0;

    try {
        for(var i = 0; i < required_tags.length; i++){
            console.log("    does it have tag " + required_tags[i] + "?");
            if(tag_names.indexOf(required_tags[i]) == -1) {
                console.log("      it does not.");              

            } else {
              num_present++;
              console.log("      it does! num_present is now: " + num_present);
            }
        }
        if (logic == "and") {
          needed = required_tags.length;
        } else {
          needed = 1;  
        }
        if (num_present >= needed) {
          console.log("      instance has enough tags to pass. Need: " + needed + " and it has: " + num_present);          
        } else {
          raw_alert = json_input[instance_id];
            region = raw_alert["violations"]["ec2-get-all-instances-older-than"]["region"];
            kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["kill_script"] = kill_cmd;
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["aws_console"] = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + ";sort=vpcId";
            ret = kill_all_script.push(kill_cmd);
            console.log("      ret: " + ret + " kill_cmd: " + kill_cmd);
            ret_alerts[instance_id] = raw_alert;
          console.log("      instance is in violation: " + instance_id);
        
        }
        if (kill_all_script.length > 0) {
          ret_alerts["kill_all_script"] = kill_all_script;
        }
        throw BreakException;
      } catch (e) {
        if (e !== BreakException) throw e;
    }
}

callback(ret_alerts)
  EOH
end

coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than-kill-all-script" do
  action :run
  json_input 'STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.report'
  function <<-EOH
required_tags = [
    ${AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS}
];
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
ret_alerts = {};
var BreakException = {};
kill_all_script = "";

for (instance_id in json_input) {
    console.log("examining instance: " + instance_id);
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        tag_names.push(tags[i]['key'])
        console.log ("  has tag: " + tags[i]['key']);
    }
    num_required = 0;
    num_present = 0;

    try {
        for(var i = 0; i < required_tags.length; i++){
            console.log("    does it have tag " + required_tags[i] + "?");
            if(tag_names.indexOf(required_tags[i]) == -1) {
                console.log("      it does not.");              

            } else {
              num_present++;
              console.log("      it does! num_present is now: " + num_present);
            }
        }
        if (logic == "and") {
          needed = required_tags.length;
        } else {
          needed = 1;  
        }
        if (num_present >= needed) {
          console.log("      instance has enough tags to pass. Need: " + needed + " and it has: " + num_present);          
        } else {
            kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
            kill_all_script = kill_all_script + kill_cmd + "; ";
            console.log("      instance is in violation: " + instance_id);
        
        }
        throw BreakException;
      } catch (e) {
        if (e !== BreakException) throw e;
    }
}

callback(kill_all_script)
  EOH
end

coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_checks",
  "violations": STACK::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than.return }'
  payload_type "${AUDIT_AWS_EC2_TAG_EXAMPLE_PAYLOAD_TYPE}"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end

coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
  payload 'STACK::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'
  payload_type "text"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end

#  "number_of_violations":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_violations",
#  "number_violations_ignored":"STACK::coreo_aws_advisor_ec2.advise-ec2-get-all-instances-older-than.number_ignored_violations",
