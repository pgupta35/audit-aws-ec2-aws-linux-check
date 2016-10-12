
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
// implement case-insensitive
required_tags_lower = [];
console.log(required_tags_lower);
for (var i = 0; i < required_tags.length; i++) {
  required_tags_lower.push(required_tags[i].toLowerCase());
};
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
if (logic == "") {logic = "and";}
ret_alerts = {};
var BreakException = {};

for (instance_id in json_input) {
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
          raw_alert = json_input[instance_id];
          region = raw_alert["violations"]["ec2-get-all-instances-older-than"]["region"];
          kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
          // leave off the violating_object to reduce size of the json
          raw_alert["violations"]["ec2-get-all-instances-older-than"]["violating_object"] = {};
          raw_alert["violations"]["ec2-get-all-instances-older-than"]["kill_script"] = kill_cmd;
          raw_alert["violations"]["ec2-get-all-instances-older-than"]["aws_console"] = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + ";sort=vpcId";
          ret_alerts[instance_id] = raw_alert;
          console.log("      instance is in violation: " + instance_id);
        
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
// implement case-insensitive
required_tags_lower = [];
for (var i = 0; i < required_tags.length; i++) {
  required_tags_lower.push(required_tags[i].toLowerCase());
};
console.log(required_tags_lower);
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
if (logic == "") {logic = "and";}
ret_alerts = {};
var BreakException = {};
kill_all_script = "";

for (instance_id in json_input) {
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
  payload_type "json"
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
