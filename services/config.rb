
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
  alerts ["ec2-get-all-instances-older-than", "ec2-aws-linux-latest-not"]
  action :advise
  regions ${AUDIT_AWS_EC2_TAG_EXAMPLE_REGIONS}
end

# ################################################################
# ## finds the instances launched more than 5 minutes ago that do not meet the tags and logic as specified
# ## in the stack variables - returns a HTML table
# ################################################################
#
coreo_uni_util_jsrunner "ec2-runner-advise-no-tags-older-than" do
  action :run
  data_type "html"
  packages([
        {
          :name => "tableify",
          :version => "1.0.0"
        }       ])
  json_input 'COMPOSITE::coreo_aws_advisor_ec2.advise-ec2-samples.report'
  function <<-EOH
var tableify = require('tableify');
required_tags = [
    ${AUDIT_AWS_EC2_TAG_EXAMPLE_EXPECTED_TAGS}
];
var style_section = "\
<style>body {\
font-family :arial;\
padding : 0px;\
margin : 0px;\
}\
\
table {\
font-size: 10pt;\
border-top : black 1px solid;\
border-right : black 1px solid;\
/* border-spacing : 10px */\
border-collapse : collapse;\
}\
\
td, th {\
text-align : left;\
vertical-align : top;\
white-space: nowrap;\
overflow: hidden;\
text-overflow: ellipsis;\
border-left : black 1px solid;\
border-bottom: black 1px solid;\
padding-left : 4px;\
padding-right : 4px;\
}\
\
th {\
background-color : #aaaaaa;\
}\
\
td.number {\
color : blue\
}\
\
td.boolean {\
color : green;\
font-style : italic;\
}\
\
td.date {\
color : purple;\
}\
\
td.null:after {\
color : gray;\
font-style : italic;\
content : null;\
}\
</style>\
";
// implement case-insensitive
required_tags_lower = [];
for (var i = 0; i < required_tags.length; i++) {
  required_tags_lower.push(required_tags[i].toLowerCase());
};
required_tags_lower_string = required_tags_lower.toString().replace(/,/g,', ');;
logic = ${AUDIT_AWS_EC2_TAG_EXAMPLE_TAG_LOGIC};
if (logic == "") {logic = "and";}
ret_alerts = {};
ret_table = "[";
var BreakException = {};
num_violations = 0;
num_instances = 0;
for (instance_id in json_input) {
  inst_tags_string = "";
  num_instances++;
    console.log("examining instance: " + instance_id);
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        //console.log ("  has tag: " + tags[i]['key']);
        // implement case-insensitive
        inst_tag = tags[i]['key'];
        inst_tag = inst_tag.toLowerCase();
        tag_names.push(inst_tag);
        inst_tags_string = inst_tags_string + inst_tag + ", ";
    }
    inst_tags_string = inst_tags_string.replace(/, $/, "");
    num_required = 0;
    num_present = 0;
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
            raw_alert = json_input[instance_id];
            region = raw_alert["violations"]["ec2-get-all-instances-older-than"]["region"];
            kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
            //aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + ";sort=vpcId";
            aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + "";
            // leave off the violating_object to reduce size of the json
            aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["violating_object"] = {};
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["kill_script"] = kill_cmd;
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["aws_console"] = aws_console;
            ret_alerts[instance_id] = raw_alert;
            ret_table = ret_table + '{"instance id" : "' + instance_id + '", "region" : "' + region + '", "kill script" : "' + kill_cmd + '", "aws link" : "' + aws_console_html + '","aws tags" : "' + inst_tags_string + '"}, ';
            console.log("      instance is in violation: " + instance_id);
        }

}
    ret_table = ret_table.replace(/, $/, "");
    ret_table = ret_table + "]";
    ret_obj = JSON.parse(ret_table);
    html = tableify(ret_obj);
    // https://www.cloudcoreo.com/img/logo/logo.png
    // https://d1qb2nb5cznatu.cloudfront.net/startups/i/701250-e3792035663a30915a0b9ab26293b85b-medium_jpg.jpg?buster=1432673112
    html1 = '<p>Alerts powered by <img src="https://d1qb2nb5cznatu.cloudfront.net/startups/i/701250-e3792035663a30915a0b9ab26293b85b-medium_jpg.jpg?buster=1432673112"></p>';
    html2 = "<p>AWS tags required: " + required_tags_lower_string + "</p><p>logic: " + logic + "</p>";
    html3 = "<p>Number of Instances: " + num_instances + "</p><p>Number in Violation: " + num_violations + "</p>";
    html = html1 + html2 + html3 + html;
    // add style
    html = style_section + html;
    callback(html);

EOH
end

# same as first filter, but this one just returns a simple text of a shell script that could
# directly terminate instances that are missing tags
#
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

# send email to recipient that contains the html table of violating instances
#
coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than" do
  action :run
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
  payload '
  COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than.return
  <p>stack name: PLAN::stack_name</p>
  <p>instance name: PLAN::name</p>
  '
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

# send email to recipient that contains just the shell script to terminate instances
#
coreo_uni_util_notify "advise-ec2-notify-no-tags-older-than-kill-all-script" do
  action :run
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_TAG_EXAMPLE_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_TAG_EXAMPLE_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.ec2-runner-advise-no-tags-older-than-kill-all-script.return'
  payload_type "text"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_TAG_EXAMPLE_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

