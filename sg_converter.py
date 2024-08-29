import boto3
import argparse
import sys
import json
import os
from jinja2 import Environment, PackageLoader, select_autoescape

# jinja config

jinja_env = Environment(
    loader = PackageLoader("sg_conversion"),
    autoescape = select_autoescape()
)

def generate_template(_template, _data):
    return _template.render(_data)

def create_boto_session(region: str): 
    """
    creates boto session via region and saml session
    """

    # Establish a session using the specified profile and region
    try:
        botoSession = boto3.Session(profile_name='saml', region_name=region)
    except Exception as e:
        print(f"ERROR: {e}")
        return {}
    return botoSession



def get_all_sg_info(region: str,debug: bool):
    """
    Get SG info for all regions
    
    """

    # init session and use ec2 to describe security groups for region
    
    botoSession = create_boto_session(region)
    ec2Client = botoSession.client('ec2', region_name=region)
    sgInfo = ec2Client.describe_security_groups()
    if debug:
        print(f'{sgInfo}')
    return sgInfo


def get_sg_info(region: str, sgId: str,debug: bool):

    """
    Get specific sg info 
    """
    botoSession = create_boto_session(region)
    ec2Client = botoSession.client('ec2', region_name=region)
    sgGrpInfo = ec2Client.describe_security_groups(GroupIds=[sgId])
    if debug:
        formattedSg= json.dumps(sgGrpInfo['SecurityGroups'][0], indent=4)
        with open(f"{sgGrpInfo['SecurityGroups'][0]['GroupName']}.json" ,'w+') as f:
            f.write(formattedSg) 
        print(f"{sgGrpInfo['SecurityGroups'][0]['GroupName']} {sgGrpInfo['SecurityGroups'][0]['Description']}")

    

    return sgGrpInfo['SecurityGroups'][0]

def create_cidrs(ipRanges: list):
    """creates list of cidrs from IpRanges"""
    cidrStr = ""
    for ip in ipRanges:
        if ip['CidrIp'] == ipRanges[-1]['CidrIp']:
            cidrStr+=ip['CidrIp']
        else:
            cidrStr+=f"{ip['CidrIp']},"
    if cidrStr == "":
        return "None"
    return cidrStr

def create_pflist(prefixIds: list):
    prefixIdStr = ""
    for pfId in prefixIds:
        if pfId['PrefixListId'] == prefixIds[-1]['PrefixListId']:
            prefixIdStr+=pfId['PrefixListId']
        else:
            prefixIdStr += f"{pfId['PrefixListId']},"
    if prefixIdStr == "":
        return "None"
    return prefixIdStr

def create_sg_ref_str(sgIds: list, accountId: str):
    sgStr = ""
    for obj in sgIds:
        if obj['GroupId'] == sgIds[-1]['GroupId']:
            
            if accountId == obj['UserId']:
                sgStr+=obj['GroupId']
            else:
                sgStr+=f"{obj['UserId']}/{obj['GroupId']}"
        else:
            if accountId == obj['UserId']:
                sgStr+=f"{obj['GroupId']},"
            else:
                sgStr+=f"{obj['UserId']/obj['GroupId']},"
    if sgStr == "":
        return "None"
    return sgStr

def get_rule_desc(obj):
    """
    gets a rule description if it exists
    
    """
    for itm in obj['IpRanges']:
        try:
            ruleDesc = itm['Description']
            print(ruleDesc)
            if len(ruleDesc) > 1:
                return itm['Description']
        except:
            ruleDesc = ""
    for itm in obj['UserIdGroupPairs']:
        try:
            ruleDesc = itm['Description']
            print(ruleDesc)
            if len(ruleDesc) > 1:
                return itm['Description']
        except:
            ruleDesc = ""
    for itm in obj['PrefixListIds']:
        try:
            ruleDesc = itm['Description']
            print(ruleDesc)
            if len(ruleDesc) > 1:
                return itm['Description']
        except:
            ruleDesc = ""
    
def convert_to_tf(region: str, sgId: str, debug: bool, tfFileName: str):
    # sg_id, vpc_id, sg_name
    sgInfo = get_sg_info(region, sgId, debug)
        
    # Generate template


    ingress_rules = []
    for obj in sgInfo['IpPermissions']:
        # check if rule is for self

        for sgPair in obj['UserIdGroupPairs']:
            if sgId == sgPair['GroupId'] and sgPair['UserId'] == sgInfo['OwnerId']:
                is_self = "true"
                break
            else:
                is_self = "false"
        else:
            is_self = "false"
        if obj['IpProtocol'] == '-1':
            obj['FromPort'] = '0'
            obj['ToPort'] = '0'
        rule = {
            "from_port": str(obj['FromPort']), 
            "to_port": str(obj['ToPort']), 
            "proto": obj['IpProtocol'], 
            "cidr_blocks": create_cidrs(obj['IpRanges']), 
            "prefix_list_ids":create_pflist(obj['PrefixListIds']),
            "security_groups": create_sg_ref_str(obj['UserIdGroupPairs'],sgInfo['OwnerId']), 
            "description": f"{get_rule_desc(obj)}",
            "if_self": is_self
        }
        ingress_rules.append(rule)

    egress_rules = []
    for obj in sgInfo['IpPermissionsEgress']:
        # check if rule is for self

        for sgPair in obj['UserIdGroupPairs']:
            if sgId == sgPair['GroupId'] and sgPair['UserId'] == sgInfo['OwnerId']:
                is_self = "true"
                break
            else:
                is_self = "false"
        
        if obj['IpProtocol'] == '-1':
            obj['FromPort'] = '0'
            obj['ToPort'] = '0'
        rule = {
            "from_port": str(obj['FromPort']), 
            "to_port": str(obj['ToPort']), 
            "proto": obj['IpProtocol'], 
            "cidr_blocks": create_cidrs(obj['IpRanges']), 
            "prefix_list_ids":create_pflist(obj['PrefixListIds']),
            "security_groups": create_sg_ref_str(obj['UserIdGroupPairs'],sgInfo['OwnerId']), 
            "description": f"{get_rule_desc(obj)}",
            "if_self": is_self
        }
        egress_rules.append(rule)   
    egressRules = egress_rules
    ingressRules = ingress_rules
    vs_template = generate_template(
        
        _template = jinja_env.get_template("sg_template.jinja2"),
        _data = {
            "sg_name": sgInfo['GroupName'],
            "vpc_id": sgInfo['VpcId'],
            "sg_id": sgInfo['GroupId'].replace("-","_"),
            "sg_desc": sgInfo['Description'],
            "ingress_rules": ingressRules,
            "egress_rules" : egressRules,
            "tags": sgInfo['Tags']
            }
    )

    # Write template to file

    with open(os.getcwd() + f"/{tfFileName}.tf", "a+") as fd:
        fd.write(vs_template)

if __name__ == "__main__":

    activeHHCRegions = ['us-east-1', 'us-west-2', 'us-east-2', 'eu-west-2', 'eu-central-1', 'ap-southeast-1'] # udpate with hlt specific info when required

    parser = argparse.ArgumentParser(description="GNE Security group conversion tool")
    parser.add_argument('-s', '--security-group-id', type=str, help="AWS Security Group ID to grab info")
    parser.add_argument('-r', '--region', type=str, required=True, help="AWS Region to get security groups", choices=activeHHCRegions) 
    parser.add_argument('-t', '--generate-tf', type=str, help="Generates terraform file with the given name")
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debug mode")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.region and not args.security_group_id:
        get_all_sg_info(args.region, args.debug)

    if args.region and args.security_group_id:
        get_sg_info(args.region, sgId=args.security_group_id, debug=args.debug)

    if args.generate_tf:
        convert_to_tf(args.region, args.security_group_id, args.debug,args.generate_tf)