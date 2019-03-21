
import boto3
import hashlib
import json
import urllib2

# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE = "s3"
# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = { 'Http' : 80, 'Https': 443 }
# Tags which identify the security groups you want to update
SECURITY_GROUP_TAG_FOR_REGION_HTTPS = { 'Name': 's3_access', 'AutoUpdate': 'true', 'Protocol': 'https' }


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # extract the service ranges
    #global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")
    ip_ranges = { "REGION": region_cf_ranges }

    # update the security groups
    result = update_security_groups(ip_ranges)

    return result

def get_ip_groups_json(url, expected_hash):
    print("Updating from " + url)

    response = urllib2.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, service, subset):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service and ((subset == prefix['region'] and subset == "GLOBAL") or (subset != 'GLOBAL' and prefix['region'] != 'GLOBAL')):
            print('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix'])
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_security_groups(new_ranges):
    client = boto3.client('ec2')

    region_https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_REGION_HTTPS)

    print ('Found ' + str(len(region_https_group)) + ' s3_access HttpsSecurityGroups to update')

    result = list()

    region_https_updated = 0

    for group in region_https_group:
        if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https']):
            region_https_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(region_https_updated) + ' of ' + str(len(region_https_group)) + 's3_access HttpsSecurityGroups')

    return result

def update_security_group(client, group, new_ranges, port):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['FromPort'] <= port and permission['ToPort'] >= port :
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))

                for range in new_ranges:
                    if old_prefixes.count(range) == 0:
                        to_add.append({ 'CidrIp': range })
                        print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({ 'CidrIp': range })
            print(group['GroupId'] + ": Adding " + range + ":" + str(port))
        permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add)

    print (group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed))
    return (added > 0 or removed > 0)

def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def add_permissions(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def get_security_groups_for_update(client, security_group_tag):
    filters = list();
    for key, value in security_group_tag.iteritems():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

