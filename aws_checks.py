# aws_checks_refactored.py
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

# -----------------------
# Session / Role Handling
# -----------------------
def assume_role(role_arn, session_name='infra-scan'):
    sts = boto3.client('sts')
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = resp['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )


# -----------------------
# S3 Checks
# -----------------------
def list_s3_buckets(session=None):
    s = session or boto3.Session()
    client = s.client('s3')
    resp = client.list_buckets()
    return [b['Name'] for b in resp.get('Buckets', [])]


def inspect_bucket(session=None, bucket_name=None, max_objects_head=50):
    """Enhanced bucket inspection with encryption, versioning, policy, and object-level SSE checks"""
    s3 = (session or boto3.Session()).client('s3')
    findings = {'bucket': bucket_name, 'issues': [], 'meta': {}}

    # --- Public access block ---
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        findings['meta']['public_access_block'] = pab.get('PublicAccessBlockConfiguration', {})
    except ClientError as e:
        findings['meta']['public_access_block_error'] = str(e)

    # --- Versioning ---
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        findings['meta']['versioning'] = ver
        if ver.get('Status') != 'Enabled':
            findings['issues'].append('Bucket versioning not enabled')
    except ClientError as e:
        findings['meta']['versioning_error'] = str(e)

    # --- Encryption ---
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc['ServerSideEncryptionConfiguration']['Rules']
        findings['meta']['encryption_rules'] = rules
        uses_kms = any('aws:kms' in r.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm','') for r in rules)
        if not uses_kms:
            findings['issues'].append('Bucket default encryption does not use KMS')
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code == 'ServerSideEncryptionConfigurationNotFoundError':
            findings['issues'].append('Bucket has no default encryption configured')
        else:
            findings['meta']['encryption_error'] = str(e)

    # --- Bucket policy / resource policy ---
    try:
        pol = s3.get_bucket_policy(Bucket=bucket_name)
        findings['meta']['bucket_policy'] = pol['Policy']
        if '"Principal":"*"' in pol['Policy'] or '"AWS":"*"' in pol['Policy']:
            findings['issues'].append('Bucket policy allows public access (Principal: *)')
    except ClientError as e:
        findings['meta']['bucket_policy_error'] = str(e)

    # --- Object-level SSE check (sample) ---
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects_head).get('Contents', [])
        object_issues = []
        for o in objs:
            try:
                head = s3.head_object(Bucket=bucket_name, Key=o['Key'])
                if head.get('ServerSideEncryption') is None:
                    object_issues.append({'key': o['Key'], 'issue': 'object not encrypted'})
            except ClientError:
                object_issues.append({'key': o['Key'], 'issue': 'head_object failed'})
        if object_issues:
            findings['issues'].append({'objects_without_sse_sample': object_issues})
    except ClientError as e:
        findings['meta']['list_objects_error'] = str(e)

    # --- Key insights for S3 ---
    insights = []
    if findings['issues']:
        insights.append(f"{len(findings['issues'])} issues found")
    else:
        insights.append("Bucket follows best practices")
    findings['meta']['insights'] = insights

    return findings


def get_s3_cost_estimate(profile_name=None, region="us-east-1"):
    """S3 cost per bucket using Cost Explorer"""
    session = boto3.Session(profile_name=profile_name, region_name=region)
    ce = session.client("ce")
    end = datetime.utcnow().replace(day=1)
    start = (end - timedelta(days=1)).replace(day=1)
    time_period = {"Start": start.strftime("%Y-%m-%d"), "End": end.strftime("%Y-%m-%d")}

    try:
        response = ce.get_cost_and_usage(
            TimePeriod=time_period,
            Granularity="MONTHLY",
            Metrics=["BlendedCost"],
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Simple Storage Service"]}},
        )
        results = []
        for result in response["ResultsByTime"]:
            for group in result.get("Groups", []):
                bucket_name = group.get("Keys", ["Unknown"])[0]
                amount = float(group["Metrics"]["BlendedCost"]["Amount"])
                currency = group["Metrics"]["BlendedCost"]["Unit"]
                results.append({"bucket_name": bucket_name, "amount": amount, "currency": currency})
        if not results:
            total = float(response["ResultsByTime"][0]["Total"]["BlendedCost"]["Amount"])
            currency = response["ResultsByTime"][0]["Total"]["BlendedCost"]["Unit"]
            results.append({"bucket_name": "All S3 Buckets", "amount": total, "currency": currency})
        return results
    except Exception as e:
        return {"error": str(e)}


# -----------------------
# KMS Checks
# -----------------------
def check_kms_keys(session=None):
    s = session or boto3.Session()
    kms = s.client('kms')
    keys = []
    paginator = kms.get_paginator('list_keys')
    for page in paginator.paginate():
        for k in page.get('Keys', []):
            kid = k['KeyId']
            desc = kms.describe_key(KeyId=kid)['KeyMetadata']
            rotation = None
            try:
                rotation = kms.get_key_rotation_status(KeyId=kid)['KeyRotationEnabled']
            except ClientError:
                rotation = None
            # --- Insights ---
            if not rotation:
                insight = "Rotation not enabled"
            else:
                insight = "Rotation enabled"
            keys.append({
                'KeyId': kid,
                'Description': desc.get('Description'),
                'KeyState': desc.get('KeyState'),
                'RotationEnabled': rotation,
                'PolicyExists': True,
                'insight': insight
            })
    return keys


# -----------------------
# IAM Checks
# -----------------------
def check_iam_policies(session=None, max_entities=50):
    s = session or boto3.Session()
    iam = s.client('iam')
    issues = []
    for role in iam.list_roles(MaxItems=max_entities).get('Roles', []):
        role_name = role['RoleName']
        attached = iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
        inline = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
        for p in inline:
            pol = iam.get_role_policy(RoleName=role_name, PolicyName=p)['PolicyDocument']
            doc_str = str(pol)
            if '"*" in doc_str or "'*' in doc_str" in doc_str or "Action": "*"' in doc_str:
                issues.append({'entity': role_name, 'policy': p, 'issue': 'Potential wildcard in inline role policy'})
        for ap in attached:
            if ap['PolicyName'] in ('AdministratorAccess',):
                issues.append({'entity': role_name, 'policy': ap['PolicyName'], 'issue': 'Attached admin policy'})
    return issues


# -----------------------
# Security Groups Checks
# -----------------------
def check_security_groups(session=None, region='us-east-1'):
    ec2 = (session or boto3.Session(region_name=region)).client('ec2', region_name=region)
    findings = []
    resp = ec2.describe_security_groups()
    for sg in resp.get('SecurityGroups', []):
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                from_port = perm.get('FromPort')
                to_port = perm.get('ToPort')
                if cidr == '0.0.0.0/0' and (from_port in (22,3389) or (from_port and from_port <= 1024)):
                    findings.append({'GroupId': sg['GroupId'], 'issue': f'Ingress wide-open {cidr} to ports {from_port}-{to_port}'})
    return findings


# -----------------------
# AWS Action Registry (Dynamic Mapping)
# -----------------------
AWS_ACTIONS = {
    "s3": {
        "list": list_s3_buckets,
        "status": inspect_bucket,
        "cost": get_s3_cost_estimate
    },
    "kms": {
        "check": check_kms_keys
    },
    "iam": {
        "check": check_iam_policies
    },
    "security": {
        "check": check_security_groups
    }
}


def call_aws_action(service: str, intent: str, *args, **kwargs):
    """Call AWS function dynamically using registry"""
    try:
        func = AWS_ACTIONS[service][intent]
        return func(*args, **kwargs)
    except KeyError:
        return {"error": f"No action found for service={service}, intent={intent}"}
