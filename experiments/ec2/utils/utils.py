import boto3

N = 8
F = int(N/4)
I = 2
WAN = True
BATCH_SIZES = [100, 1000, 10000, 100_000, 1_000_000, 2_000_000] if WAN else [N]

SERVER_AMI_ID = 'ami-042e8287309f5df03'  # Ubuntu 20.04 64 bit x86
SERVER_INSTANCE_TYPE = 't2.micro'
NAME_FILTER = 'ABFT'
SECURITY_GROUP_ID = 'sg-0a6d95c8b0adda476'  # US East (N. Virginia)
SSH_KEY_NAME = 'AWS Micro Testing'


secgroups = {
    'us-east-1': 'sg-0a6d95c8b0adda476',  # US East (N. Virginia)
    'us-west-1': 'sg-0aca35689124ec0e6',  # US West (N. California)
    'us-west-2': 'sg-0bd192072af3d9e9d',  # US West (Oregon)
    'eu-west-1': 'sg-013d3ba90b24c1f8f',  # Europe (Ireland)
    'sa-east-1': 'sg-0de7811d778d68632',  # South America (São Paulo)
    'ap-southeast-1': 'sg-0a75411f0f4963609',  # Asia Pacific (Singapore)
    'ap-southeast-2': 'sg-00e234e13d2ed42e4',  # Asia Pacific (Sydney)
    'ap-northeast-1': 'sg-04bc0de4cfaac4ab3',  # Asia Pacific (Tokyo)
}
regions = list(secgroups)


def get_ec2_instances_ips(region):

    ec2_resource = boto3.resource("ec2", region_name=region)

    running_instances = ec2_resource.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

    ips = [instance.public_dns_name for instance in running_instances]

    return ips


def get_ec2_instances_ids(region, FilterNames: str = None):
    ec2_resource = boto3.resource("ec2", region_name=region)

    instances = ec2_resource.instances

    if FilterNames:
        instances = ec2_resource.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': FilterNames}])

    ids = [instance.instance_id for instance in instances]

    return ids


def ip_all():
    result = []
    for region in regions:
        result += get_ec2_instances_ips(region)
    return result


def launch_LAN(number=N):

    ec2_resource = boto3.resource("ec2", region_name=regions[0])

    print("Launching for", regions[0])

    instances = ec2_resource.create_instances(
        InstanceType=SERVER_INSTANCE_TYPE, MinCount=number, MaxCount=number, ImageId=SERVER_AMI_ID, KeyName=SSH_KEY_NAME, SecurityGroupIds=[SECURITY_GROUP_ID], TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': NAME_FILTER
                    },

                ]
            },
        ],)

    for instance in instances:
        instance.wait_until_running()

    print(instances[0].public_dns_name)


def launch_WAN(number=N):

    per_region: int = number // len(regions)

    remaining = number % len(regions)

    instances = []

    for region in regions:

        print("Launching for", region)

        ec2_client = boto3.client('ec2', region_name=region)

        img_id = ec2_client.describe_images(
            Filters=[{'Name': 'name', 'Values': ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200924"]}])['Images'][0]['ImageId']

        ec2_resource = boto3.resource("ec2", region_name=region)

        count = per_region

        if region == region[-1]:
            count + remaining

        pending_instances = ec2_resource.create_instances(
            InstanceType=SERVER_INSTANCE_TYPE, MinCount=per_region, MaxCount=per_region, ImageId=img_id, KeyName=SSH_KEY_NAME, SecurityGroupIds=[secgroups[region]], TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': NAME_FILTER
                        },

                    ]
                },
            ],)

        instances.append(*pending_instances)

    for instance in instances:
        instance.wait_until_running()

    print(instances[0].public_dns_name)


def terminate_all():

    for region in regions:

        ec2_client = boto3.client('ec2', region_name=region)

        instances = get_ec2_instances_ids(
            region, FilterNames=['running', 'stopped'])

        if len(instances):
            ec2_client.terminate_instances(
                InstanceIds=instances)


def monitor_all():

    for region in regions:
        ec2_client = boto3.client('ec2', region_name=region)
        ec2_resource = boto3.resource("ec2")

    pass


def stop_all():
    for region in regions:
        ec2_client = boto3.client('ec2', region_name=region)
        ec2_client.stop_instances(
            InstanceIds=get_ec2_instances_ids(region, FilterNames=['running']))


def start_all():
    for region in regions:
        ec2_client = boto3.client('ec2', region_name=region)
        ec2_client.start_instances(
            InstanceIds=get_ec2_instances_ids(region, FilterNames=['stopped']))


if __name__ == '__main__':

    from IPython import embed
    embed()
