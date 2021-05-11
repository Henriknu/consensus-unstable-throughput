import datetime
import glob
import boto3

N = 8  # 8, 32, 64, 100 Stable. N = 8, 64 unstable.
F = int(N/4)
I = 1
WAN = True
SHOULD_MONITOR = False
BATCH_SIZES = [100, 1000, 10000, 100_000, 1_000_000, 2_000_000] if WAN else [
    N]  # 100, 1000, 10000, 100_000 1_000_000, 2_000_000
UNSTABLE_BATCH_SIZES = {8: 10_000, 64: 1_000_000}
SHOULD_PACKET_DELAY = True
SHOULD_PACKET_LOSS = True
PACKET_LOSS_RATES = [5, 10, 15]
PACKET_DELAYS = [500, 2500, 5000]
M = [int(F/2), F, 2*F, 3*F, N]

SERVER_AMI_ID = 'ami-042e8287309f5df03'  # Ubuntu 20.04 64 bit x86
SERVER_INSTANCE_TYPE = 't2.medium'
NAME_FILTER = 'ABFT'
SECURITY_GROUP_ID = 'sg-0a6d95c8b0adda476'  # US East (N. Virginia)
SSH_KEY_NAME = 'AWS Micro Testing'
IAM_CWAGENT_ARN = "arn:aws:iam::150709297964:instance-profile/CloudWatchAgentServerRole"

METRIC_PERIOD = 300


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


def get_ec2_instances_dns(region):

    ec2_resource = boto3.resource("ec2", region_name=region)

    running_instances = ec2_resource.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

    ips = [instance.public_dns_name for instance in running_instances]

    return ips


def get_ec2_instances_private_hosts(region):

    ec2_resource = boto3.resource("ec2", region_name=region)

    ips = [instance.private_ip_address for instance in ec2_resource.instances.all()]

    hosts = ["ip-" + ip.replace(".", "-") for ip in ips]

    return hosts


def get_ec2_instances_ids(region, FilterNames: str = None):
    ec2_resource = boto3.resource("ec2", region_name=region)

    instances = ec2_resource.instances

    if FilterNames:
        instances = ec2_resource.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': FilterNames}])

    ids = [instance.instance_id for instance in instances]

    return ids


def get_metric_data(region):

    # Create CloudWatch client
    cloudwatch = boto3.client('cloudwatch', region_name=region)

    ips = get_ec2_instances_private_hosts(region)

    cpu_metrics = [{"Id": f"cpu_metrics{i}", "Label": f"Cpu Metrics for Party {i}", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "cpu_time_active",

            "Dimensions": [{"Name": "host", "Value": ip}]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Maximum",


    }} for i, ip in enumerate(ips)]

    mem_metrics = [{"Id": f"mem_metrics{i}", "Label": f"Memory Metrics for Party {i}", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "mem_used",

            "Dimensions": [{"Name": "host", "Value": ip}]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Maximum",
        "Unit": "Bytes"

    }} for i, ip in enumerate(ips)]

    net_metrics = [{"Id": f"net_metrics{i}", "Label": f"Network Metrics for Party {i}", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "net_bytes_sent",

            "Dimensions": [
                {
                    "Name": "host",
                    "Value": ip
                },
                {
                    "Name": "interface",
                    "Value": "eth0"
                }
            ]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Sum",
        "Unit": "Bytes"

    }} for i, ip in enumerate(ips)]

    response = cloudwatch.get_metric_data(
        MetricDataQueries=[*cpu_metrics, *net_metrics, *mem_metrics], StartTime=datetime.datetime.now() -
        datetime.timedelta(days=1),
        EndTime=datetime.datetime.now() + datetime.timedelta(days=1))

    print(response)


def get_metric_data2(private_host_name: str, starttime: datetime.datetime, endtime: datetime.datetime):

   # Create CloudWatch client
    cloudwatch = boto3.client('cloudwatch')

    cpu_metric = {"Id": "cpu_metrics", "Label": "Cpu Metrics for Party", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "cpu_time_active",

            "Dimensions": [{"Name": "host", "Value": private_host_name}]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Maximum",
    }}

    mem_metric = {"Id": "mem_used", "Label": "Mem Metrics for Party", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "mem_used",

            "Dimensions": [{"Name": "host", "Value": private_host_name}]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Maximum",
    }}

    net_metric = {"Id": "net_metrics", "Label": "Net Metrics for Party", "MetricStat": {

        "Metric": {

            "Namespace": "CWAgent",

            "MetricName": "net_bytes_sent",

            "Dimensions": [
                {
                    "Name": "host",
                    "Value": private_host_name
                },
                {
                    "Name": "interface",
                    "Value": "eth0"
                }
            ]
        },

        "Period": METRIC_PERIOD,
        "Stat": "Maximum",
    }}

    results = cloudwatch.get_metric_data(
        MetricDataQueries=[cpu_metric, net_metric,
                           mem_metric], StartTime=starttime,
        EndTime=endtime)["MetricDataResults"]

    print(results)

    cpu_data, mem_data, net_data = None

    return cpu_data, mem_data, net_data


def ip_all():
    result = []
    for region in regions:
        result += get_ec2_instances_dns(region)
    return result


def launch_LAN(number=N):

    region = regions[0]

    ec2_resource = boto3.resource("ec2", region_name=region)

    print(f"Launching for region {region}")

    remaining = number - \
        _get_num_unterminated_instances_for_region(ec2_resource)

    print(f"Remaining instances to launch: {remaining}")

    if remaining < 1:
        return

    instances = ec2_resource.create_instances(
        InstanceType=SERVER_INSTANCE_TYPE, IamInstanceProfile={"Arn": IAM_CWAGENT_ARN}, MinCount=remaining, MaxCount=remaining, ImageId=SERVER_AMI_ID, KeyName=SSH_KEY_NAME, SecurityGroupIds=[SECURITY_GROUP_ID], TagSpecifications=[
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

    instances[0].load()

    print(instances[0].public_dns_name)


def launch_WAN(number=N):

    per_region: int = number // len(regions)

    remainder = number % len(regions)

    print(remainder)

    instances = []

    for region in regions:

        print(f"Launching for region {region}")

        ec2_client = boto3.client('ec2', region_name=region)

        img_id = ec2_client.describe_images(
            Filters=[{'Name': 'name', 'Values': ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200924"]}])['Images'][0]['ImageId']

        ec2_resource = boto3.resource("ec2", region_name=region)

        count = per_region

        if region == regions[-1]:
            count += remainder

        print(f"Need {count} instances")

        remaining = count - \
            _get_num_unterminated_instances_for_region(ec2_resource)

        print(f"Remaining instances to launch: {remaining}")

        if remaining < 1:
            continue

        pending_instances = ec2_resource.create_instances(
            InstanceType=SERVER_INSTANCE_TYPE, IamInstanceProfile={"Arn": IAM_CWAGENT_ARN}, MinCount=remaining, MaxCount=remaining, ImageId=img_id, KeyName=SSH_KEY_NAME, SecurityGroupIds=[secgroups[region]], TagSpecifications=[
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

        instances.extend(pending_instances)

    if len(instances):

        for instance in instances:
            instance.wait_until_running()

        instances[0].load()

        print(instances[0].public_dns_name)


def _get_num_unterminated_instances_for_region(ec2_resource):
    terminated = ec2_resource.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['terminated']}])

    instances = [
        instance for instance in ec2_resource.instances.all() if instance not in terminated]

    return len(instances)


def terminate_all():

    for region in regions:

        ec2_client = boto3.client('ec2', region_name=region)

        instances = get_ec2_instances_ids(
            region, FilterNames=['running', 'stopped'])

        if len(instances):
            ec2_client.terminate_instances(
                InstanceIds=instances)


def stop_all():
    stopped_instances = []
    for region in regions:
        print("Stopping instances in region:", region)
        ec2_client = boto3.client('ec2', region_name=region)
        instances = get_ec2_instances_ids(
            region, FilterNames=['running', "pending"])
        stopped_instances.append(instances)
        if len(instances):
            ec2_client.stop_instances(
                InstanceIds=instances)

    for i, region in enumerate(regions):
        print(f"Waiting for instances in region {region} to stop")
        ec2_client = boto3.client('ec2', region_name=region)
        waiter = ec2_client.get_waiter("instance_stopped")

        if len(stopped_instances[i]):
            waiter.wait(InstanceIds=stopped_instances[i])


def start_N_WAN(number=N):
    per_region: int = number // len(regions)

    remainder = number % len(regions)

    started_instances = []

    for region in regions:

        ec2_client = boto3.client('ec2', region_name=region)
        instances = get_ec2_instances_ids(region, FilterNames=['stopped'])

        count = per_region

        if region == regions[-1]:
            count += remainder

        print(f"Starting {count} instances in region:", region)

        instances = instances[0:count]

        started_instances.append(instances)

        if len(instances):
            ec2_client.start_instances(
                InstanceIds=instances)

    for i, region in enumerate(regions):
        print(f"Waiting for instances in region {region} to run")
        ec2_client = boto3.client('ec2', region_name=region)
        waiter = ec2_client.get_waiter("instance_running")

        if len(started_instances[i]):
            waiter.wait(InstanceIds=started_instances[i])


def start_N_LAN(number=N):

    region = regions[0]

    ec2_client = boto3.client('ec2', region_name=region)
    instances = get_ec2_instances_ids(
        region, FilterNames=['stopped'])

    instances = instances[0:number]

    print(f"Starting {number} instances in region:", region)

    if len(instances):
        print(f"Waiting for instances in region {region} to run")
        ec2_client.start_instances(
            InstanceIds=instances)

        waiter = ec2_client.get_waiter("instance_running")

        waiter.wait(InstanceIds=instances)


if __name__ == '__main__':

    from IPython import embed
    embed()
