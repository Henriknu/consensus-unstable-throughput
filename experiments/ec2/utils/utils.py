import re
import time
from typing import List, Dict
from datetime import datetime
import datetime
import glob
import boto3
import pickle

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

METRIC_PERIOD = 1


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


def get_metric_data(private_host_names, starttime, endtime):

    metrics = []

    private_host_names = list(private_host_names.values())
    starttime = datetime.datetime.fromtimestamp(starttime)
    endtime = datetime.datetime.fromtimestamp(endtime)

    print(private_host_names)
    print(starttime)
    print(endtime)

    per_region: int = N // len(regions)

    remainder = N % len(regions)

    offset = 0

    prev_offset = 0

    for region in regions:

        offset += per_region

        if region == regions[-1]:
            offset += remainder

        # Create CloudWatch client
        cloudwatch = boto3.client('cloudwatch', region_name=region)

        cpu_metrics = [{"Id": f"cpu_metrics_{prev_offset + i}", "Label": f"Cpu Metrics for Party {prev_offset + i} of {region}, ip: {ip}", "MetricStat": {

            "Metric": {

                "Namespace": "CWAgent",

                "MetricName": "cpu_usage_active",

                "Dimensions": [{"Name": "host", "Value": ip}]
            },

            "Period": METRIC_PERIOD,
            "Stat": "Average",


        }} for i, ip in enumerate(private_host_names[prev_offset:offset])]

        mem_metrics = [{"Id": f"mem_metrics_{prev_offset + i}", "Label": f"Memory Metrics for Party {prev_offset + i} of {region}, ip: {ip}", "MetricStat": {

            "Metric": {

                "Namespace": "CWAgent",

                "MetricName": "mem_used",

                "Dimensions": [{"Name": "host", "Value": ip}]
            },

            "Period": METRIC_PERIOD,
            "Stat": "Average",
            "Unit": "Bytes"

        }} for i, ip in enumerate(private_host_names[prev_offset:offset])]

        net_metrics = [{"Id": f"net_metrics_{prev_offset + i}", "Label": f"Network Metrics for Party {prev_offset + i} of {region}, ip: {ip}", "MetricStat": {

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

        }} for i, ip in enumerate(private_host_names[prev_offset:offset])]

        metric_data = cloudwatch.get_metric_data(
            MetricDataQueries=[*cpu_metrics, *net_metrics, *mem_metrics], StartTime=starttime,
            EndTime=endtime)["MetricDataResults"]

        if not len(metric_data):
            print("received empty metric_data")

        print(metric_data)

        metrics.append(metric_data)

        prev_offset = offset

    return metrics


def store_metric_data_pickle(batch_size: int):

    metrics = {}

    log_file_name_list = sorted(glob.glob(
        f"logs/{N}_{F}_{batch_size}_*-" + ('WAN' if WAN else "LAN") + "*"))

    contents = [open(file_name).read().strip().split("\n\n")
                for file_name in log_file_name_list]

    for i in range(I):

        log_segments = [content[i] for content in contents]

        # Want private hostnames, starttimes and endtimes. We could get the earliest startime and latest of the logs,

        private_host_names, starttime, endtime = _get_metric_info_from_logs(
            log_segments)

        metrics[i] = get_metric_data(private_host_names, starttime, endtime)

    with open(f'metrics/{N}_{int(F)}_{batch_size}.pickle', 'wb') as handle:

        pickle.dump(metrics, handle, protocol=pickle.HIGHEST_PROTOCOL)


def store_metric_data_pickle_unstable(batch_size: int, m_parties: int, delay: int, loss: int):

    metrics = {}

    log_file_name_list = sorted(glob.glob(
        f"unstable_logs/{N}_{F}_{batch_size}_unstable_{m_parties}_{delay}_{loss}*"))

    contents = [open(file_name).read().strip().split("\n\n")
                for file_name in log_file_name_list]

    for i in range(I):

        log_segments = [content[i] for content in contents]

        # Want private hostnames, starttimes and endtimes. We could get the earliest startime and latest of the logs,

        private_host_names, starttime, endtime = _get_metric_info_from_logs(
            log_segments)

        metrics[i] = get_metric_data(private_host_names, starttime, endtime)

    with open(f'unstable_metrics/{N}_{int(F)}_{batch_size}_{m_parties}_{delay}_{loss}.pickle', 'wb') as handle:

        pickle.dump(metrics, handle, protocol=pickle.HIGHEST_PROTOCOL)


def _get_metric_info_from_logs(log_segments):
    private_host_names, starttimes, endtimes = get_host_start_end(log_segments)

    starttime = min(starttimes.values())
    endtime = max(endtimes.values())

    return private_host_names, starttime, endtime


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


def start_compiler():
    region = regions[0]

    ec2_client = boto3.client('ec2', region_name=region)
    instance = get_ec2_instances_ids(
        region, FilterNames=['stopped'])[0]

    if instance:
        print(f"Waiting for instances in region {region} to run")
        ec2_client.start_instances(
            InstanceIds=[instance])

        waiter = ec2_client.get_waiter("instance_running")

        waiter.wait(InstanceIds=[instance])


r_private = re.compile(".*private_host_name:.*")
r_start = re.compile(".*Invoking ABFT.*")
r_end = re.compile(".*terminated ABFT with value:.*")


def get_host_start_end(log_segments: List[str]):

    private_host_names: Dict[int, str] = dict()
    starttime: Dict[int, datetime] = dict()
    endtime: Dict[int, datetime] = dict()

    for i, log in enumerate(log_segments):
        for line in log.split("\n"):
            if r_start.match(line):
                starttime[i] = to_unix(
                    datetime.datetime.fromisoformat(line.split(" - ")[0]))
            elif r_end.match(line):
                endtime[i] = to_unix(
                    datetime.datetime.fromisoformat(line.split(" - ")[0]))
            elif r_private.match(line):
                private_host_names[i] = line.split(":")[4]

    return private_host_names, starttime, endtime


def to_unix(d: datetime.datetime): return time.mktime(
    d.timetuple()) + d.microsecond / 1e6


if __name__ == '__main__':

    from IPython import embed
    embed()
