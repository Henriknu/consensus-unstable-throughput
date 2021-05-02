import boto3

N = 8
F = 2

SERVER_AMI_NAME = 'abft-ubuntu-ami-20210430213719'
SERVER_INSTANCE_TYPE = 't2.micro'
SERVER_REGION = "us-east-2"
NAME_FILTER = 'ABFT'
SECURITY_GROUP_ID = 'sg-03b657f73c0d0ad3e'
SSH_KEY_NAME = 'AWS Micro Testing'


def get_ec2_instances_ips():

    ec2_resource = boto3.resource("ec2")

    running_instances = ec2_resource.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

    ips = [instance.public_dns_name for instance in running_instances]

    return ips


def get_ec2_instances_ids(FilterNames: str = None):
    ec2_resource = boto3.resource("ec2")

    instances = ec2_resource.instances

    if FilterNames:
        instances = ec2_resource.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': FilterNames}])

    ids = [instance.instance_id for instance in instances]

    return ids


def ipAll():
    result = []
    result += get_ec2_instances_ips()
    open('hosts', 'w').write('\n'.join(result))
    return result


def launch(number):

    ec2_client = boto3.client('ec2', region_name=SERVER_REGION)

    img_id = ec2_client.describe_images(
        Filters=[{'Name': 'name', 'Values': [SERVER_AMI_NAME]}])['Images'][0]['ImageId']

    ec2_resource = boto3.resource("ec2")

    instances = ec2_resource.create_instances(
        InstanceType=SERVER_INSTANCE_TYPE, MinCount=number, MaxCount=number, ImageId=img_id, KeyName=SSH_KEY_NAME, SecurityGroupIds=[SECURITY_GROUP_ID], TagSpecifications=[
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


def terminate_all():

    ec2_client = boto3.client('ec2', region_name=SERVER_REGION)

    ec2_client.terminate_instances(
        InstanceIds=get_ec2_instances_ids(FilterNames=['running', 'stopped']))


def monitor_all():
    ec2_client = boto3.client('ec2', region_name=SERVER_REGION)
    ec2_resource = boto3.resource("ec2")

    pass


def stop_all():
    ec2_client = boto3.client('ec2', region_name=SERVER_REGION)
    ec2_client.stop_instances(
        InstanceIds=get_ec2_instances_ids(FilterNames=['running']))


def start_all():
    ec2_client = boto3.client('ec2', region_name=SERVER_REGION)
    ec2_client.start_instances(
        InstanceIds=get_ec2_instances_ids(FilterNames=['stopped']))


if __name__ == '__main__':

    from IPython import embed
    embed()
