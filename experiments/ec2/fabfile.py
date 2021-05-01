from fabric import Connection, ThreadingGroup, task
from utils.utils import get_ec2_instances_ips
from datetime import datetime

N = 8
F = N / 4


def get_group():
    return ThreadingGroup(*get_ec2_instances_ips(), user="ubuntu", forward_agent=True)


@task
def upload_crypto(c):

    group = get_group()

    group.run("mkdir -p crypto")

    connection: Connection

    for i, connection in enumerate(group):
        connection.put(f"../../abft/crypto/key_material{i}", remote='crypto/')


@task
def upload_binary(c):

    group = get_group()

    group.put(f"../../target/release/abft")

    group.sudo("rm /usr/local/bin/abft")

    group.sudo("mv abft /usr/local/bin/abft")


@task
def download_logs(c):

    group = get_group()

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/log.txt", local=f'logs/execution_log-node{i}-{datetime.now().strftime("%m-%d, %H:%M:%S")}')


@task
def start_protocol(c):
    group = get_group()

    connection: Connection

    for i, connection in enumerate(group):
        connection.run(
            f"nohup abft --id 0 -i {i} -n {N} -f {F} --crypto crypto/ &> /dev/null &", pty=False)


@task
def stop_protocol(c):
    group = get_group()

    group.run("pkill abft")


@task
def prepare(c):
    upload_crypto(c)
    upload_binary(c)
