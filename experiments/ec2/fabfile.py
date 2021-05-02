from fabric import Connection, ThreadingGroup, task
from utils.utils import get_ec2_instances_ips
from datetime import datetime
#from multiprocessing import Pool

N = 4
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
def prepare_hosts(c):

    group = get_group()

    ips = get_ec2_instances_ips()
    open('hosts', 'w').write('\n'.join(ips))

    group.put("hosts")


@task
def prepare_logs(c):

    group = get_group()

    group.run("mkdir -p logs")

    group.put("../../log4rs.yaml")


@task
def prepare_deps(c):

    group = get_group()

    group.sudo("apt-get install dtach -y")


@task
def download_logs(c):

    group = get_group()

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/execution.log", local=f'logs/execution_log-N{N}-node{i}-{datetime.now().strftime("%m-%d, %H:%M:%S")}')


@task
def start_protocol(c):
    group = get_group()

    connection: Connection

    for i, connection in enumerate(group):

        print(f"Starting connection: {i}")

        connection.run(
            f"RUST_LOG=info dtach -n `abft --id 0 -i {i} -n {N} -f {F} -h hosts -e $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4) --crypto crypto/`", disown=True)


@task
def stop_protocol(c):
    group = get_group()

    group.run("pkill abft")


@task
def prepare(c):
    upload_crypto(c)
    upload_binary(c)
    prepare_hosts(c)
    prepare_logs(c)
    prepare_deps(c)
