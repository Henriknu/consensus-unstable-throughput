from fabric import Connection, task
from fabric import ThreadingGroup
from utils.utils import get_ec2_instances_ips


def get_group():
    return ThreadingGroup(*get_ec2_instances_ips(), user="ubuntu", forward_agent=True)


@task
def upload_crypto(c):

    group = get_group()

    group.run("mkdir -p crypto")

    connection: Connection

    for i, connection in enumerate(group):
        connection.put(f"../../abft/crypto/key_material{i}", remote='crypto/')
