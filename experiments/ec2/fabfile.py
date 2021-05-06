from subprocess import Popen
from fabric import Connection, ThreadingGroup, task
from utils.utils import ip_all, launch_WAN, launch_LAN, terminate_all, N, F, M, BATCH_SIZES, UNSTABLE_BATCH_SIZES, I, WAN, PACKET_LOSS_RATES, PACKET_DELAYS
from datetime import datetime
import time


@task
def prepare_awscw_agent(c, group=None):

    group.run("wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb", hide=True)
    group.sudo("dpkg -i -E ./amazon-cloudwatch-agent.deb", hide=True)
    group.run("rm ./amazon-cloudwatch-agent.deb")


@task
def upload_crypto(c, group=None):

    p = Popen(["./generate.sh",  f"{N}",  f"{int(F)}"])

    p.wait()

    group.run("mkdir -p crypto")

    connection: Connection

    for i, connection in enumerate(group):
        connection.put(f"../../abft/crypto/key_material{i}", remote='crypto/')


@task
def upload_binary(c, group=None):

    group.put(f"../../target/release/abft")

    group.sudo("mv abft /usr/local/bin/abft")


@task
def prepare_hosts(c, ips, group=None):

    open('hosts', 'w').write('\n'.join(ips))

    group.put("hosts")


@task
def clear_logs(c, group=None):

    group.sudo("rm logs/execution.log")


@task
def prepare_logs(c, group=None):

    group.run("mkdir -p logs")

    group.put("../../log4rs.yaml")


@task
def install_deps(c, group=None):

    group.sudo("apt-get update -y")
    group.sudo("apt-get upgrade -y && sudo apt-get dist-upgrade -y")
    group.sudo("apt-get install -y iproute2 dtach build-essential")


@task
def download_logs(c, b, group=None):

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/execution.log", local=f'logs/{N}_{int(F)}_{b}_[{i+1}]-{"WAN" if WAN else "LAN"}-{datetime.now().strftime("%m-%d, %H:%M")}.log')


@task
def download_logs_unstable(c, b, m, delay, packet_loss, group=None):

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/execution.log", local=f'unstable_logs/{N}_{int(F)}_{b}_unstable_{m}_{delay}_{packet_loss}_[{i+1}]-{"WAN" if WAN else "LAN"}-{datetime.now().strftime("%m-%d, %H:%M")}.log')


@task
def run_protocol(c, iteration, b, group=None):

    promises = []

    connection: Connection

    for i, connection in enumerate(group):

        print(
            f"Starting connection: {i}, N: {N}, B: {b} Iteration: {iteration}")

        promise = connection.run(
            f"RUST_LOG=info abft --id 0 -i {i} -n {N} -f {F} -b {b} -m 0 -d 0 -l 0 -h hosts -e $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4) --crypto crypto/", asynchronous=True)

        promises.append(promise)

    for promise in promises:
        promise.join()


@task
def run_protocol_unstable(c, iteration, b, m, delay, packet_loss, group=None):

    promises = []

    connection: Connection

    for i, connection in enumerate(group):

        print(
            f"Starting connection: {i}, N: {N}, B: {b}, M: {m}, D: {delay}, L: {packet_loss} Iteration: {iteration}")

        promise = connection.run(
            f"RUST_LOG=info abft --id 0 -i {i} -n {N} -f {F} -b {b} -m {m} -d {delay} -l {packet_loss} -h hosts -e $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4) --crypto crypto/", asynchronous=True)

        promises.append(promise)

    for promise in promises:
        promise.join()


@task
def stop_protocol(c, group=None):

    group.run("pkill abft")


@task
def prepare(c, ips, group=None):
    upload_crypto(c, group=group)
    upload_binary(c, group=group)
    prepare_hosts(c, ips, group=group)
    prepare_logs(c, group=group)
    # prepare_awscw_agent(c, group=group)


@task
def full(c):

    if WAN:
        launch_WAN()
    else:
        launch_LAN()

    time.sleep(20)

    ips = ip_all()

    group = ThreadingGroup(*ips,
                           user="ubuntu", forward_agent=True)

    prepare(c, ips, group=group)

    for b in BATCH_SIZES:

        for i in range(I):

            run_protocol(c, i + 1, b, group=group)

        download_logs(c, b, group=group)

        clear_logs(c, group=group)

    terminate_all()


@task
def full_unstable(c):

    if WAN:
        launch_WAN()
    else:
        launch_LAN()

    time.sleep(20)

    ips = ip_all()

    group = ThreadingGroup(*ips,
                           user="ubuntu", forward_agent=True)

    prepare(c, ips, group=group)

    for b in UNSTABLE_BATCH_SIZES:

        for m in M:

            for d in PACKET_DELAYS:

                for i in range(I):

                    run_protocol_unstable(c, i + 1, b, m, d, 0, group=group)

                download_logs_unstable(c, b, m, d, 0, group=group)

                clear_logs(c, group=group)

            for l in PACKET_LOSS_RATES:

                for i in range(I):

                    run_protocol_unstable(c, i + 1, b, m, 0, l, group=group)

                download_logs_unstable(c, b, m, 0, l, group=group)

                clear_logs(c, group=group)

    terminate_all()
