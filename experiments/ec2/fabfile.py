import os
from subprocess import Popen
from fabric import Connection, ThreadingGroup, task
from utils.utils import ip_all, start_N_LAN, start_N_WAN, start_compiler, stop_all, N, F, M, BATCH_SIZES, UNSTABLE_BATCH_SIZES, I, WAN, PACKET_LOSS_RATES, PACKET_DELAYS, SHOULD_MONITOR, SHOULD_PACKET_DELAY, SHOULD_PACKET_LOSS
from datetime import datetime
import time


SHOULD_USE_EC2_BUILT_BINARY = False


def get_group():
    ips = ip_all()

    return ThreadingGroup(*ips,
                          user="ubuntu", forward_agent=True)


@task
def compile_binary_and_crypto(c):

    def put_dir(conn: Connection, source, target):
        for item in os.listdir(source):
            if os.path.isfile(os.path.join(source, item)):
                conn.put(os.path.join(source, item),
                         remote='%s/%s' % (target, item))
            else:
                conn.run('mkdir -p %s/%s' % (target, item))
                put_dir(conn, os.path.join(source, item),
                        '%s/%s' % (target, item))

    start_compiler()

    ip = ip_all()[0]

    print(ip)

    time.sleep(20)

    conn = Connection(ip, user="ubuntu", forward_agent=True)

    conn.sudo("apt-get update -y")
    conn.sudo("apt-get upgrade -y && sudo apt-get dist-upgrade -y")
    conn.sudo(
        "apt-get install -y iproute2 dtach build-essential make automake autoconf libtool")

    conn.sudo(
        "curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y")

    conn.run(
        "/home/ubuntu/.cargo/bin/rustup toolchain add nightly-2021-04-25 && \
        /home/ubuntu/.cargo/bin/rustup default nightly-2021-04-25 && \
        /home/ubuntu/.cargo/bin/rustup component add --toolchain nightly-2021-04-25 rustfmt clippy rust-src && \
        /home/ubuntu/.cargo/bin/rustup update")

    put_dir(conn, "../../consensus-core", "consensus-core/")

    put_dir(conn, "../../abft", "abft/")

    with conn.cd("abft"):

        conn.run("mkdir -p .cargo")

        conn.put(".cargo/config.toml", remote="abft/.cargo/")

        conn.run("/home/ubuntu/.cargo/bin/cargo build --release")

        conn.run(
            f"/home/ubuntu/.cargo/bin/cargo run --release --bin generate_crypto {N} {F}")

        conn.get("abft/target/release/abft", local="abft")

        result = conn.run("ls crypto/")

        files = result.stdout.split()

        for file in files:
            conn.get(f"abft/abft/crypto/{file}", local=f"crypto/{file}")

    stop_all()


@task
def prepare_awscw_agent(c, group=None):

    if not group:
        group = get_group()

    group.run("wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb", hide=True)
    group.sudo("dpkg -i -E ./amazon-cloudwatch-agent.deb", hide=True)
    group.put("amazon-cloudwatch-agent.json")
    group.run("rm ./amazon-cloudwatch-agent.deb")


@task
def start_awscw_agent(c, group=None):

    if not group:
        group = get_group()

    group.sudo(
        "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:amazon-cloudwatch-agent.json", hide=True)


@task
def upload_crypto(c, group=None):

    if not group:
        group = get_group()

    if not SHOULD_USE_EC2_BUILT_BINARY:

        p = Popen(["./generate.sh",  f"{N}",  f"{int(F)}"])

        p.wait()

    print("Uploading crypto")

    group.run("mkdir -p crypto")

    path = "crypto" if SHOULD_USE_EC2_BUILT_BINARY else "../../abft/crypto"

    connection: Connection

    for i, connection in enumerate(group):
        connection.put(f"{path}/key_material{i}", remote='crypto/')


@task
def upload_binary(c, group=None):

    print("Uploading binary")

    if not group:
        group = get_group()

    path = "abft" if SHOULD_USE_EC2_BUILT_BINARY else "../../target/release/abft"

    group.run("mkdir -p binary")

    group.put(path, remote="binary/abft")

    group.sudo("mv binary/abft /usr/local/bin/abft")


@task
def prepare_hosts(c, ips, group=None):

    print("Preparing hosts")

    if not group:
        group = get_group()

    open('hosts', 'w').write('\n'.join(ips))

    group.put("hosts")


@task
def clear_logs(c, group=None):

    if not group:
        group = get_group()

    group.sudo("rm logs/execution.log")


@task
def prepare_logs(c, group=None):

    print("Preparing logs")

    if not group:
        group = get_group()

    group.run("mkdir -p logs")

    group.put("../../log4rs.yaml")


@task
def install_deps(c, group=None):

    if not group:
        group = get_group()

    group.sudo("apt-get update -y")
    group.sudo("apt-get upgrade -y && sudo apt-get dist-upgrade -y")
    group.sudo("apt-get install -y iproute2 dtach build-essential")


@task
def download_logs(c, b, group=None):

    if not group:
        group = get_group()

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/execution.log", local=f'logs/{N}_{int(F)}_{b}_[{i+1}]-{"WAN" if WAN else "LAN"}-{datetime.now().strftime("%m-%d, %H:%M")}.log')


@task
def download_logs_unstable(c, b, m, delay, packet_loss, group=None):

    if not group:
        group = get_group()

    connection: Connection

    for i, connection in enumerate(group):
        connection.get(
            f"logs/execution.log", local=f'unstable_logs/{N}_{int(F)}_{b}_unstable_{m}_{delay}_{packet_loss}_[{i+1}]-{"WAN" if WAN else "LAN"}-{datetime.now().strftime("%m-%d, %H:%M")}.log')


@task
def run_protocol(c, iteration, b, group=None):

    if not group:
        group = get_group()

    promises = []

    connection: Connection

    for i, connection in enumerate(group):

        print(
            f"Starting connection: {i + 1}, N: {N}, B: {b} Iteration: {iteration}")

        promise = connection.run(
            f"RUST_LOG=info abft --id 0 -i {i} -n {N} -f {F} -b {b} --iterations {I} -m 0 -d 0 -l 0 -h hosts -e $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4) --crypto crypto/", asynchronous=True)

        promises.append(promise)

    for promise in promises:
        promise.join()


@task
def run_protocol_unstable(c, iteration, b, m, delay, packet_loss, group=None):

    if not group:
        group = get_group()

    promises = []

    connection: Connection

    for i, connection in enumerate(group):

        print(
            f"Starting connection: {i + 1}, N: {N}, B: {b}, M: {m}, D: {delay}, L: {packet_loss} Iteration: {iteration}")

        promise = connection.run(
            f"RUST_LOG=info abft --id 0 -i {i} -n {N} -f {F} -b {b} --iterations {I} -m {m} -d {delay} -l {packet_loss} -h hosts -e $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4) --crypto crypto/", asynchronous=True)

        promises.append(promise)

    for promise in promises:
        promise.join()


@task
def stop_protocol(c, group=None):

    if not group:
        group = get_group()

    group.run("pkill abft")


@task
def setup(c, ips, group=None):

    if WAN:
        start_N_WAN()
    else:
        start_N_LAN()

    time.sleep(20)

    ips = ip_all()

    group = ThreadingGroup(*ips,
                           user="ubuntu", forward_agent=True)

    print("Setting up instances")

    if not group:
        group = get_group()

    upload_crypto(c, group=group)
    upload_binary(c, group=group)
    prepare_hosts(c, ips, group=group)
    prepare_logs(c, group=group)

    stop_all()


@task
def prepare(c, ips, group=None):

    if not group:
        group = get_group()

    upload_crypto(c, group=group)
    upload_binary(c, group=group)
    prepare_hosts(c, ips, group=group)
    prepare_logs(c, group=group)


@task
def full(c):

    if WAN:
        start_N_WAN()
    else:
        start_N_LAN()

    time.sleep(20)

    ips = ip_all()

    group = ThreadingGroup(*ips,
                           user="ubuntu", forward_agent=True)

    prepare(c, ips, group=group)

    if SHOULD_MONITOR and WAN:
        prepare_awscw_agent(c, group=group)

    for b in BATCH_SIZES:

        print("Running experiments with batch size:", b)

        for i in range(I):

            run_protocol(c, i + 1, b, group=group)

        download_logs(c, b, group=group)

        clear_logs(c, group=group)

    stop_all()


@task
def full_unstable(c):

    if WAN:
        start_N_WAN()
    else:
        start_N_LAN()

    time.sleep(20)

    ips = ip_all()

    group = ThreadingGroup(*ips,
                           user="ubuntu", forward_agent=True)

    prepare(c, ips, group=group)

    if SHOULD_MONITOR and WAN:
        prepare_awscw_agent(c, group=group)

    b = UNSTABLE_BATCH_SIZES[N]

    for m in M:

        if SHOULD_PACKET_DELAY:

            for d in PACKET_DELAYS:

                for i in range(I):

                    run_protocol_unstable(
                        c, i + 1, b, m, d, 0, group=group)

                download_logs_unstable(c, b, m, d, 0, group=group)

                clear_logs(c, group=group)

        if SHOULD_PACKET_LOSS:

            for l in PACKET_LOSS_RATES:

                for i in range(I):

                    run_protocol_unstable(
                        c, i + 1, b, m, 0, l, group=group)

                download_logs_unstable(c, b, m, 0, l, group=group)

                clear_logs(c, group=group)

    stop_all()
