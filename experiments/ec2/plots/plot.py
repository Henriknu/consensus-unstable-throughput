import matplotlib.pyplot as plt
from data import MEASUREMENTS_STABLE_WAN, MEASUREMENTS_STABLE_LAN, MEASUREMENTS_UNSTABLE_DELAY, MEASUREMENTS_UNSTABLE_PACKET_LOSS


# STABLE_LAN STABLE_WAN UNSTABLE_DELAY UNSTABLE_PACKET_LOSS
SHOULD_PLOT_FOR = "STABLE_WAN"


def plot_LAN():
    plot_latency(MEASUREMENTS_STABLE_LAN, "STABLE_LAN")


def plot_stable():
    plot_latency(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")
    plot_throughput(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")
    plot_v_latency_throughput(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")
    plot_cpu(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")
    plot_mem(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")
    plot_net(MEASUREMENTS_STABLE_WAN, "STABLE_WAN")


def plot_unstable():
    plot_latency(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")
    plot_throughput(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")
    plot_v_latency_throughput(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")
    plot_cpu(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")
    plot_mem(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")
    plot_net(MEASUREMENTS_UNSTABLE_DELAY, "UNSTABLE_DELAY")

    plot_latency(MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")
    plot_throughput(MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")
    plot_v_latency_throughput(
        MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")
    plot_cpu(MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")
    plot_mem(MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")
    plot_net(MEASUREMENTS_UNSTABLE_PACKET_LOSS, "UNSTABLE_PACKET_LOSS")


def plot_latency(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, _ in get_data():
        batch = []
        latencies = []
        for ToverN, latency, _, _, _ in entries:
            batch.append(ToverN * N)
            latencies.append(latency)
        ax.plot(batch, latencies, label='%d/%d' % (N, t))

    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.ylim([10**0.2, 10**2.6])
    plt.xlim([10**2.2, 3 * 10**6])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Latency (Seconds) ')
    plt.xlabel('Batch size (Number of Tx) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency.pdf', format='pdf', dpi=1000)


def plot_throughput(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        batch = []
        throughput = []
        for ToverN, latency, _, _, _ in entries:
            batch.append(N*ToverN)
            throughput.append(ToverN*(N-t) / latency)
        ax.plot(batch, throughput, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    #plt.ylim([10**2.1, 10**4.8])
    #plt.xlim([10**3.8, 10**6.4])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Throughput (Tx per second) in log scale')
    plt.xlabel('Batch size (Number of Tx) in log scale')
    plt.savefig('pdfs/plot_throughput.pdf',
                format='pdf', dpi=1000)


def plot_v_latency_throughput(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        throughput = []
        latencies = []
        for ToverN, latency, _, _, _ in entries:
            throughput.append(ToverN*(N-t) / latency)
            latencies.append(latency)
        ax.plot(throughput, latencies, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Latency (Seconds) in log scale')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency_throughput.pdf', format='pdf', dpi=1000)


def plot_cpu(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        throughput = []
        cpu_usage = []
        for ToverN, latency, cpu, _, _ in entries:
            throughput.append(ToverN*(N-t) / latency)
            cpu_usage.append(cpu)
        ax.plot(throughput, cpu_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('CPU utilization (Percentage)')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency_throughput.pdf', format='pdf', dpi=1000)


def plot_mem(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        throughput = []
        mem_usage = []
        for ToverN, latency, _, mem,  _ in entries:
            throughput.append(ToverN*(N-t) / latency)
            mem_usage.append(mem)
        ax.plot(throughput, mem_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Memory utilization (Bytes)')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency_throughput.pdf', format='pdf', dpi=1000)


def plot_net(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        throughput = []
        net_usage = []
        for ToverN, latency, _, _, net in entries:
            throughput.append(ToverN*(N-t) / latency)
            net_usage.append(net)
        ax.plot(throughput, net_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Outbound network traffic (Bytes)')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency_throughput.pdf', format='pdf', dpi=1000)


def get_data():
    if SHOULD_PLOT_FOR == "STABLE_LAN":
        return MEASUREMENTS_STABLE_LAN
    elif SHOULD_PLOT_FOR == "STABLE_WAN":
        return MEASUREMENTS_STABLE_WAN
    elif SHOULD_PLOT_FOR == "UNSTABLE_DELAY":
        return MEASUREMENTS_UNSTABLE_DELAY
    elif SHOULD_PLOT_FOR == "UNSTABLE_PACKET_LOSS":
        return MEASUREMENTS_UNSTABLE_PACKET_LOSS
    else:
        print("Data collection not found")
        None


if __name__ == '__main__':

    from IPython import embed
    embed()
