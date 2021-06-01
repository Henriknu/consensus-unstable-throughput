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
    plt.savefig(f'pdfs/plot_latency_{suffix}.pdf', format='pdf', dpi=1000)


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
    plt.savefig(f'pdfs/plot_throughput_{suffix}.pdf',
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
    plt.savefig(
        f'pdfs/plot_latency_throughput_{suffix}.pdf', format='pdf', dpi=1000)


def plot_cpu(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        batches = []
        cpu_usage = []
        for ToverN, _, cpu, _, _ in entries:
            batches.append(N*ToverN)
            cpu_usage.append(cpu)
        ax.plot(batches, cpu_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    plt.ylim([0, 100])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('CPU utilization (Percentage)')
    plt.xlabel('Batch size (Number of Tx) in log scale')
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_cpu_{suffix}.pdf', format='pdf', dpi=1000)


def plot_mem(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        batches = []
        mem_usage = []
        for ToverN, _, _, mem,  _ in entries:
            batches.append(N*ToverN)
            mem_usage.append(mem)
        ax.plot(batches, mem_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    plt.ylim([10**6, 4 * 10**9])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Memory utilization (Bytes)')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_mem_{suffix}.pdf', format='pdf', dpi=1000)


def plot_net(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in get_data():
        batches = []
        net_usage = []
        for ToverN, _, _, _, net in entries:
            batches.append(ToverN*(N-t))
            net_usage.append(net)
        ax.plot(batches, net_usage, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Outbound network traffic (Bytes)')
    plt.xlabel('Throughput (Tx per second) in log scale')
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_net_{suffix}.pdf', format='pdf', dpi=1000)


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
