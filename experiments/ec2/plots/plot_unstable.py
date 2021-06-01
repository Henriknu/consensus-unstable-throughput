
from data import MEASUREMENTS_UNSTABLE_DELAY, MEASUREMENTS_UNSTABLE_PACKET_LOSS
import matplotlib.pyplot as plt
# STABLE_LAN STABLE_WAN UNSTABLE_DELAY UNSTABLE_PACKET_LOSS
SHOULD_PLOT_FOR = "UNSTABLE_DELAY"


def plot_unstable():
    plot_latency_unstable(data=MEASUREMENTS_UNSTABLE_DELAY,
                          suffix="UNSTABLE_DELAY")
    plot_throughput_unstable(
        data=MEASUREMENTS_UNSTABLE_DELAY, suffix="UNSTABLE_DELAY")
    plot_cpu_unstable(data=MEASUREMENTS_UNSTABLE_DELAY,
                      suffix="UNSTABLE_DELAY")
    plot_mem_unstable(data=MEASUREMENTS_UNSTABLE_DELAY,
                      suffix="UNSTABLE_DELAY")
    plot_net_unstable(data=MEASUREMENTS_UNSTABLE_DELAY,
                      suffix="UNSTABLE_DELAY")

    plot_latency_unstable(
        data=MEASUREMENTS_UNSTABLE_PACKET_LOSS, suffix="UNSTABLE_PACKET_LOSS")
    plot_throughput_unstable(
        data=MEASUREMENTS_UNSTABLE_PACKET_LOSS, suffix="UNSTABLE_PACKET_LOSS")
    plot_cpu_unstable(data=MEASUREMENTS_UNSTABLE_PACKET_LOSS,
                      suffix="UNSTABLE_PACKET_LOSS")
    plot_mem_unstable(data=MEASUREMENTS_UNSTABLE_PACKET_LOSS,
                      suffix="UNSTABLE_PACKET_LOSS")
    plot_net_unstable(data=MEASUREMENTS_UNSTABLE_PACKET_LOSS,
                      suffix="UNSTABLE_PACKET_LOSS")


def plot_latency_unstable(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)

    for N, t, m, entries, style in data:
        parameters = []
        latencies = []

        for _, latency, _, _, _, d, l in entries:
            parameters.append(d if suffix == "UNSTABLE_DELAY" else l)
            latencies.append(latency)
        ax.plot(parameters, latencies, style, label='%d/%d/%d' % (N, t, m))

    plt.legend(title='Nodes / Tolerance / Unstable', loc='best')
    plt.xticks(parameters, parameters)
    plt.ylabel('Latency (Seconds) ')
    plt.xlabel("Packet Delays (Milliseconds)" if suffix ==
               "UNSTABLE_DELAY" else "Packet Loss (Percentage)")
    plt.savefig(f'pdfs/plot_latency_{suffix}.pdf', format='pdf', dpi=1000)


def plot_throughput_unstable(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, m, entries, style in data:
        parameters = []
        throughput = []
        for ToverN, latency, _, _, _, d, l in entries:
            parameters.append(d if suffix == "UNSTABLE_DELAY" else l)
            throughput.append(ToverN*(N-t) / latency)

        ax.plot(parameters, throughput, style, label='%d/%d/%d' % (N, t, m))
    ax.set_yscale("log")
    plt.xticks(parameters, parameters)
    # plt.ylim([10**2.1, 10**4.8])
    # plt.xlim([10**3.8, 10**6.4])
    plt.legend(title='Nodes / Tolerance / Unstable', loc='best')
    plt.ylabel('Throughput (Tx per second) in log scale')
    plt.xlabel("Packet Delays (Milliseconds)" if suffix ==
               "UNSTABLE_DELAY" else "Packet Loss (Percentage)")
    plt.savefig(f'pdfs/plot_throughput_{suffix}.pdf',
                format='pdf', dpi=1000)


def plot_cpu_unstable(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, m, entries, style in data:
        parameters = []
        cpu_usage = []
        for _, _, cpu, _, _, d, l in entries:
            parameters.append(d if suffix == "UNSTABLE_DELAY" else l)
            cpu_usage.append(cpu)
        ax.plot(parameters, cpu_usage, style, label='%d/%d/%d' % (N, t, m))
    plt.ylim([0, 10])
    plt.xticks(parameters, parameters)
    plt.legend(title='Nodes / Tolerance / Unstable', loc='best')
    plt.ylabel('CPU utilization (Percentage)')
    plt.xlabel("Packet Delays (Milliseconds)" if suffix ==
               "UNSTABLE_DELAY" else "Packet Loss (Percentage)")
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_cpu_{suffix}.pdf', format='pdf', dpi=1000)


def plot_mem_unstable(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, m, entries, style in data:
        parameters = []
        mem_usage = []
        for _, _, _, mem,  _, d, l in entries:
            parameters.append(d if suffix == "UNSTABLE_DELAY" else l)
            mem_usage.append(mem)
        ax.plot(parameters, mem_usage, style, label='%d/%d/%d' % (N, t, m))
    plt.ylim([10**6, 4 * 10**9])
    plt.xticks(parameters, parameters)
    plt.legend(title='Nodes / Tolerance / Unstable', loc='best')
    plt.ylabel('Memory utilization (Bytes)')
    plt.xlabel("Packet Delays (Milliseconds)" if suffix ==
               "UNSTABLE_DELAY" else "Packet Loss (Percentage)")
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_mem_{suffix}.pdf', format='pdf', dpi=1000)


def plot_net_unstable(data=None, suffix=None):

    if not data:
        data = get_data()

    if not suffix:
        suffix = SHOULD_PLOT_FOR

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, m, entries, style in data:
        parameters = []
        net_usage = []
        for _, _, _, _, net, d, l in entries:
            parameters.append(d if suffix == "UNSTABLE_DELAY" else l)
            net_usage.append(net)
        ax.plot(parameters, net_usage, style, label='%d/%d/%d' % (N, t, m))
    ax.set_yscale("log")
    plt.xticks(parameters, parameters)
    plt.legend(title='Nodes / Tolerance / Unstable', loc='best')
    plt.ylabel('Outbound network traffic (Bytes)')
    plt.xlabel("Packet Delays (Milliseconds)" if suffix ==
               "UNSTABLE_DELAY" else "Packet Loss (Percentage)")
    plt.tight_layout()
    plt.savefig(
        f'pdfs/plot_res_net_{suffix}.pdf', format='pdf', dpi=1000)


def get_data():
    if SHOULD_PLOT_FOR == "UNSTABLE_DELAY":
        return MEASUREMENTS_UNSTABLE_DELAY
    elif SHOULD_PLOT_FOR == "UNSTABLE_PACKET_LOSS":
        return MEASUREMENTS_UNSTABLE_PACKET_LOSS
    else:
        print("Data collection not found")
        None


if __name__ == '__main__':

    from IPython import embed
    embed()
