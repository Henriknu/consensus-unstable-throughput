import matplotlib.pyplot as plt
from data import MEASUREMENTS_STABLE_WAN, MEASUREMENTS_BARE_LATENCY_LAN_ABFT, MEASUREMENTS_BARE_LATENCY_LAN_BEAT_BEAT, MEASUREMENTS_BARE_LATENCY_LAN_BEAT_HB, MEASUREMENTS_BARE_LATENCY_WAN_ABFT, MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_HB, MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO1, MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO2, MEASUREMENTS_WAN_THROUGHPUT_ABFT, MEASUREMENTS_WAN_THROUGHPUT_HB, MEASUREMENTS_WAN_THROUGHPUT_DUMBO1,  MEASUREMENTS_WAN_THROUGHPUT_DUMBO2, MEASUREMENTS_UNSTABLE_DELAY, MEASUREMENTS_UNSTABLE_PACKET_LOSS


# STABLE_LAN STABLE_WAN UNSTABLE_DELAY UNSTABLE_PACKET_LOSS
SHOULD_PLOT_FOR = "STABLE_WAN"


def plot_related_latency_LAN():

    labels = ['N=4', 'N=7', 'N=10', 'N=13', 'N=16']
    colors = {
        "HB": "red",
        "BEAT0": "green",
        "ABFT": "blue"
    }
    x = [4, 7, 10, 13, 16]
    width = 0.5

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_LAN_BEAT_HB:
        bar = ax.bar(N - 1.25 * width, latency, width,
                     label='Honeybadger', color=colors["HB"])
        ax.bar_label(bar, fmt='%.2f', padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_LAN_BEAT_BEAT:
        bar = ax.bar(N, latency, width, label='BEAT0', color=colors["BEAT0"])
        ax.bar_label(bar, fmt='%.2f', padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_LAN_ABFT[0:2]:
        bar = ax.bar(N + 1.25 * width, latency, width,
                     label='ABFT', color=colors["ABFT"])
        ax.bar_label(bar, fmt='%.2f', padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_LAN_ABFT[2:]:
        bar = ax.bar(N, latency, width, label='ABFT', color=colors["ABFT"])
        ax.bar_label(bar, fmt='%.2f', padding=3)

    # Handle duplicate legends

    handles, _labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(_labels, handles))
    plt.legend(by_label.values(), by_label.keys(),
               loc='best')

    plt.ylabel('Latency (Seconds) ')
    plt.xlabel('Number of nodes')
    plt.xticks(x, labels)
    plt.ylim([0, 2])
    plt.tight_layout()
    plt.savefig(f'pdfs/plot_latency_LAN.pdf', format='pdf', dpi=1000)


def plot_related_latency_WAN():

    labels = ['N=32', 'N=64', 'N=100']
    colors = {
        "HB": "red",
        "Dumbo1": "green",
        "Dumbo2": "purple",
        "ABFT": "blue"
    }
    x = [32, 64, 100]
    width = 2

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_HB:
        bar = ax.bar(N - 2.5 * width, latency, width,
                     label='Honeybadger', color=colors["HB"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO1:
        bar = ax.bar(N - 0.75 * width, latency, width,
                     label='Dumbo1', color=colors["Dumbo1"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO2:
        bar = ax.bar(N + 0.75 * width, latency, width,
                     label='Dumbo2', color=colors["Dumbo2"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_BARE_LATENCY_WAN_ABFT:
        bar = ax.bar(N + 2.5 * width, latency, width,
                     label='ABFT', color=colors["ABFT"])
        ax.bar_label(bar, fmt='%.2f', padding=3)

    # Handle duplicate legends

    handles, _labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(_labels, handles))
    plt.legend(by_label.values(), by_label.keys(),
               loc='best')

    ax.set_yscale("log")
    plt.ylim([1, 10**2.9])

    plt.ylabel('Latency (Seconds) ')
    plt.xlabel('Number of nodes')

    plt.xticks(x, labels)
    plt.tight_layout()
    plt.savefig(f'pdfs/plot_latency_WAN.pdf', format='pdf', dpi=1000)


def plot_related_throughput_WAN():

    labels = ['N=8', 'N=32', 'N=64', 'N=100']
    colors = {
        "HB": "red",
        "Dumbo1": "green",
        "Dumbo2": "purple",
        "ABFT": "blue"
    }
    x = [8, 32, 64, 100]
    width = 4

    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)

    for N, _, latency in MEASUREMENTS_WAN_THROUGHPUT_HB:
        bar = ax.bar(N - 2.5 * width, latency, width,
                     label='Honeybadger', color=colors["HB"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_WAN_THROUGHPUT_DUMBO1:
        bar = ax.bar(N - 0.75 * width, latency, width,
                     label='Dumbo1', color=colors["Dumbo1"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_WAN_THROUGHPUT_DUMBO2:
        bar = ax.bar(N + 0.75 * width, latency, width,
                     label='Dumbo2', color=colors["Dumbo2"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in [MEASUREMENTS_WAN_THROUGHPUT_ABFT[0]]:
        bar = ax.bar(N, latency, width,
                     label='ABFT', color=colors["ABFT"])
        ax.bar_label(bar, padding=3)

    for N, _, latency in MEASUREMENTS_WAN_THROUGHPUT_ABFT[1:]:
        bar = ax.bar(N + 2.5 * width, latency, width,
                     label='ABFT', color=colors["ABFT"])
        ax.bar_label(bar, padding=3)

    # Handle duplicate legends

    handles, _labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(_labels, handles))
    plt.legend(by_label.values(), by_label.keys(),
               loc='best')

    plt.ylim([0, 50000])

    plt.ylabel('Throughput (Tx per second)')
    plt.xlabel('Number of nodes')

    plt.xticks(x, labels)
    plt.tight_layout()
    plt.savefig(f'pdfs/plot_throughput_WAN.pdf', format='pdf', dpi=1000)


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
    for N, t, entries, _ in data:
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
    for N, t, entries, style in data:
        batch = []
        throughput = []
        for ToverN, latency, _, _, _ in entries:
            batch.append(N*ToverN)
            throughput.append(ToverN*(N-t) / latency)

        ax.plot(batch, throughput, style, label='%d/%d' % (N, t))
        print(N, throughput)
    ax.set_xscale("log")
    ax.set_yscale("log")
    # plt.ylim([10**2.1, 10**4.8])
    # plt.xlim([10**3.8, 10**6.4])
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
    for N, t, entries, style in data:
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
    for N, t, entries, style in data:
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
    for N, t, entries, style in data:
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
    for N, t, entries, style in data:
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
