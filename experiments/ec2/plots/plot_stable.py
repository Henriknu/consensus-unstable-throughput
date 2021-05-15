import matplotlib.pyplot as plt
from data import MEASUREMENTS


def plot_latency():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, _ in MEASUREMENTS:
        batch = []
        latencies = []
        for ToverN, latency, _, _, _ in entries:
            batch.append(ToverN * N)
            latencies.append(latency)
        ax.plot(batch, latencies, label='%d/%d' % (N, t))

    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.ylim([10**0.2, 10**2.6])
    plt.xlim([10**2.2, 10**6.3])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Latency (Seconds) ')
    plt.xlabel('Batch size (Number of Tx) in log scale')
    plt.tight_layout()
    plt.savefig('pdfs/plot_latency.pdf', format='pdf', dpi=1000)


def plot_throughput():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
        batch = []
        throughput = []
        for ToverN, latency, _, _, _ in entries:
            batch.append(N*ToverN)
            throughput.append(ToverN*(N-t) / latency)
        ax.plot(batch, throughput, style, label='%d/%d' % (N, t))
    ax.set_xscale("log")
    ax.set_yscale("log")
    plt.ylim([10**2.1, 10**4.8])
    plt.xlim([10**3.8, 10**6.4])
    plt.legend(title='Nodes / Tolerance', loc='best')
    plt.ylabel('Throughput (Tx per second) in log scale')
    plt.xlabel('Batch size (Number of Tx) in log scale')
    plt.savefig('pdfs/plot_throughput.pdf',
                format='pdf', dpi=1000)


def plot_v_latency_throughput():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
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


def plot_cpu():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
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


def plot_mem():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
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


def plot_net():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
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


if __name__ == '__main__':

    from IPython import embed
    embed()
