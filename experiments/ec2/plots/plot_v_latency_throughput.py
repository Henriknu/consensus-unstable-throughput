import matplotlib.pyplot as plt
from data import MEASUREMENTS


def do_plot():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
        throughput = []
        latencies = []
        for ToverN, latency in entries:
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


do_plot()
