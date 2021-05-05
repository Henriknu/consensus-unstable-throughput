import matplotlib.pyplot as plt
from data import MEASUREMENTS


def do_plot():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, _ in MEASUREMENTS:
        batch = []
        latencies = []
        for ToverN, latency in entries:
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


do_plot()
