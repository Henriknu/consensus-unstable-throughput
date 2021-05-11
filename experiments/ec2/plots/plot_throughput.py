import matplotlib.pyplot as plt
from data import MEASUREMENTS


def do_plot():
    f = plt.figure(1, figsize=(7, 5))
    plt.clf()
    ax = f.add_subplot(1, 1, 1)
    for N, t, entries, style in MEASUREMENTS:
        batch = []
        throughput = []
        for ToverN, latency in entries:
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


do_plot()
