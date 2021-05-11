import numpy as np
import glob
import re
from utils.utils import BATCH_SIZES, M, PACKET_DELAYS, PACKET_LOSS_RATES, get_metric_data2
from datetime import datetime
from typing import List, Dict
import time

r_private = re.compile("private_host_name:*")
r_start = re.compile(".*Invoking ABFT.*")
r_end = re.compile(".*terminated ABFT with value:.*")


def _process_iteration(log_segments: List[str], n_parties: int, f_tolerance: int, batch_size: int):
    private_host_names: Dict[int, str] = dict()
    starttime: Dict[int, datetime] = dict()
    endtime: Dict[int, datetime] = dict()
    latencies: List[int] = []

    def to_unix(d: datetime): return time.mktime(
        d.timetuple()) + d.microsecond / 1e6

    # Find start and end time

    for i, log in enumerate(log_segments):
        for line in log.split("\n"):
            if r_start.match(line):
                starttime[i] = to_unix(
                    datetime.fromisoformat(line.split(" - ")[0]))
            elif r_end.match(line):
                endtime[i] = to_unix(
                    datetime.fromisoformat(line.split(" - ")[0]))
            elif r_private.match(line):
                private_host_names[i] = line.split(":")[1]

    # Calculate latencies and max_latency

    maxLatency = 0
    for key, value in endtime.items():
        latencies.append(value - starttime[key])
        if value - starttime[key] > maxLatency:
            maxLatency = value - starttime[key]

    # Get metrics either from file, or api if file does not exist

    print('(N-t) finishing at', sorted(endtime.values())
          [n_parties-f_tolerance-1] - min(starttime.values()))
    print('(N/2) finishing at', sorted(endtime.values())
          [int(n_parties/2)] - min(starttime.values()))
    print('max_local', maxLatency)
    print('avg_local', sum(latencies) / len(latencies))
    print('range', max(endtime.values()) - min(starttime.values()))

    result_latency = sorted(endtime.values())[
        n_parties-f_tolerance-1] - min(starttime.values())

    if False:
        cpu, mem, net = get_metrics(private_host_names, starttime, endtime)

        result_cpu = sorted(cpu.values())[
            n_parties-f_tolerance-1]

        result_mem = sorted(mem.values())[
            n_parties-f_tolerance-1]

        result_net = sorted(net.values())[
            n_parties-f_tolerance-1]

    return result_latency


def get_metrics(private_host_names: Dict[int, str],
                starttime: Dict[int, datetime],
                endtime: Dict[int, datetime]):

    cpu = {}
    mem = {}
    net = {}

    # For each party, get metrics for iteration

    for i in range(len(private_host_names)):
        cpu_data, mem_data, net_data = get_metric_data2(
            private_host_names[i], starttime[i], endtime[i])
        cpu[i] = cpu_data
        mem[i] = mem_data
        net[i] = net_data

    return cpu, mem, net


def store_metrics(n_parties: int, f_tolerance: int, batch_size: int):
    pass


def store_metrics_unstable():
    pass


def process_log_files_stable(n_parties: int, f_tolerance: int, batch_size: int, WAN: bool):

    log_file_name_list = sorted(glob.glob(
        f"logs/{n_parties}_{f_tolerance}_{batch_size}_*-" + ('WAN' if WAN else "LAN") + "*"))

    contents = [open(file_name).read().strip().split("\n\n")
                for file_name in log_file_name_list]

    results = []

    if contents:

        for i in range(len(contents[0])):
            log_segments = [content[i] for content in contents]
            result = _process_iteration(
                log_segments, n_parties, f_tolerance, batch_size)
            results.append(result)

        print(tuple(results))
        print(f"Avg Latency:{sum(results) / len(results)} seconds,", f"Std:{np.std(results)},",
              'Number of iterations:', len(results))

        return sum(results) / len(results)


def process_log_files_unstable(n_parties: int, f_tolerance: int, batch_size: int, m_parties: int, delay: int, loss: int):

    log_file_name_list = sorted(glob.glob(
        f"unstable_logs/{n_parties}_{f_tolerance}_{batch_size}_unstable_{m_parties}_{delay}_{loss}*"))

    contents = [open(file_name).read().strip().split("\n\n")
                for file_name in log_file_name_list]

    results = []

    if contents:

        for i in range(len(contents[0])):
            log_segments = [content[i] for content in contents]
            result = _process_iteration(
                log_segments, n_parties, f_tolerance, batch_size)
            results.append(result)

        print(tuple(results))
        print(f"Avg Latency:{sum(results) / len(results)} seconds,", f"Std:{np.std(results)},",
              'Number of iterations:', len(results))

        return sum(results) / len(results)


def ps(n_parties: int, WAN: bool):

    results = []

    f_tolerance = n_parties // 4

    # TODO: Get CPU, MEM, NET metrics

    results = [(batch_size / n_parties, process_log_files_stable(
        n_parties, f_tolerance, batch_size, WAN)) for batch_size in BATCH_SIZES]

    print((n_parties, f_tolerance, results))


def pu(n_parties: int):

    batches = {8: 1000, 64: 1_000_000}

    results_delay = []
    results_loss = []

    batch_size = batches[n_parties]

    f_tolerance = n_parties // 4

    # TODO: Get CPU, MEM, NET metrics

    for m_parties in M:

        partial_delay = []
        partial_loss = []

        for delay in PACKET_DELAYS:

            latency = process_log_files_unstable(
                n_parties, f_tolerance, batch_size, m_parties, delay, 0)
            if latency:
                partial_delay.append((delay, latency))

        for loss in PACKET_LOSS_RATES:
            latency = process_log_files_unstable(
                n_parties, f_tolerance, batch_size, m_parties, 0, loss)
            if latency:
                partial_loss.append((loss, latency))

        results_delay.append(
            (n_parties, f_tolerance, m_parties, partial_delay))
        results_loss.append((n_parties, f_tolerance, m_parties, partial_loss))

    print(results_delay)
    print(results_loss)


if __name__ == '__main__':

    from IPython import embed
    embed()
