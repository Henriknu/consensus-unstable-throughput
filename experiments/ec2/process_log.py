import pickle
import numpy as np
import glob
from utils.utils import BATCH_SIZES, M, PACKET_DELAYS, PACKET_LOSS_RATES, get_host_start_end, to_unix
from datetime import datetime
from typing import List, Dict
import time


def _process_iteration(log_segments: List[str], n_parties: int, f_tolerance: int, batch_size: int, iteration: int):

    # Find start and end time
    private_host_names, starttime, endtime = get_host_start_end(log_segments)
    latencies: List[int] = []

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

    cpu, mem, net = get_metrics(iteration, starttime, endtime)

    result_cpu = sorted(cpu.values())[
        n_parties-f_tolerance-1]

    result_mem = sorted(mem.values())[
        n_parties-f_tolerance-1]

    result_net = sorted(net.values())[
        n_parties-f_tolerance-1]

    return result_latency, result_cpu, result_mem, result_net


def get_metrics(iteration: int, starttime, endtime):

    cpu = {i: i for i in range(8)}
    mem = {}
    net = {}

    with open("metrics/8_2_100.pickle", "rb") as file:
        metric_collection = pickle.load(file)

    for i, metrics in enumerate(metric_collection[iteration]):

        # Collection of cpu utilization, current memory usage, bytes sent

        for metric in metrics:

            metric["Timestamps"] = [to_unix(timestamp) - 3600
                                    for timestamp in metric["Timestamps"]]

            filtered = filter(lambda x: x[1] >
                              starttime[i] and x[1] < endtime[i], zip(metric["Values"], metric["Timestamps"]))

            if metric["Id"].startswith("net_metrics"):

                print("start", starttime[i])
                print("end", endtime[i])
                print("net", metric["Values"])

                net[i] = sum(map(lambda x: x[0], filtered))

            elif metric["Id"].startswith("cpu_metrics"):
                if filtered := list(filtered):
                    cpu[i] = sum(map(lambda x: x[0], filtered)) / \
                        len(filtered)

            elif metric["Id"].startswith("mem_metrics"):
                if filtered := list(filtered):
                    mem[i] = sum(map(lambda x: x[0], filtered)) / \
                        len(filtered)

    print(cpu, mem, net)

    return cpu, mem, net


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
                log_segments, n_parties, f_tolerance, batch_size, i)
            results.append(result)

        latency = sum(map(lambda result: result[0], results))
        cpu = sum(map(lambda result: result[1], results))
        mem = sum(map(lambda result: result[2], results))
        net = sum(map(lambda result: result[3], results))

        print("Result", latency, cpu, mem, net)

        return latency, cpu, mem, net

    return None, None, None, None


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

        latency = sum(map(lambda result: result[0], results))
        cpu = sum(map(lambda result: result[1], results))
        mem = sum(map(lambda result: result[2], results))
        net = sum(map(lambda result: result[3], results))

        return latency, cpu, mem, net

    return None, None, None, None


def ps(n_parties: int, WAN: bool):

    results = []

    f_tolerance = n_parties // 4

    # TODO: Get CPU, MEM, NET metrics

    results = [(batch_size / n_parties, *process_log_files_stable(
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
