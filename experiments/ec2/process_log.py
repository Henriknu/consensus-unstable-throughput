import numpy as np
import glob
import re
from utils.utils import BATCH_SIZES
from datetime import datetime
from typing import List, Dict
import time

r_start = re.compile(".*Invoking ABFT.*")
r_end = re.compile(".*terminated ABFT with value:.*")


def _process_latency(log_segments: List[str], n_parties: int, f_tolerance: int, batch_size: int):
    endtime: Dict[int, datetime] = dict()
    starttime: Dict[int, datetime] = dict()
    latencies: List[int] = []

    def to_unix(d: datetime): return time.mktime(
        d.timetuple()) + d.microsecond / 1e6

    for i, log in enumerate(log_segments):
        for line in log.split("\n"):
            if r_start.match(line):
                starttime[i] = to_unix(
                    datetime.fromisoformat(line.split(" - ")[0]))
            elif r_end.match(line):
                endtime[i] = to_unix(
                    datetime.fromisoformat(line.split(" - ")[0]))

    maxLatency = 0
    for key, value in endtime.items():
        latencies.append(value - starttime[key])
        if value - starttime[key] > maxLatency:
            maxLatency = value - starttime[key]

    print('(N-t) finishing at', sorted(endtime.values())
          [n_parties-f_tolerance-1] - min(starttime.values()))
    print('(N/2) finishing at', sorted(endtime.values())
          [int(n_parties/2)] - min(starttime.values()))
    print('max_local', maxLatency)
    print('avg_local', sum(latencies) / len(latencies))
    print('range', max(endtime.values()) - min(starttime.values()))
    return sorted(endtime.values())[n_parties-f_tolerance-1] - min(starttime.values())


def process_log_files(n_parties: int, f_tolerance: int, batch_size: int, WAN: bool):

    log_file_name_list = sorted(glob.glob(
        f"logs/{n_parties}_{f_tolerance}_{batch_size}_*-" + ('WAN' if WAN else "LAN") + "*"))

    contents = [open(file_name).read().strip().split("\n\n")
                for file_name in log_file_name_list]

    results = []

    if contents:

        for i in range(len(contents[0])):
            log_segments = [content[i] for content in contents]
            result = _process_latency(
                log_segments, n_parties, f_tolerance, batch_size)
            results.append(result)

        print(tuple(results))
        print(f"Avg Latency:{sum(results) / len(results)} seconds,", f"Std:{np.std(results)},",
              'Number of iterations:', len(results))

        return sum(results) / len(results)


def process_batch_N(n_parties: int, WAN: bool):

    results = []

    f_tolerance = n_parties // 4

    results = [(batch_size / n_parties, process_log_files(
        n_parties, f_tolerance, batch_size, WAN)) for batch_size in BATCH_SIZES]

    print(results)


if __name__ == '__main__':

    from IPython import embed
    embed()
