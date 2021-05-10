from utils.utils import F, M, BATCH_SIZES, UNSTABLE_BATCH_SIZES, I, WAN, PACKET_LOSS_RATES, PACKET_DELAYS

N = [8, 32, 64, 100]

K = 1
TRANSACTION_BYTE_SIZE = 250
SIGNATUER_SHARE_BYTE_SIZE = 32
SIGNATURE_BYTE_SIZE = 68

BANDWIDTH_COST = 0.02 * 10**-9


def input_size(n, b):
    return (b // n) * TRANSACTION_BYTE_SIZE


def bucket_size(n, b):
    div = n // 2
    return (input_size(n, b) // div)


def estimate_bandwidth():

    results = {}

    for n in N:

        partial = {}

        for b in BATCH_SIZES:

            bandwith_prbc = (n * (n - 1)) * bucket_size(n, b) + \
                (n * (n - 1)) * SIGNATUER_SHARE_BYTE_SIZE
            print(bandwith_prbc)
            bandwith_mvba = K * (8 * n**2 - 4*n) * (n * SIGNATURE_BYTE_SIZE)
            print(bandwith_mvba)

            partial[b] = bandwith_prbc + bandwith_mvba

        results[n] = partial

    print(results)


estimate_bandwidth()
