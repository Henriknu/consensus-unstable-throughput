
# LAN Bare Latency

MEASUREMENTS_BARE_LATENCY_LAN_ABFT = [
    (4, 1, 0.0240478515625),  # ABFT
    (7, 2, 0.04808104515075684),  # ABFT
    (10, 3,  0.061860084533691406),  # ABFT
    (13, 4, 0.08942985534667969),  # ABFT
    (16, 5, 0.11595892906188965)  # ABFT
]

MEASUREMENTS_BARE_LATENCY_LAN_BEAT_BEAT = [
    (4, 1, 0.1),  # BEAT BEAT0
    (7, 2, 0.54),  # BEAT BEAT0
]

MEASUREMENTS_BARE_LATENCY_LAN_BEAT_HB = [
    (4, 1, 0.21),  # BEAT HB
    (7, 2, 1.47),  # BEAT HB
]

# WAN Bare Latency

MEASUREMENTS_BARE_LATENCY_WAN_ABFT = [

    (32, 8, 2.0476999282836914),
    (64, 16, 2.8309249877929688),
    (100, 25, 6.553422927856445)
]

MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_HB = [

    (32, 8, 70),
    (64, 16, 240),
    (100, 25, 491)

]

MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO1 = [

    (32, 8, 19),
    (64, 16, 49),
    (100, 25, 90)
]

MEASUREMENTS_BARE_LATENCY_WAN_DUMBO_DUMBO2 = [

    (32, 8, 7.5),
    (64, 16, 14),
    (100, 25, 24)

]

# WAN Transaction throughput - 2x10^6 transactions

MEASUREMENTS_WAN_THROUGHPUT_ABFT = [
    (8, 2, 38106),
    (32, 8, 38733),
    (64, 16, 34486),
    (100, 25, 28591)
]

MEASUREMENTS_WAN_THROUGHPUT_HB = [
    (32, 8, 8430),
    (64, 16, 4453),
    (100, 25, 1934)
]

MEASUREMENTS_WAN_THROUGHPUT_DUMBO1 = [
    (32, 8, 11313),
    (64, 16, 12111),
    (100, 25, 8814)
]

MEASUREMENTS_WAN_THROUGHPUT_DUMBO2 = [
    (32, 8, 15121),
    (64, 16, 18692),
    (100, 25, 17767)
]


# Measurements from the table. (N, F, [(batch_size / N, latency, CPU, MEM, NET), ...], styling)
MEASUREMENTS_STABLE_WAN = [(8, 2, [(12.5, 1.9007458686828613, 0.5025252525262144, 197582848.0, 167117.0), (125.0, 2.2110040187835693, 1.0075757575762698, 208984064.0, 859172.0), (1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0), (12500.0, 8.612051010131836, 6.103703574365339, 296191488.0, 52425379.0), (125000.0, 27.262948036193848, 24.53056951988803, 1228982125.7142856, 506807818.0), (250000.0, 39.3635311126709, 31.811707152973902, 2165066137.6, 1005872352.0)], "-o"),
                           (32, 8, [(3.125, 2.0476999282836914, 7.894736842104633, 209805312.0, 859229.0), (31.25, 1.988602876663208, 6.25, 219234304.0, 1294089.0), (312.5, 2.504643201828003, 11.640399731407697, 227898709.33333334, 6662281.0), (
                               3125.0, 6.176145076751709, 16.343526766172914, 330242730.6666667, 55229920.0), (31250.0, 23.845752000808716, 32.175676182107175, 1085860249.6, 526896289.0), (62500.0, 38.72602105140686, 41.265931610374686, 2055932006.4, 1043712062.0)], "-x"),
                           (64, 16, [(1.5625, 2.8309249877929688, 36.66383219954513, 261618346.66666666, 4972465.0), (15.625, 2.847291946411133, 34.14141414141339, 267456512.0, 4934465.0), (156.25, 3.0814712047576904, 38.181088634611434, 288313344.0, 13552153.0), (
                               1562.5, 5.10654616355896, 36.504487944466796, 390029312.0, 59080582.0), (15625.0, 21.417402029037476, 44.156174676930334, 1232529221.8181818, 528416347.0), (31250.0, 43.49578619003296, 45.521736702747525, 2199629633.4883723, 1054025142.0)], "-x"),
                           (100, 25, [(1.0, 6.553422927856445, 65.11637551562886, 460545462.85714287, 18119997.0), (10.0, 6.532922029495239, 65.00330504623062, 468030025.14285713, 19504642.0), (100.0, 6.740656852722168, 67.14400579501105, 479527497.14285713, 27070624.0), (
                               1000.0, 8.720366954803467, 64.69915032484958, 618374030.2222222, 92255279.0), (10000.0, 26.421448945999146, 59.8857464002934, 1810710831.4074075, 615704538.0), (20000.0, 52.46390199661255, 58.58825900740474, 3053076086.1538463, 1228737671.0)], "-o")

                           ]


# (N, F, M, Delay, [(batch_size / N, latency, CPU, MEM, NET)]
MEASUREMENTS_UNSTABLE_DELAY = [

    (8, 2, 2, [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0),
               (1250.0, 5.789690017700195,
     1.3502542431115971, 208059733.33333334, 5163906.0, 500, 0,),
               (1250.0, 5.2708070278167725, 1.515241636683749,
                219598283.03448275, 3199866.0, 2500, 0),
     (1250.0, 7.1574859619140625,
      1.0111278115388456, 208103424.0, 3198247.0, 5000, 0)], "-o"),

    (8, 2, 4,  [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0),
                (1250.0, 15.739091157913208,
     0.8052436757535979, 212625271.46666667, 5512676.0, 500, 0),
                (1250.0, 64.39703488349915,
                 0.2468268969253733, 223641032.86153847, 5575856.0, 2500, 0,),
     (1250.0, 127.06522703170776,
      0.20094787830409389, 224433973.45054945, 5592536.0, 5000, 0)], "-o"),


    (8, 2, 6,  [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0),
                (1250.0, 21.37873101234436,
     0.6371032838500523, 225244811.63636363, 5574652.0, 500, 0,),
                (1250.0, 95.83916997909546,
                 0.20936952427867442, 224272725.33333334, 5633614.0, 2500, 0,),
     (1250.0, 182.81810998916626,
      0.16158195319548177, 223481980.12121212, 3166826.0, 5000, 0,)], "-o"),

    (8, 2, 8,  [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0),
                (1250.0, 22.618544101715088,
     0.5889272890583312, 222895237.5652174, 5529976.0, 500, 0,),
                (1250.0, 92.2409999370575,
                 0.27745001925442725, 224360180.86956522, 5630029.0, 2500, 0,),
     (1250.0, 177.96966791152954,
      0.16542538575015178, 226059328.44755244, 4927408.0, 5000, 0,)], "-o"),





    # (64, 16, 0, 0, [
    #    (15625.0, 21.417402029037476, 44.156174676930334, 1232529221.8181818, 528416347.0)], "-x"),

]


# (N, F, M, Packet loss, [(batch_size / N, latency, CPU, MEM, NET)]
MEASUREMENTS_UNSTABLE_PACKET_LOSS = [

    (8, 2, 2, [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0,),
               (1250.0, 5.770542860031128,
     1.5292101614632643, 204718762.66666666, 4861846.0, 0, 5,),
               (1250.0, 5.789463043212891,
                1.2204141873919885, 215327539.2, 4257093.0, 0, 10,),
               (1250.0, 8.054816007614136,
                0.9444834897101799, 216415573.33333334, 4267269.0, 0, 15,)],  "-o"),



    (8, 2, 4, [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0,),
               (1250.0, 16.179215908050537,
     0.819949007320353, 218652416.0, 5522187.0, 0, 5,),
               (1250.0, 29.82213807106018,
                0.46813481022646886, 215234969.6, 5541822.0, 0, 10,),
               (1250.0, 54.54358696937561,
                0.2468851781645473, 215873573.23636365, 5594443.0, 0, 15,)],  "-o"),



    (8, 2, 6, [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0,),
               (1250.0, 19.216768980026245,
     0.47553690835908047, 221007225.2631579, 5537401.0, 0, 5,),
               (1250.0, 34.022512912750244,
                0.3839070689370991, 220948720.94117647, 5590951.0, 0, 10,),
               (1250.0, 63.81846499443054,
                0.25047543222390056, 220963663.44827586, 5499311.0, 0, 15,)],  "-o"),



    (8, 2, 8, [(1250.0, 6.404989957809448, 1.5250885351383578, 219720362.66666666, 5529528.0, 0, 0,),
               (1250.0, 15.689013957977295,
     0.7040421475338349, 207307571.2, 5485420.0, 0, 5,),
               (1250.0, 34.663408041000366,
                0.43080265340289975, 218613278.11764705, 5591167.0, 0, 10,),
               (1250.0, 94.55719089508057,
                0.22613336602685888, 221213448.08421052, 5738674.0, 0, 15,)],  "-o"),






    # (64, 16, 0, 0, [
    #    (15625.0, 21.417402029037476, 44.156174676930334, 1232529221.8181818, 528416347.0)], "-x"),




]
