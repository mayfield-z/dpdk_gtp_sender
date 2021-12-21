/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#define _GNU_SOURCE

#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sched.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include "gen_gtp.h"
#include "gtp_hdr.h"

#define RX_RING_SIZE 1024 * 4
#define TX_RING_SIZE 1024 * 4

#define NUM_MBUFS ((1 << 21) - 1)
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 32
#define MAX_TXQ 1024
#define MAX_RXQ 1024
#define MAX_LCORE 64
#define MAX_PORTS 2

#define NB_MBUF ((1 << 20) - 1)

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

#define NS_PER_SEC 1E9

extern uint16_t pkt_length;
struct rte_mbuf* mbufs[NB_MBUF];

uint8_t debug;

/* Configuration of ethernet ports. 8<  */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_NONFRAG_IPV4_UDP,
        },
    },
    .txmode = {
        .offloads = DEV_TX_OFFLOAD_UDP_CKSUM,
    },
};

struct global_info
{
    uint64_t tx_mbps; // configured tx speed, Mbps
    int nb_txq;
    int nb_rxq;
};

struct global_info ginfo = {
    .tx_mbps = 10,
    .nb_txq = 1,
    .nb_rxq = 1,
};
/* >8 End of configuration of ethernet ports. */

struct port_stats_info
{
    struct
    {
        uint64_t tx_total_pkts;
        uint64_t tx_total_bytes;
        uint64_t tx_last_total_pkts;
        uint64_t tx_last_total_bytes;
    } txq_stats[MAX_TXQ];

    struct
    {
        uint64_t rx_total_pkts;
        uint64_t rx_total_bytes;
        uint64_t rx_last_total_pkts;
        uint64_t rx_last_total_bytes;
        double OWD;
    } rxq_stats[MAX_RXQ];

    uint64_t tx_total_pkts;
    uint64_t tx_total_bytes;
    uint64_t tx_pps;
    uint64_t tx_mbps;
    uint64_t rx_total_pkts;
    uint64_t rx_total_bytes;
    uint64_t rx_pps;
    uint64_t rx_mbps;
} port_stats[MAX_PORTS];

struct lcore_args
{
    struct
    {
        struct rte_mbuf *m_table[BURST_SIZE] __rte_cache_aligned;
        struct rte_mempool *mp;
        uint32_t queue_id;
        struct rte_timer timer;
        uint8_t is_tx_lcore;
        uint64_t period;
        uint32_t port_id;
    } tx;
    struct
    {
        struct rte_mbuf *m_table[BURST_SIZE] __rte_cache_aligned;
        uint8_t is_rx_lcore;
        uint32_t queue_id;
        uint32_t port_id;
    } rx;
} lc_args[MAX_LCORE];


static void usage()
{
    printf("Usage: main <EAL options> -- -s <bitrate#[MG]> -d\n");
    rte_exit(-1, "invalid arguments!\n");
}

static void parse_params(int argc, char **argv)
{
    char opt;
    int accept = 0;
    char speed[32] = "";

    while ((opt = getopt(argc, argv, "ds:r:t:")) != -1)
    {
        switch (opt)
        {
        case 's':
            rte_memcpy(speed, optarg, strlen(optarg) - 1);
            switch (*(optarg + strlen(optarg) - 1))
            {
            case 'M':
                ginfo.tx_mbps = atoi(speed);
                break;
            case 'G':
                ginfo.tx_mbps = atoi(speed) * 1024;
                break;
            default:
                usage();
            }
            accept = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'r':
            ginfo.nb_rxq = atoi(optarg);
            if (ginfo.nb_rxq >= MAX_RXQ)
            {
                usage();
            }
            break;
        case 't':
            ginfo.nb_txq = atoi(optarg);
            if (ginfo.nb_txq >= MAX_TXQ)
            {
                usage();
            }
            break;
        default:
            usage();
            break;
        }
    }
    if (!accept)
    {
        usage();
    }
}

void my_stats_display()
{
    int i, j;
    port_stats->tx_total_pkts = 0;
    port_stats->rx_total_pkts = 0;
    port_stats->tx_total_bytes = 0;
    port_stats->rx_total_bytes = 0;
    for (i = 0; i < MAX_PORTS; i++)
    {
        printf("\n  #######################################\n");
        printf("  port#%d:\n    ->tx:\n      ->p:", i);
        for (j = 0; j < ginfo.nb_txq; j++)
        {
            if (j % 5 == 0)
            {
                printf("\n        ");
            }
            printf("q#%d: %llu ", j, (unsigned long long)port_stats[i].txq_stats[j].tx_total_pkts);
            port_stats->tx_total_pkts += port_stats[i].txq_stats[j].tx_total_pkts;
        }
        printf("\n      ->b:");
        for (j = 0; j < ginfo.nb_txq; j++)
        {
            if (j % 5 == 0)
            {
                printf("\n        ");
            }
            printf("q#%d: %llu ", j, (unsigned long long)port_stats[i].txq_stats[j].tx_total_bytes);
            port_stats->tx_total_bytes += port_stats[i].txq_stats[j].tx_total_bytes;
        }
        printf("\ntx total bytes: %lu", port_stats->tx_total_bytes);
        printf("\n    ->rx:\n      ->p:");
        for (j = 0; j < ginfo.nb_rxq; j++)
        {
            if (j % 5 == 0)
            {
                printf("\n        ");
            }
            printf("q#%d: %llu ", j, (unsigned long long)port_stats[i].rxq_stats[j].rx_total_pkts);
            port_stats->rx_total_pkts += port_stats[i].rxq_stats[j].rx_total_pkts;
        }
        printf("\n      ->b:");
        for (j = 0; j < ginfo.nb_rxq; j++)
        {
            if (j % 5 == 0)
            {
                printf("\n        ");
            }
            printf("q#%d: %llu ", j, (unsigned long long)port_stats[i].rxq_stats[j].rx_total_bytes);
            port_stats->rx_total_bytes += port_stats[i].rxq_stats[j].rx_total_bytes;
        }
        printf("\n  #######################################\n");
    }
}

void nic_stats_display(uint16_t port_id)
{
    static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
    static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
    static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
    static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
    static uint64_t prev_ns[RTE_MAX_ETHPORTS];
    struct timespec cur_time;
    uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx,
        diff_ns;
    uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
    struct rte_eth_stats stats;

    static const char *nic_stats_border = "########################";

    // if (port_id_is_invalid(port_id, ENABLED_WARN))
    // {
    // 	print_valid_ports();
    // 	return;
    // }
    rte_eth_stats_get(port_id, &stats);
    printf("\n  %s NIC statistics for port %-2d %s\n",
           nic_stats_border, port_id, nic_stats_border);

    printf("  RX-packets: %-10" PRIu64 " RX-missed: %-10" PRIu64 " RX-bytes:  "
           "%-" PRIu64 "\n",
           stats.ipackets, stats.imissed, stats.ibytes);
    printf("  RX-errors: %-" PRIu64 "\n", stats.ierrors);
    printf("  RX-nombuf:  %-10" PRIu64 "\n", stats.rx_nombuf);
    printf("  TX-packets: %-10" PRIu64 " TX-errors: %-10" PRIu64 " TX-bytes:  "
           "%-" PRIu64 "\n",
           stats.opackets, stats.oerrors, stats.obytes);

    diff_ns = 0;
    if (clock_gettime(CLOCK_TYPE_ID, &cur_time) == 0)
    {
        uint64_t ns;

        ns = cur_time.tv_sec * NS_PER_SEC;
        ns += cur_time.tv_nsec;

        if (prev_ns[port_id] != 0)
            diff_ns = ns - prev_ns[port_id];
        prev_ns[port_id] = ns;
    }

    diff_pkts_rx = (stats.ipackets > prev_pkts_rx[port_id]) ? (stats.ipackets - prev_pkts_rx[port_id]) : 0;
    diff_pkts_tx = (stats.opackets > prev_pkts_tx[port_id]) ? (stats.opackets - prev_pkts_tx[port_id]) : 0;
    prev_pkts_rx[port_id] = stats.ipackets;
    prev_pkts_tx[port_id] = stats.opackets;
    mpps_rx = diff_ns > 0 ? (double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
    mpps_tx = diff_ns > 0 ? (double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

    diff_bytes_rx = (stats.ibytes > prev_bytes_rx[port_id]) ? (stats.ibytes - prev_bytes_rx[port_id]) : 0;
    diff_bytes_tx = (stats.obytes > prev_bytes_tx[port_id]) ? (stats.obytes - prev_bytes_tx[port_id]) : 0;
    prev_bytes_rx[port_id] = stats.ibytes;
    prev_bytes_tx[port_id] = stats.obytes;
    mbps_rx = diff_ns > 0 ? (double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
    mbps_tx = diff_ns > 0 ? (double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

    printf("\n  Throughput (since last show)\n");
    printf("  Rx-pps: %12" PRIu64 "          Rx-Mbps: %12" PRIu64 "\n  Tx-pps: %12" PRIu64 "          Tx-Mbps: %12" PRIu64 "\n",
           mpps_rx, mbps_rx * 8 / 1024 / 1024,
           mpps_tx, mbps_tx * 8 / 1024 / 1024);

    printf("  %s############################%s\n",
           nic_stats_border, nic_stats_border);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t rx_rings, uint16_t tx_rings)
{
    struct rte_eth_conf port_conf = port_conf_default;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    
    printf("\nport #%u nb_rxd=%u nb_txd=%u.\n", port, nb_rxd, nb_txd);

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

static void timer_handler(__rte_unused struct rte_timer *timer, void *arg)
{
    static uint32_t mb_pointer = 0;
    if (unlikely(mb_pointer > NB_MBUF-40))
    {
        mb_pointer = 0;
    }

    struct lcore_args *largs = (struct lcore_args *)arg;
    // struct gtp_packet gp = gp;
    int i;
    int ret;
    // uint8_t payload[256];
    // uint64_t tsc = rte_rdtsc();
    // rte_memcpy(payload, &tsc, sizeof(tsc));
    // for (i = 0; i < 10; i++)
    // {
    //     int r = rand();
    //     rte_memcpy(payload + 8 + i * sizeof(r), &r, sizeof(r));
    // }
    // set_payload(&local_gp, payload, sizeof(payload));

    for (i = 0; i < BURST_SIZE; i++)
    {
        largs->tx.m_table[i] = mbufs[mb_pointer++];
    }

    ret = rte_eth_tx_burst(largs->tx.port_id, largs->tx.queue_id, largs->tx.m_table, BURST_SIZE);
    // while(to_send != BURST_SIZE) {    
        // ret = rte_eth_tx_burst(largs->tx.port_id, largs->tx.queue_id, largs->tx.m_table + to_send, BURST_SIZE - to_send);
        // to_send += ret;
    // }

    // -1G
    // port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_total_pkts += ret;
    // port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_total_bytes += ret * pkt_length;

    if (unlikely(ret < BURST_SIZE)) {
        while (ret < BURST_SIZE)
        {
            rte_pktmbuf_free(largs->tx.m_table[ret++]);
        }
    }
    // printf("\nl2 s_mac: %02X:%02X:%02X:%02X:%02X:%02X, d_mac: %02X:%02X:%02X:%02X:%02X:%02X, eth_type: %04X\n",
    // 	   gp.ether.s_addr.addr_bytes[0], gp.ether.s_addr.addr_bytes[1],
    // 	   gp.ether.s_addr.addr_bytes[2], gp.ether.s_addr.addr_bytes[3],
    // 	   gp.ether.s_addr.addr_bytes[4], gp.ether.s_addr.addr_bytes[5],
    // 	   gp.ether.d_addr.addr_bytes[0], gp.ether.d_addr.addr_bytes[1],
    // 	   gp.ether.d_addr.addr_bytes[2], gp.ether.d_addr.addr_bytes[3],
    // 	   gp.ether.d_addr.addr_bytes[4], gp.ether.d_addr.addr_bytes[5],
    // 	   gp.ether.ether_type);
    // printf("\ngtp ext_hdr_len: %d, pdu_session_container:%02X%02X, next_ext_hdr_type: %02X\n",
    // 	   gp.gtp.pdu_session_container.ext_hdr_len, gp.gtp.pdu_session_container.pdu_session_container[0],
    // 	   gp.gtp.pdu_session_container.pdu_session_container[1], gp.gtp.pdu_session_container.next_ext_hdr_type);
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

__rte_noreturn static int
tx_lcore_main(void *args)
{
    struct lcore_args *largs;
    int ret;

    largs = (struct lcore_args *)args;
    assert(largs->tx.is_tx_lcore);

    port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_total_pkts = 0;
    port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_last_total_pkts = 0;
    port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_total_bytes = 0;
    port_stats[largs->tx.port_id].txq_stats[largs->tx.queue_id].tx_last_total_bytes = 0;
    rte_timer_init(&largs->tx.timer);

    largs->tx.period =
        BURST_SIZE * (pkt_length)*8 * rte_get_tsc_hz() * ginfo.nb_txq / (ginfo.tx_mbps * 1024 * 1024);
    printf("CPU#%d lcore#%u is sending packet from port %u - queue %u, period is %lu\n", sched_getcpu(), rte_lcore_id(), largs->tx.port_id, largs->tx.queue_id, largs->tx.period);

    if (debug)
    {
        rte_timer_reset(&largs->tx.timer, largs->tx.period, SINGLE, rte_lcore_id(), timer_handler, largs);
    }
    else
    {
        rte_timer_reset(&largs->tx.timer, largs->tx.period, PERIODICAL, rte_lcore_id(), timer_handler, largs);
    }

    for (;;)
    {
        rte_timer_manage();
    }
}

__rte_noreturn static int
rx_lcore_main(void *args)
{
    struct lcore_args *largs;
    uint8_t is_rx;
    uint16_t rxq_id;
    int ret;
    struct rte_mbuf *rx_bufs[BURST_SIZE];

    largs = (struct lcore_args *)args;
    assert(largs->rx.is_rx_lcore);
    rxq_id = (uint16_t)(largs->rx.queue_id);

    printf("CPU#%d lcore#%u is receiving packet from port %u - queue %u\n", sched_getcpu(), rte_lcore_id(), largs->rx.port_id,
           largs->rx.queue_id);

    port_stats[largs->rx.port_id].rxq_stats[largs->rx.queue_id].rx_total_pkts = 0;
    port_stats[largs->rx.port_id].rxq_stats[largs->rx.queue_id].rx_last_total_pkts = 0;
    port_stats[largs->rx.port_id].rxq_stats[largs->rx.queue_id].rx_total_bytes = 0;
    port_stats[largs->rx.port_id].rxq_stats[largs->rx.queue_id].rx_last_total_bytes = 0;

    for (;;)
    {
        ret = rte_eth_rx_burst(largs->rx.port_id, largs->rx.queue_id, largs->rx.m_table, BURST_SIZE);
        port_stats[largs->rx.port_id].rxq_stats[rxq_id].rx_total_pkts += ret;
        for (int i = 0; i < ret; i++)
        {
            port_stats[largs->rx.port_id].rxq_stats[rxq_id].rx_total_bytes += rte_pktmbuf_pkt_len(largs->rx.m_table[i]);
            rte_pktmbuf_free(largs->rx.m_table[i]);
        }
    }
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;
    struct gtp_packet gp;
    struct gtp_packet gp2;

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initializion the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    debug = 0;
    parse_params(argc, argv);
    printf("[CONF]tx speed: %lluMbps, tx queue: %d, rx queue: %d.\n", (unsigned long long)ginfo.tx_mbps, ginfo.nb_txq,
           ginfo.nb_rxq);
    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();

    unsigned int lcore_num = rte_lcore_count();
    if (lcore_num - 1 < ginfo.nb_txq + ginfo.nb_rxq)
    {
        rte_exit(EXIT_FAILURE, "working lcore num less than queue num.\n");
    }
    /* Creates a new mempool in memory to hold the mbufs. */

    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    /* >8 End of allocating mempool to hold mbuf. */

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    rte_timer_subsystem_init();

    for (int i = 0; i < lcore_num; i++)
    {
        if (0 < i && i < ginfo.nb_txq + 1)
        {
            lc_args[i].tx.is_tx_lcore = 1;
            lc_args[i].tx.mp = mbuf_pool;
            lc_args[i].tx.queue_id = i - 1;
            lc_args[i].tx.port_id = 0;
        }
        if (lcore_num - ginfo.nb_rxq - 1 < i)
        {
            lc_args[i].rx.is_rx_lcore = 1;
            lc_args[i].rx.queue_id = i + ginfo.nb_rxq - (int)lcore_num;
            lc_args[i].rx.port_id = 1;
        }
    }

    uint16_t _pkt_length = pkt_length;
    // to upf
    set_mac(&(gp.ether), "52:54:00:15:3e:09", "52:54:00:77:0c:cc");
    // local
    //    set_mac(&(gp.ether), "52:54:00:15:3e:09", "52:54:00:42:b2:9b");
    _pkt_length -= sizeof(gp.ether);
    set_ipv4(&(gp.ipv4_1), "1.1.1.1", "1.1.1.2", 17, _pkt_length);
    _pkt_length -= sizeof(gp.ipv4_1);
    set_udp(&(gp.udp_1), &(gp.ipv4_1), 2152, 2152, _pkt_length);
    _pkt_length -= sizeof(gp.udp_1);
    set_gtp(&(gp.gtp), 0x01, _pkt_length);
    _pkt_length -= sizeof(gp.gtp);
    set_ipv4(&(gp.ipv4_2), "60.60.0.1", "1.1.1.3", 17, _pkt_length);
    _pkt_length -= sizeof(gp.ipv4_2);
    set_udp(&(gp.udp_2), &(gp.ipv4_1), 10000, 10000, _pkt_length);

    set_udp(&(gp2.udp_2), &(gp.ipv4_1), 10000, 10000, _pkt_length);
    
    for (size_t i = 0; i < NB_MBUF; i++)
    {
        struct rte_mbuf* mb;
        set_udp_port(&(gp.udp_2), (uint16_t)rand()%20000+20000, (uint16_t)rand()%20000+20000);
        mb = generate_mbuf(&gp, mbuf_pool, pkt_length);
        mb->ol_flags |= PKT_TX_UDP_CKSUM;
        mbufs[i] = mb;
    }
    

    /* Initializing all ports. 8< */
    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool, ginfo.nb_rxq, ginfo.nb_txq) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                 portid);

    printf("\nusing %d cores.\n", lcore_num);

    int lcore_id;
    RTE_LCORE_FOREACH(lcore_id)
    {
        if (lcore_id == 0)
        {
            continue;
        }
        if (lc_args[lcore_id].tx.is_tx_lcore)
        {
            rte_eal_remote_launch(tx_lcore_main, (void *)&lc_args[lcore_id], lcore_id);
        }
        else if (lc_args[lcore_id].rx.is_rx_lcore)
        {
            rte_eal_remote_launch(rx_lcore_main, (void *)&lc_args[lcore_id], lcore_id);
        }
    }
    /* >8 End of called on single lcore. */
    for (;;)
    {
        char c;
        c = getchar();
        if (c == 'q')
        {
            rte_exit(0, "quit");
        }
        else if (c == 's')
        {
            nic_stats_display(0);
            nic_stats_display(1);
        }
        else if (c == 'm'){
            my_stats_display();
        }
    }
    /* clean up the EAL */

    return 0;
}
