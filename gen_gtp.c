#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include "gtp_hdr.h"

uint16_t pkt_length = 512;

void set_mac(struct rte_ether_hdr *eth_hdr, char *s_mac_str, char *d_mac_str)
{
    int i = 0;
    uint8_t *mac_p = NULL;
    static uint8_t base;

    memset(&(eth_hdr->d_addr), 0, sizeof(eth_hdr->d_addr));
    memset(&(eth_hdr->s_addr), 0, sizeof(eth_hdr->s_addr));
    srand(time(NULL));

    /* s mac */
    if (!s_mac_str)
    {
        for (i = 0; i < 6; ++i)
        {
            // eth_hdr->s_addr.addr_bytes[i] = (uint8_t)0x34;
            eth_hdr->s_addr.addr_bytes[i] = ++base;
        }
    }
    else
    {
        mac_p = &(eth_hdr->s_addr.addr_bytes[0]);
        sscanf(s_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               mac_p, mac_p + 1, mac_p + 2,
               mac_p + 3, mac_p + 4, mac_p + 5);
    }

    /* d mac */
    if (!d_mac_str)
    {
        for (i = 0; i < 6; ++i)
        {
            // eth_hdr->d_addr.addr_bytes[i] = (uint8_t)0x12;
            eth_hdr->d_addr.addr_bytes[i] = ++base;
        }
    }
    else
    {
        mac_p = &(eth_hdr->d_addr.addr_bytes[0]);
        sscanf(d_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               mac_p, mac_p + 1, mac_p + 2,
               mac_p + 3, mac_p + 4, mac_p + 5);
    }

    eth_hdr->ether_type = htons((uint16_t)0x0800);
}

void set_ipv4(struct rte_ipv4_hdr *ipv4, char *s_ip_str, char *d_ip_str, uint8_t next_proto_id, uint16_t len)
{
    static int cnt = 0;

    //ipv4 header
    srand(time(NULL));
    ipv4->version_ihl = (uint8_t)0x45;
    ipv4->type_of_service = (uint8_t)0;
    ipv4->total_length = htons(len);
    ipv4->packet_id = (uint16_t)rand();
    ipv4->fragment_offset = 0x0040; //DF
    ipv4->time_to_live = 0x40;
    ipv4->next_proto_id = next_proto_id;
    ipv4->hdr_checksum = 0;

    /* s ip */
    ipv4->src_addr = inet_addr(s_ip_str);

    /* d ip */
    ipv4->dst_addr = inet_addr(d_ip_str);

    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
}

void set_udp(struct rte_udp_hdr *udp, struct rte_ipv4_hdr *ipv4, uint16_t s_port, uint16_t d_port, uint16_t len)
{
    srand(time(NULL));

    udp->src_port = htons(s_port);
    udp->dst_port = htons(d_port);
    udp->dgram_len = htons(len);
    udp->dgram_cksum = 0;
    // udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, (void *)(udp));
}

void set_udp_port(struct rte_udp_hdr *udp, uint16_t s_port, uint16_t d_port)
{
    udp->src_port = htons(s_port);
    udp->dst_port = htons(d_port);
}

void set_gtp(struct gtp_hdr *gtp, uint64_t teid, uint16_t len)
{
    srand(time(NULL));
    gtp->flag = 0x34;
    gtp->message_type = 0xff;
    gtp->length = htons(len);
    gtp->teid = htonl(teid);
    for (uint8_t i = 0; i < 3; i++)
    {
        gtp->zero[i] = 0;
    }
    gtp->next_ext_hdr_type = 0x85;
    gtp->pdu_session_container.ext_hdr_len = 1;
    gtp->pdu_session_container.pdu_session_container[0] = 0x10;
    gtp->pdu_session_container.pdu_session_container[1] = 0x09;
    gtp->pdu_session_container.next_ext_hdr_type = 0x00;
}

void set_icmp(struct rte_icmp_hdr *icmp) {
    srand(time(NULL));
    icmp->icmp_type = 8;
    icmp->icmp_code = 0;
    icmp->icmp_ident = htobe16(0x09);
    icmp->icmp_seq_nb = htobe16(0x02);
    icmp->icmp_cksum = 0x2fc9;
}

void set_payload(struct gtp_packet *gp, uint8_t *payload, uint16_t payload_length) {
    assert(payload_length <= sizeof(gp->payload));
    rte_memcpy(gp->payload, payload, payload_length);
}

struct rte_mbuf *generate_mbuf(struct gtp_packet *gp, struct rte_mempool *mp, uint32_t pkt_length)
{
    struct rte_mbuf *m = NULL;

    m = rte_pktmbuf_alloc(mp);
    if (m == NULL)
    {
        rte_exit(-1, "mempool is empty!\n");
    }
    assert(pkt_length > sizeof(*gp) - sizeof(gp->payload));

    char *data;
//    data = rte_pktmbuf_append(m, sizeof(*gp));
    data = rte_pktmbuf_append(m, pkt_length);
    if (data == NULL)
    {
        rte_exit(-1, "mbuf append gtp packet failed!\n");
    }
    if (pkt_length < sizeof(*gp))
    {
        rte_memcpy(data, gp, pkt_length);
    } else {
        rte_memcpy(data, gp, sizeof(*gp));
    }


    return m;
}