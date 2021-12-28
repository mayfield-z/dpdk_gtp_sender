#ifndef GTP_HDR_H
#define GTP_HDR_H

#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_icmp.h>

struct ext_hdr
{
    uint8_t ext_hdr_len;
    uint8_t pdu_session_container[2];
    uint8_t next_ext_hdr_type;
} __attribute__((packed));

struct gtp_hdr
{
    uint8_t flag;
    uint8_t message_type;
    rte_be16_t length;
    rte_be32_t teid;
    uint8_t zero[3];
    uint8_t next_ext_hdr_type;
    struct ext_hdr pdu_session_container;
} __attribute__((aligned));

struct gtp_pkt
{
    struct rte_ether_hdr ether;
    struct rte_ipv4_hdr ipv4_1;
    struct rte_udp_hdr udp_1;
    struct gtp_hdr gtp;
    struct rte_ipv4_hdr ipv4_2;
    struct rte_udp_hdr udp_2;
    uint8_t payload[512];
} __attribute__((packed));

struct gtp_pkt_info
{
    uint16_t pkt_length;
    uint16_t payload_offset;
    char *s_mac;
    char *d_mac;
    char *n3_gnb_ip;
    char *n3_upf_ip;
    uint64_t teid;
    char *ue_ip;
    char *dn_ip;
    uint16_t udp_s_port;
    uint16_t udp_d_port;
    uint8_t *payload;
    struct gtp_pkt *gp;
    struct rte_mbuf *mb;
} __attribute__((aligned));

#endif