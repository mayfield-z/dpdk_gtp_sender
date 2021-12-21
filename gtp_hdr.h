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

struct gtp_packet
{
    struct rte_ether_hdr ether;
    struct rte_ipv4_hdr ipv4_1;
    struct rte_udp_hdr udp_1;
    struct gtp_hdr gtp;
    struct rte_ipv4_hdr ipv4_2;
    struct rte_udp_hdr udp_2;
    uint8_t payload[512];
} __attribute__((packed));

#endif