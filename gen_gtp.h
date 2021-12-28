#ifndef GEN_GTP
#define GEN_GTP

#include "gtp_hdr.h"

#ifdef __cplusplus
extern "C"
{
#endif

void set_mac(struct rte_ether_hdr *eth_hdr, char *d_mac_str, char *s_mac_str);
void set_ipv4(struct rte_ipv4_hdr *ipv4, char *s_ip_str, char *d_ip_str, uint8_t next_proto_id, uint16_t len);
void set_udp(struct rte_udp_hdr *udp, struct rte_ipv4_hdr *ipv4, uint16_t s_port, uint16_t d_port, uint16_t len);
void set_udp_port(struct rte_udp_hdr *udp, uint16_t s_port, uint16_t d_port);
void set_gtp(struct gtp_hdr *gtp, uint64_t teid, uint16_t len);
void set_icmp(struct rte_icmp_hdr *icmp);
void set_payload(struct gtp_pkt *gp, uint8_t *payload, uint16_t payload_length);
struct rte_mbuf *generate_mbuf(struct gtp_pkt *gp, struct rte_mempool *mp, uint16_t pkt_length);
void generate_gtp(struct gtp_pkt_info *info);

#ifdef __cplusplus
}
#endif

#endif