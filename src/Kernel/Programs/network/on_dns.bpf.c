#include "allocators.bpf.h"
#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"
#include "event_and_rule_matcher.bpf.h"
#include "prevention.bpf.h"

#define DNS_HEADER_SIZE 12
#define SOCK_TYPE_MASK_LOCAL 0xf
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define UDP_HEADER_SIZE 8

statfunc unsigned short resolve_transport_protocol(const struct socket *sock, const struct sock *sk)
{
    const unsigned short protocol = BPF_CORE_READ(sk, sk_protocol);
    if (protocol == IPPROTO_UDP || protocol == IPPROTO_TCP)
    {
        return protocol;
    }

    const unsigned short socket_type = BPF_CORE_READ(sock, type) & SOCK_TYPE_MASK_LOCAL;
    if (socket_type == SOCK_DGRAM)
    {
        return IPPROTO_UDP;
    }
    if (socket_type == SOCK_STREAM)
    {
        return IPPROTO_TCP;
    }

    return protocol;
}

static __attribute__((noinline)) unsigned int clamp_dns_payload_len(unsigned int payload_len)
{
    if (payload_len < DNS_HEADER_SIZE)
    {
        return 0;
    }
    if (payload_len > DNS_PACKET_CAPTURE_LENGTH)
    {
        return DNS_PACKET_CAPTURE_LENGTH;
    }

    return payload_len;
}

statfunc int read_destination_port_from_msghdr(const struct msghdr *msg, unsigned short *destination_port)
{
    if (!msg || !destination_port)
    {
        return NOT_SUPPORTED;
    }

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    const int msg_name_len = BPF_CORE_READ(msg, msg_namelen);
    if (!msg_name || msg_name_len < 4)
    {
        return NOT_SUPPORTED;
    }

    unsigned short family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), msg_name) != SUCCESS &&
        bpf_probe_read_user(&family, sizeof(family), msg_name) != SUCCESS)
    {
        return NOT_SUPPORTED;
    }
    if (family != AF_INET && family != AF_INET6)
    {
        return NOT_SUPPORTED;
    }

    unsigned short port_nbo = 0;
    if (bpf_probe_read_kernel(&port_nbo, sizeof(port_nbo), (const unsigned char *)msg_name + sizeof(family)) != SUCCESS &&
        bpf_probe_read_user(&port_nbo, sizeof(port_nbo), (const unsigned char *)msg_name + sizeof(family)) != SUCCESS)
    {
        return NOT_SUPPORTED;
    }

    *destination_port = bpf_ntohs(port_nbo);
    return SUCCESS;
}

statfunc int fill_network_event_from_sock(struct network_event_t *network_event, struct socket *sock, struct sock *sk, struct msghdr *msg, enum connection_direction direction)
{
    if (!sock || !sk)
    {
        REPORT_ERROR(GENERIC_ERROR, "sock/sk is null");
        return NOT_SUPPORTED;
    }

    const unsigned short protocol = resolve_transport_protocol(sock, sk);
    /*
    We currently support DNS payload extraction only for UDP.
    DNS over TCP has a two-byte length prefix and different framing.
    */
    if (protocol != IPPROTO_UDP)
    {
        return NOT_SUPPORTED;
    }
    if (direction == OUTGOING)
    {
        unsigned short dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (dport == 0)
        {
            read_destination_port_from_msghdr(msg, &dport);
        }
        if (dport != 53)
        {
            return NOT_SUPPORTED;
        }
    }
    else
    {
        unsigned short sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (sport == 0)
        {
            read_destination_port_from_msghdr(msg, &sport);
        }
        if (sport != 53)
        {
            return NOT_SUPPORTED;
        }
    }
    network_event->protocol = protocol;
    network_event->direction = direction;

    const unsigned short family = BPF_CORE_READ(sk, __sk_common.skc_family);
    network_event->ip_type = family;
    if (family == AF_INET)
    {
        if (direction == OUTGOING)
        {
            network_event->addresses.ipv4.source_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            network_event->addresses.ipv4.destination_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            network_event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
            network_event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
            if (network_event->destination_port == 0)
            {
                read_destination_port_from_msghdr(msg, &network_event->destination_port);
            }
        }
        else
        {
            network_event->addresses.ipv4.source_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            network_event->addresses.ipv4.destination_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            network_event->source_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
            network_event->destination_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        }
        return SUCCESS;
    }
    if (family == AF_INET6)
    {
        if (direction == OUTGOING)
        {
            BPF_CORE_READ_INTO(&network_event->addresses.ipv6.source_ip, sk, __sk_common.skc_v6_rcv_saddr);
            BPF_CORE_READ_INTO(&network_event->addresses.ipv6.destination_ip, sk, __sk_common.skc_v6_daddr);
            network_event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
            network_event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
            if (network_event->destination_port == 0)
            {
                read_destination_port_from_msghdr(msg, &network_event->destination_port);
            }
        }
        else
        {
            BPF_CORE_READ_INTO(&network_event->addresses.ipv6.source_ip, sk, __sk_common.skc_v6_daddr);
            BPF_CORE_READ_INTO(&network_event->addresses.ipv6.destination_ip, sk, __sk_common.skc_v6_rcv_saddr);
            network_event->source_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
            network_event->destination_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        }
        return SUCCESS;
    }

    return NOT_SUPPORTED;
}

statfunc int read_dns_packet(struct msghdr *msg, unsigned char *packet, unsigned short *packet_len, unsigned int max_copy_len)
{
    void *iov_base = NULL;
    __kernel_size_t iov_len = 0;
    struct iov_iter iter = {};
    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) != SUCCESS &&
        bpf_probe_read_user(&iter, sizeof(iter), &msg->msg_iter) != SUCCESS)
    {
        return NOT_SUPPORTED;
    }

    if (iter.__ubuf_iovec.iov_base && iter.__ubuf_iovec.iov_len)
    {
        iov_base = iter.__ubuf_iovec.iov_base;
        iov_len = iter.__ubuf_iovec.iov_len;
    }
    else
    {
        const struct iovec *iov = iter.__iov;
        if (!iov)
        {
            return NOT_SUPPORTED;
        }

        struct iovec first_iov = {};
        if (bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov) != SUCCESS &&
            bpf_probe_read_user(&first_iov, sizeof(first_iov), iov) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }
        iov_base = first_iov.iov_base;
        iov_len = first_iov.iov_len;
    }

    const __kernel_size_t offset = iter.iov_offset;
    if (offset >= iov_len)
    {
        return NOT_SUPPORTED;
    }
    iov_base = (void *)((unsigned char *)iov_base + offset);
    iov_len -= offset;

    if (iov_len < DNS_HEADER_SIZE)
    {
        return NOT_SUPPORTED;
    }

    unsigned int bytes_to_copy = DNS_PACKET_CAPTURE_LENGTH;
    if (iov_len < bytes_to_copy)
    {
        bytes_to_copy = (unsigned int)iov_len;
    }
    if (max_copy_len > 0 && bytes_to_copy > max_copy_len)
    {
        bytes_to_copy = max_copy_len;
    }
    if (bytes_to_copy < DNS_HEADER_SIZE)
    {
        return NOT_SUPPORTED;
    }

    if (bpf_probe_read_user(packet, bytes_to_copy, iov_base) != SUCCESS &&
        bpf_probe_read_kernel(packet, bytes_to_copy, iov_base) != SUCCESS)
    {
        return NOT_SUPPORTED;
    }

    *packet_len = (unsigned short)bytes_to_copy;
    return SUCCESS;
}

statfunc int process_dns_query_message(struct socket *sock, struct msghdr *msg)
{
    if (is_current_pid_related())
    {
        return ALLOW;
    }
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
    {
        return ALLOW;
    }

    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed");
        return ALLOW;
    }

    struct network_event_t network_event = {};
    if (fill_network_event_from_sock(&network_event, sock, sk, msg, OUTGOING) != SUCCESS)
    {
        // REPORT_ERROR(GENERIC_ERROR, "fill_network_event_from_sock failed");
        bpf_ringbuf_discard(event, 0);
        return ALLOW;
    }

    unsigned short packet_len = 0;
    event->type = DNS_QUERY;
    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);
    event->data.dns_query.network = network_event;
    event->data.dns_query.txid = 0;
    event->data.dns_query.question_type = 0;
    event->data.dns_query.question[0] = '\0';
    event->data.dns_query.question_len = 0;
    event->data.dns_query.raw_packet_len = 0;
    if (read_dns_packet(msg, event->data.dns_query.raw_packet, &packet_len, 0) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "dns read_dns_packet failed");
        bpf_ringbuf_discard(event, 0);
        return ALLOW;
    }
    event->data.dns_query.raw_packet_len = packet_len;
    bpf_ringbuf_submit(event, 0);
    return ALLOW;
}

statfunc int fill_incoming_network_event_from_skb(struct __sk_buff *skb, struct network_event_t *network_event, unsigned int *payload_offset, unsigned int *payload_len)
{
    if (!skb || !network_event || !payload_offset || !payload_len)
    {
        return NOT_SUPPORTED;
    }

    unsigned char eth_hdr[14] = {};
    if (bpf_skb_load_bytes(skb, 0, eth_hdr, sizeof(eth_hdr)) != SUCCESS)
    {
        return NOT_SUPPORTED;
    }
    const unsigned short eth_proto = ((unsigned short)eth_hdr[12] << 8) | eth_hdr[13];

    network_event->direction = INCOMING;
    network_event->protocol = IPPROTO_UDP;

    if (eth_proto == ETH_P_IP)
    {
        unsigned char ip_hdr[20] = {};
        if (bpf_skb_load_bytes(skb, sizeof(eth_hdr), ip_hdr, sizeof(ip_hdr)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }

        const unsigned char version = ip_hdr[0] >> 4;
        const unsigned char ihl = (ip_hdr[0] & 0x0F) * 4;
        if (version != 4 || ihl < 20 || ip_hdr[9] != IPPROTO_UDP)
        {
            return NOT_SUPPORTED;
        }

        unsigned char udp_hdr[UDP_HEADER_SIZE] = {};
        if (bpf_skb_load_bytes(skb, sizeof(eth_hdr) + ihl, udp_hdr, sizeof(udp_hdr)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }

        const unsigned short src_port = ((unsigned short)udp_hdr[0] << 8) | udp_hdr[1];
        const unsigned short dst_port = ((unsigned short)udp_hdr[2] << 8) | udp_hdr[3];
        const unsigned int udp_len = ((unsigned int)udp_hdr[4] << 8) | udp_hdr[5];
        if (src_port != 53 || udp_len < UDP_HEADER_SIZE + DNS_HEADER_SIZE)
        {
            return NOT_SUPPORTED;
        }

        network_event->ip_type = AF_INET;
        network_event->source_port = src_port;
        network_event->destination_port = dst_port;

        unsigned int src_ip = 0;
        unsigned int dst_ip = 0;
        unsigned int off_src_ip = sizeof(eth_hdr) + 12;
        unsigned int off_dst_ip = sizeof(eth_hdr) + 16;
        if (bpf_skb_load_bytes(skb, off_src_ip, &src_ip, sizeof(src_ip)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }
        if (bpf_skb_load_bytes(skb, off_dst_ip, &dst_ip, sizeof(dst_ip)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }
        network_event->addresses.ipv4.source_ip = src_ip;
        network_event->addresses.ipv4.destination_ip = dst_ip;

        *payload_offset = sizeof(eth_hdr) + ihl + UDP_HEADER_SIZE;
        *payload_len = udp_len - UDP_HEADER_SIZE;
        return SUCCESS;
    }

    if (eth_proto == ETH_P_IPV6)
    {
        unsigned char ipv6_hdr[40] = {};
        if (bpf_skb_load_bytes(skb, sizeof(eth_hdr), ipv6_hdr, sizeof(ipv6_hdr)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }

        const unsigned char version = ipv6_hdr[0] >> 4;
        if (version != 6 || ipv6_hdr[6] != IPPROTO_UDP)
        {
            return NOT_SUPPORTED;
        }

        unsigned char udp_hdr[UDP_HEADER_SIZE] = {};
        if (bpf_skb_load_bytes(skb, sizeof(eth_hdr) + 40, udp_hdr, sizeof(udp_hdr)) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }

        const unsigned short src_port = ((unsigned short)udp_hdr[0] << 8) | udp_hdr[1];
        const unsigned short dst_port = ((unsigned short)udp_hdr[2] << 8) | udp_hdr[3];
        const unsigned int udp_len = ((unsigned int)udp_hdr[4] << 8) | udp_hdr[5];
        if (src_port != 53 || udp_len < UDP_HEADER_SIZE + DNS_HEADER_SIZE)
        {
            return NOT_SUPPORTED;
        }

        network_event->ip_type = AF_INET6;
        network_event->source_port = src_port;
        network_event->destination_port = dst_port;
        if (bpf_skb_load_bytes(skb, sizeof(eth_hdr) + 8, network_event->addresses.ipv6.source_ip, 16) != SUCCESS ||
            bpf_skb_load_bytes(skb, sizeof(eth_hdr) + 24, network_event->addresses.ipv6.destination_ip, 16) != SUCCESS)
        {
            return NOT_SUPPORTED;
        }

        *payload_offset = sizeof(eth_hdr) + 40 + UDP_HEADER_SIZE;
        *payload_len = udp_len - UDP_HEADER_SIZE;
        return SUCCESS;
    }

    return NOT_SUPPORTED;
}

/* cgroup/sendmsg handlers receive a struct sk_msg_md * context. Implement
 * a separate path that pulls message data using bpf_msg_pull_data and then
 * reuses the existing DNS parsing helpers. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(dns_query_hook, struct socket *sock, struct msghdr *msg, int size)
{
    set_hook_name("dns_query_hook", 14);
    return process_dns_query_message(sock, msg);
}

SEC("tc")
int dns_response_tc_ingress(struct __sk_buff *skb)
{
    set_hook_name("dns_response_tc_ingress", 23);

    struct network_event_t network_event = {};
    unsigned int payload_offset = 0;
    unsigned int payload_len = 0;
    if (fill_incoming_network_event_from_skb(skb, &network_event, &payload_offset, &payload_len) != SUCCESS)
    {
        return TC_ACT_OK;
    }

    unsigned int helper_len = clamp_dns_payload_len(payload_len);
    if (helper_len == 0)
    {
        return TC_ACT_OK;
    }

    /* Allocate only after size validation and start from empty_event_t so all
     * fields are initialized before publishing to userspace. */
    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, payload_offset, event->data.dns_response.raw_packet, helper_len) != SUCCESS)
    {
        bpf_ringbuf_discard(event, 0);
        return TC_ACT_OK;
    }

    event->type = DNS_RESPONSE;
    event->data.dns_response.network = network_event;
    event->data.dns_response.txid = 0;
    event->data.dns_response.question_type = 0;
    event->data.dns_response.answer_count = 0;
    event->data.dns_response.rcode = 0;
    event->data.dns_response.question[0] = '\0';
    event->data.dns_response.question_len = 0;
    event->data.dns_response.raw_packet_len = (unsigned short)helper_len;

    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
