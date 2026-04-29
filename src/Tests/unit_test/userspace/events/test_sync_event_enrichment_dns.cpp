#include <gtest/gtest.h>

#include "events/sync_enrichment.hpp"
#include "globals/global_objects.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
using owlsm::events::Event;
using owlsm::events::SyncEventEnrichment;

event_t make_dns_query_raw_event(const unsigned short txid, const unsigned short source_port)
{
    event_t raw_event = {};
    raw_event.type = DNS_QUERY;
    raw_event.action = ALLOW_EVENT;
    raw_event.process.pid = 777;
    raw_event.parent_process.pid = 555;

    raw_event.data.dns_query.network.direction = OUTGOING;
    raw_event.data.dns_query.network.protocol = 17;
    raw_event.data.dns_query.network.ip_type = AF_INET;
    raw_event.data.dns_query.network.source_port = source_port;
    raw_event.data.dns_query.network.destination_port = 53;
    raw_event.data.dns_query.network.addresses.ipv4.source_ip = htonl(0x0A000001);
    raw_event.data.dns_query.network.addresses.ipv4.destination_ip = htonl(0x08080808);

    const std::vector<unsigned char> packet = {
        static_cast<unsigned char>(txid >> 8), static_cast<unsigned char>(txid & 0xFF),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    raw_event.data.dns_query.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_query.raw_packet, packet.data(), packet.size());

    return raw_event;
}

event_t make_dns_response_raw_event(const unsigned short txid, const unsigned short destination_port)
{
    event_t raw_event = {};
    raw_event.type = DNS_RESPONSE;
    raw_event.action = ALLOW_EVENT;

    raw_event.data.dns_response.network.direction = INCOMING;
    raw_event.data.dns_response.network.protocol = 17;
    raw_event.data.dns_response.network.ip_type = AF_INET;
    raw_event.data.dns_response.network.source_port = 53;
    raw_event.data.dns_response.network.destination_port = destination_port;
    raw_event.data.dns_response.network.addresses.ipv4.source_ip = htonl(0x08080808);
    raw_event.data.dns_response.network.addresses.ipv4.destination_ip = htonl(0x0A000001);

    const std::vector<unsigned char> packet = {
        static_cast<unsigned char>(txid >> 8), static_cast<unsigned char>(txid & 0xFF),
        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x1E, 0x00, 0x04,
        0x08, 0x08, 0x08, 0x08
    };
    raw_event.data.dns_response.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_response.raw_packet, packet.data(), packet.size());

    return raw_event;
}
}

TEST(SyncEventEnrichmentDnsTest, dns_response_uses_cached_query_process_data)
{
    owlsm::globals::g_config.rules_config.rules.clear();
    SyncEventEnrichment enrichment;

    auto query = std::make_shared<Event>(make_dns_query_raw_event(0x1234, 53000));
    query->process.pid = 3333;
    query->parent_process.pid = 2222;
    enrichment.enrich(query);

    auto response = std::make_shared<Event>(make_dns_response_raw_event(0x1234, 53000));
    enrichment.enrich(response);

    EXPECT_EQ(response->action, ALLOW_EVENT);
    EXPECT_EQ(response->process.pid, 3333u);
    EXPECT_EQ(response->parent_process.pid, 2222u);
}

TEST(SyncEventEnrichmentDnsTest, dns_response_without_cached_query_is_excluded)
{
    owlsm::globals::g_config.rules_config.rules.clear();
    SyncEventEnrichment enrichment;

    auto response = std::make_shared<Event>(make_dns_response_raw_event(0x1234, 53000));
    enrichment.enrich(response);

    EXPECT_EQ(response->action, EXCLUDE_EVENT);
}

TEST(SyncEventEnrichmentDnsTest, dns_response_with_mismatched_txid_is_excluded)
{
    owlsm::globals::g_config.rules_config.rules.clear();
    SyncEventEnrichment enrichment;

    auto query = std::make_shared<Event>(make_dns_query_raw_event(0xAAAA, 53001));
    enrichment.enrich(query);

    auto response = std::make_shared<Event>(make_dns_response_raw_event(0xBBBB, 53001));
    enrichment.enrich(response);

    EXPECT_EQ(response->action, EXCLUDE_EVENT);
}

TEST(SyncEventEnrichmentDnsTest, dns_query_parse_failure_is_excluded)
{
    owlsm::globals::g_config.rules_config.rules.clear();
    SyncEventEnrichment enrichment;

    event_t raw_event = make_dns_query_raw_event(0x2001, 53002);
    raw_event.data.dns_query.raw_packet_len = 0;

    auto query = std::make_shared<Event>(raw_event);
    enrichment.enrich(query);

    EXPECT_EQ(query->action, EXCLUDE_EVENT);
}
