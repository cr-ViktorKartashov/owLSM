#include <gtest/gtest.h>

#include "events/event.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <vector>

namespace
{
event_t make_base_dns_query()
{
    event_t raw_event = {};
    raw_event.type = DNS_QUERY;
    raw_event.action = ALLOW_EVENT;
    raw_event.data.dns_query.network.direction = OUTGOING;
    raw_event.data.dns_query.network.protocol = 17;
    raw_event.data.dns_query.network.ip_type = AF_INET;
    raw_event.data.dns_query.network.source_port = 53000;
    raw_event.data.dns_query.network.destination_port = 53;
    raw_event.data.dns_query.network.addresses.ipv4.source_ip = htonl(0x0A000001);
    raw_event.data.dns_query.network.addresses.ipv4.destination_ip = htonl(0x08080808);
    return raw_event;
}

event_t make_base_dns_response()
{
    event_t raw_event = {};
    raw_event.type = DNS_RESPONSE;
    raw_event.action = ALLOW_EVENT;
    raw_event.data.dns_response.network.direction = INCOMING;
    raw_event.data.dns_response.network.protocol = 17;
    raw_event.data.dns_response.network.ip_type = AF_INET;
    raw_event.data.dns_response.network.source_port = 53;
    raw_event.data.dns_response.network.destination_port = 53000;
    raw_event.data.dns_response.network.addresses.ipv4.source_ip = htonl(0x08080808);
    raw_event.data.dns_response.network.addresses.ipv4.destination_ip = htonl(0x0A000001);
    return raw_event;
}
}

TEST(DnsRawPacketParseTest, dns_query_parses_name_and_type_from_raw_packet)
{
    event_t raw_event = make_base_dns_query();
    const std::vector<unsigned char> packet = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    raw_event.data.dns_query.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_query.raw_packet, packet.data(), packet.size());

    const owlsm::events::Event event(raw_event);
    const auto* dns_query = std::get_if<owlsm::events::DnsQueryEventData>(&event.data);
    ASSERT_NE(dns_query, nullptr);
    EXPECT_TRUE(dns_query->parse_success);
    EXPECT_EQ(dns_query->txid, 0x1234);
    EXPECT_EQ(dns_query->question_type, 1);
    EXPECT_EQ(dns_query->question, "example.com");
}

TEST(DnsRawPacketParseTest, dns_query_with_pointer_loop_fails_parsing)
{
    event_t raw_event = make_base_dns_query();
    const std::vector<unsigned char> packet = {
        0x12, 0x35, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C,
        0x00, 0x01, 0x00, 0x01
    };
    raw_event.data.dns_query.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_query.raw_packet, packet.data(), packet.size());

    const owlsm::events::Event event(raw_event);
    const auto* dns_query = std::get_if<owlsm::events::DnsQueryEventData>(&event.data);
    ASSERT_NE(dns_query, nullptr);
    EXPECT_FALSE(dns_query->parse_success);
}

TEST(DnsRawPacketParseTest, dns_response_parses_ipv4_answer_to_string)
{
    event_t raw_event = make_base_dns_response();
    const std::vector<unsigned char> packet = {
        0x21, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x1E, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };
    raw_event.data.dns_response.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_response.raw_packet, packet.data(), packet.size());

    const owlsm::events::Event event(raw_event);
    const auto* dns_response = std::get_if<owlsm::events::DnsResponseEventData>(&event.data);
    ASSERT_NE(dns_response, nullptr);
    ASSERT_TRUE(dns_response->parse_success);
    ASSERT_EQ(dns_response->answers.size(), 1u);
    EXPECT_EQ(dns_response->answers[0].data, "1.2.3.4");
}

TEST(DnsRawPacketParseTest, dns_response_caps_oversized_rdata_conversion)
{
    event_t raw_event = make_base_dns_response();
    constexpr size_t data_len = DNS_MAX_NAME_LENGTH + 2;
    std::vector<unsigned char> packet;
    packet.reserve(12 + 13 + 4 + 12 + data_len);
    const unsigned char header[] = {
        0x33, 0x33, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x10, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x1E,
        0x00, static_cast<unsigned char>(data_len)
    };
    packet.insert(packet.end(), header, header + sizeof(header));
    packet.insert(packet.end(), data_len, 0xAB);

    raw_event.data.dns_response.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_response.raw_packet, packet.data(), packet.size());

    const owlsm::events::Event event(raw_event);
    const auto* dns_response = std::get_if<owlsm::events::DnsResponseEventData>(&event.data);
    ASSERT_NE(dns_response, nullptr);
    ASSERT_TRUE(dns_response->parse_success);
    ASSERT_EQ(dns_response->answers.size(), 1u);
    EXPECT_EQ(dns_response->answers[0].data_length, data_len);
    EXPECT_EQ(dns_response->answers[0].data.size(), DNS_MAX_NAME_LENGTH * 2);
}

TEST(DnsRawPacketParseTest, dns_response_with_non_compressed_answer_name_fails_parsing)
{
    event_t raw_event = make_base_dns_response();
    const std::vector<unsigned char> packet = {
        0x21, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x1C, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x1C, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x10,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    raw_event.data.dns_response.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(raw_event.data.dns_response.raw_packet, packet.data(), packet.size());

    const owlsm::events::Event event(raw_event);
    const auto* dns_response = std::get_if<owlsm::events::DnsResponseEventData>(&event.data);
    ASSERT_NE(dns_response, nullptr);
    EXPECT_FALSE(dns_response->parse_success);
}
