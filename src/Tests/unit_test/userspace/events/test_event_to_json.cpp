#include <gtest/gtest.h>

#include "events/event_to_json.hpp"

#include <netinet/in.h>
#include <cstring>
#include <memory>
#include <vector>

class EventToJsonTest : public ::testing::Test
{
protected:
    owlsm::events::EventToJson<owlsm::events::Event> m_serializer;

    static std::shared_ptr<owlsm::events::Event> makeBaseEvent(event_type type)
    {
        auto event = std::make_shared<owlsm::events::Event>();
        event->id = 1;
        event->type = type;
        event->action = ALLOW_EVENT;
        event->time = 123;
        event->process.pid = 10;
        event->parent_process.pid = 1;
        return event;
    }
};

TEST_F(EventToJsonTest, dns_query_event_contains_dns_query_section)
{
    auto event = makeBaseEvent(DNS_QUERY);
    owlsm::events::DnsQueryEventData dns_data;
    dns_data.network.direction = OUTGOING;
    dns_data.network.protocol = 17;
    dns_data.network.ip_type = AF_INET;
    dns_data.network.source_port = 44444;
    dns_data.network.destination_port = 53;
    owlsm::events::Ipv4Addresses ipv4;
    ipv4.source_ip = htonl(0x0A000001);
    ipv4.destination_ip = htonl(0x08080808);
    dns_data.network.addresses = ipv4;
    dns_data.txid = 500;
    dns_data.question = "example.com";
    dns_data.question_type = 1;
    event->data = dns_data;

    m_serializer.buildOutputBuffer({event});
    const std::string output(static_cast<const char*>(m_serializer.data()), m_serializer.size());
    const auto json = nlohmann::json::parse(output);

    EXPECT_EQ(json.at("type"), "DNS_QUERY");
    EXPECT_EQ(json.at("data").at("dns_query").at("txid"), 500);
    EXPECT_EQ(json.at("data").at("dns_query").at("question"), "example.com");
    EXPECT_EQ(json.at("data").at("network").at("destination_port"), 53);
}

TEST_F(EventToJsonTest, dns_response_event_contains_answers)
{
    auto event = makeBaseEvent(DNS_RESPONSE);
    owlsm::events::DnsResponseEventData dns_data;
    dns_data.network.direction = INCOMING;
    dns_data.network.protocol = 17;
    dns_data.network.ip_type = AF_INET;
    dns_data.network.source_port = 53;
    dns_data.network.destination_port = 44444;
    owlsm::events::Ipv4Addresses ipv4;
    ipv4.source_ip = htonl(0x08080808);
    ipv4.destination_ip = htonl(0x0A000001);
    dns_data.network.addresses = ipv4;
    dns_data.txid = 777;
    dns_data.question = "example.com";
    dns_data.question_type = 1;
    dns_data.answer_count = 1;
    dns_data.rcode = 0;
    owlsm::events::DnsAnswer answer;
    answer.type = 1;
    answer.data_length = 4;
    answer.ttl = 30;
    answer.data = "93.184.216.34";
    dns_data.answers.push_back(answer);
    event->data = dns_data;

    m_serializer.buildOutputBuffer({event});
    const std::string output(static_cast<const char*>(m_serializer.data()), m_serializer.size());
    const auto json = nlohmann::json::parse(output);

    EXPECT_EQ(json.at("type"), "DNS_RESPONSE");
    EXPECT_EQ(json.at("data").at("dns_response").at("answer_count"), 1);
    EXPECT_EQ(json.at("data").at("dns_response").at("answers").at(0).at("data"), "93.184.216.34");
}

TEST_F(EventToJsonTest, dns_response_parses_cname_answer_to_text)
{
    event_t raw_event = {};
    raw_event.id = 2;
    raw_event.type = DNS_RESPONSE;
    raw_event.action = ALLOW_EVENT;
    raw_event.time = 321;
    raw_event.process.pid = 20;
    raw_event.parent_process.pid = 2;

    auto &dns = raw_event.data.dns_response;
    dns.network.direction = INCOMING;
    dns.network.protocol = 17;
    dns.network.ip_type = AF_INET;
    dns.network.source_port = 53;
    dns.network.destination_port = 44444;
    dns.network.addresses.ipv4.source_ip = htonl(0x08080808);
    dns.network.addresses.ipv4.destination_ip = htonl(0x0A000001);

    const std::vector<unsigned char> packet = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'a', 'p', 'i', '2', 'g', 'e', 'o', 0x06, 'c', 'u', 'r', 's', 'o', 'r', 0x02, 's', 'h', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x0D, 0x00, 0x0A,
        0x07, 'a', 'p', 'i', '2', 'g', 'e', 'o', 0xC0, 0x14
    };

    ASSERT_LE(packet.size(), DNS_PACKET_CAPTURE_LENGTH);
    dns.raw_packet_len = static_cast<unsigned short>(packet.size());
    std::memcpy(dns.raw_packet, packet.data(), packet.size());

    const auto event = std::make_shared<owlsm::events::Event>(raw_event);
    m_serializer.buildOutputBuffer({event});
    const std::string output(static_cast<const char*>(m_serializer.data()), m_serializer.size());
    const auto json = nlohmann::json::parse(output);

    EXPECT_EQ(json.at("type"), "DNS_RESPONSE");
    EXPECT_EQ(json.at("data").at("dns_response").at("answer_count"), 1);
    EXPECT_EQ(json.at("data").at("dns_response").at("answers").at(0).at("type"), 5);
    EXPECT_EQ(json.at("data").at("dns_response").at("answers").at(0).at("data"), "api2geo.cursor.sh");
}
