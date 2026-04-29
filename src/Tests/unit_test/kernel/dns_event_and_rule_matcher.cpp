#include "test_base.hpp"
#include "map_populator.hpp"
#include "rules_managment/rule_converter.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <stdexcept>
#include <netinet/in.h>
#include <vector>

namespace
{
struct EventAndRuleMatcherTest
{
    struct event_t event;
    struct rule_t rule;
    int actual_result;
};

template<typename T>
bool execute_matcher_test(T* skel, const event_t& event, const owlsm::config::Rule& rule)
{
    const int program_fd = bpf_program__fd(skel->progs.test_event_and_rule_matcher_test_program);
    const int map_fd = bpf_map__fd(skel->maps.event_and_rule_matcher_test_map);

    EventAndRuleMatcherTest test = {};
    test.event = event;
    test.rule = owlsm::RuleStructConverter::convertRule(rule);
    test.actual_result = -1;

    unsigned int test_key = 0;
    if (bpf_map_update_elem(map_fd, &test_key, &test, BPF_ANY) < 0)
    {
        throw std::runtime_error("Failed to update test map");
    }

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    if (bpf_map_lookup_elem(map_fd, &test_key, &test) < 0)
    {
        throw std::runtime_error("Failed to lookup test result");
    }

    return test.actual_result == 1;
}

std::shared_ptr<owlsm::config::Rule> get_rule_by_id(
    const std::vector<std::shared_ptr<owlsm::config::Rule>>& rules,
    const unsigned int id)
{
    auto it = std::find_if(rules.begin(), rules.end(),
        [id](const std::shared_ptr<owlsm::config::Rule>& rule)
        {
            return rule->id == id;
        });

    if (it == rules.end())
    {
        throw std::runtime_error("Rule not found. id: " + std::to_string(id));
    }

    return *it;
}

event_t create_dns_query_event(const unsigned int pid)
{
    event_t event = {};
    event.type = DNS_QUERY;
    event.action = ALLOW_EVENT;
    event.time = 1000;
    event.process.pid = pid;
    event.data.dns_query.network.ip_type = AF_INET;
    event.data.dns_query.network.direction = OUTGOING;
    event.data.dns_query.network.source_port = 53000;
    event.data.dns_query.network.destination_port = 53;
    return event;
}

event_t create_dns_response_event(const unsigned int pid)
{
    event_t event = {};
    event.type = DNS_RESPONSE;
    event.action = ALLOW_EVENT;
    event.time = 1001;
    event.process.pid = pid;
    event.data.dns_response.network.ip_type = AF_INET;
    event.data.dns_response.network.direction = INCOMING;
    event.data.dns_response.network.source_port = 53;
    event.data.dns_response.network.destination_port = 53000;
    return event;
}

constexpr const char* DNS_QUERY_RULE_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 100,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 9001,
      "description": "DNS query match on process pid",
      "action": "BLOCK_EVENT",
      "applied_events": ["DNS_QUERY"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* DNS_RESPONSE_RULE_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 100,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 9002,
      "description": "DNS response match on process pid",
      "action": "BLOCK_EVENT",
      "applied_events": ["DNS_RESPONSE"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";
}

TEST_F(BpfTestBase, DNS_QUERY_ProcessPidRule_Match)
{
    const auto event = create_dns_query_event(101);
    const auto organized_rules = MapPopulatorTest::populate_maps_from_json(DNS_QUERY_RULE_JSON);
    const auto rule = get_rule_by_id(organized_rules.at(DNS_QUERY), 9001);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, DNS_QUERY_ProcessPidRule_NoMatch)
{
    const auto event = create_dns_query_event(99);
    const auto organized_rules = MapPopulatorTest::populate_maps_from_json(DNS_QUERY_RULE_JSON);
    const auto rule = get_rule_by_id(organized_rules.at(DNS_QUERY), 9001);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, DNS_RESPONSE_ProcessPidRule_Match)
{
    const auto event = create_dns_response_event(102);
    const auto organized_rules = MapPopulatorTest::populate_maps_from_json(DNS_RESPONSE_RULE_JSON);
    const auto rule = get_rule_by_id(organized_rules.at(DNS_RESPONSE), 9002);
    EXPECT_TRUE(execute_matcher_test(skel, event, *rule));
}

TEST_F(BpfTestBase, DNS_RESPONSE_ProcessPidRule_NoMatch)
{
    const auto event = create_dns_response_event(100);
    const auto organized_rules = MapPopulatorTest::populate_maps_from_json(DNS_RESPONSE_RULE_JSON);
    const auto rule = get_rule_by_id(organized_rules.at(DNS_RESPONSE), 9002);
    EXPECT_FALSE(execute_matcher_test(skel, event, *rule));
}
