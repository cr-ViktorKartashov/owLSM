#include <gtest/gtest.h>
#include "rules_managment/rules_organizer.hpp"

class RulesOrganizerTest : public ::testing::Test {};

TEST_F(RulesOrganizerTest, organize_single_rule_single_event)
{
    std::vector<owlsm::config::Rule> rules;
    owlsm::config::Rule rule;
    rule.id = 1;
    rule.action = BLOCK_EVENT;
    rule.applied_events = {READ};
    rules.push_back(rule);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized.size(), 1);
    EXPECT_EQ(organized[READ].size(), 1);
    EXPECT_EQ(organized[READ][0]->id, 1);
}

TEST_F(RulesOrganizerTest, organize_single_rule_multiple_events)
{
    std::vector<owlsm::config::Rule> rules;
    owlsm::config::Rule rule;
    rule.id = 1;
    rule.action = BLOCK_EVENT;
    rule.applied_events = {READ, WRITE, CHMOD};
    rules.push_back(rule);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized.size(), 3);
    EXPECT_EQ(organized[READ].size(), 1);
    EXPECT_EQ(organized[WRITE].size(), 1);
    EXPECT_EQ(organized[CHMOD].size(), 1);
    
    // Verify it's the same rule (shared pointer)
    EXPECT_EQ(organized[READ][0]->id, 1);
    EXPECT_EQ(organized[WRITE][0]->id, 1);
    EXPECT_EQ(organized[CHMOD][0]->id, 1);
    EXPECT_EQ(organized[READ][0].get(), organized[WRITE][0].get());
}

TEST_F(RulesOrganizerTest, organize_multiple_rules_sorted_by_id)
{
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule3;
    rule3.id = 3;
    rule3.action = BLOCK_EVENT;
    rule3.applied_events = {READ};
    rules.push_back(rule3);
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {READ};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized[READ].size(), 3);
    EXPECT_EQ(organized[READ][0]->id, 1);
    EXPECT_EQ(organized[READ][1]->id, 2);
    EXPECT_EQ(organized[READ][2]->id, 3);
}

TEST_F(RulesOrganizerTest, organize_multiple_rules_different_events)
{
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {WRITE};
    rules.push_back(rule2);
    
    owlsm::config::Rule rule3;
    rule3.id = 3;
    rule3.action = BLOCK_EVENT;
    rule3.applied_events = {READ, WRITE};
    rules.push_back(rule3);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized.size(), 2);
    EXPECT_EQ(organized[READ].size(), 2);
    EXPECT_EQ(organized[WRITE].size(), 2);
    
    // Check READ rules are sorted by ID
    EXPECT_EQ(organized[READ][0]->id, 1);
    EXPECT_EQ(organized[READ][1]->id, 3);
    
    // Check WRITE rules are sorted by ID
    EXPECT_EQ(organized[WRITE][0]->id, 2);
    EXPECT_EQ(organized[WRITE][1]->id, 3);
}

TEST_F(RulesOrganizerTest, filter_below_minimum_version)
{
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    semver::parse("1000.0.1", rule1.min_version);
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {READ};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized[READ].size(), 1);
    EXPECT_EQ(organized[READ][0]->id, 2);
}

TEST_F(RulesOrganizerTest, filter_above_maximum_version)
{
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    semver::parse("0.0.1", rule1.max_version);
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {READ};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized[READ].size(), 1);
    EXPECT_EQ(organized[READ][0]->id, 2);
}

TEST_F(RulesOrganizerTest, filter_both_versions_valid)
{
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    semver::parse("0.0.1", rule1.min_version);
    semver::parse("1000.0.1", rule1.max_version);
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {READ};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized[READ].size(), 2);
    EXPECT_EQ(organized[READ][0]->id, 1);
    EXPECT_EQ(organized[READ][1]->id, 2);
}

TEST_F(RulesOrganizerTest, filter_read_disabled_removes_read_rules)
{
    owlsm::globals::g_config.features.file_monitoring.enabled = true;
    owlsm::globals::g_config.features.file_monitoring.events.read = false;
    owlsm::globals::g_config.features.file_monitoring.events.write = true;
    
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {WRITE};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized.find(READ), organized.end());
    EXPECT_EQ(organized[WRITE].size(), 1);
    EXPECT_EQ(organized[WRITE][0]->id, 2);
}

TEST_F(RulesOrganizerTest, filter_file_monitoring_disabled_removes_all)
{
    owlsm::globals::g_config.features.file_monitoring.enabled = false;
    owlsm::globals::g_config.features.file_monitoring.events.read = true;
    owlsm::globals::g_config.features.file_monitoring.events.write = true;
    
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ};
    rules.push_back(rule1);
    
    owlsm::config::Rule rule2;
    rule2.id = 2;
    rule2.action = BLOCK_EVENT;
    rule2.applied_events = {WRITE};
    rules.push_back(rule2);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    EXPECT_EQ(organized.size(), 0);
}

TEST_F(RulesOrganizerTest, filter_multi_event_rule_partial_disabled)
{
    owlsm::globals::g_config.features.file_monitoring.enabled = true;
    owlsm::globals::g_config.features.file_monitoring.events.read = false;
    owlsm::globals::g_config.features.file_monitoring.events.write = true;
    
    std::vector<owlsm::config::Rule> rules;
    
    owlsm::config::Rule rule1;
    rule1.id = 1;
    rule1.action = BLOCK_EVENT;
    rule1.applied_events = {READ, WRITE};
    rules.push_back(rule1);
    
    auto organized = owlsm::RulesOrganizer::organizeRules(rules);
    
    // READ should be removed, but WRITE should remain
    EXPECT_EQ(organized.find(READ), organized.end());
    EXPECT_EQ(organized[WRITE].size(), 1);
    EXPECT_EQ(organized[WRITE][0]->id, 1);
}

TEST_F(RulesOrganizerTest, filter_network_monitoring_disabled_removes_network_and_dns_rules)
{
    owlsm::globals::g_config.features.network_monitoring.enabled = false;
    owlsm::globals::g_config.features.network_monitoring.events.dns = true;

    std::vector<owlsm::config::Rule> rules;

    owlsm::config::Rule network_rule;
    network_rule.id = 10;
    network_rule.action = BLOCK_EVENT;
    network_rule.applied_events = {NETWORK};
    rules.push_back(network_rule);

    owlsm::config::Rule dns_query_rule;
    dns_query_rule.id = 11;
    dns_query_rule.action = BLOCK_EVENT;
    dns_query_rule.applied_events = {DNS_QUERY};
    rules.push_back(dns_query_rule);

    owlsm::config::Rule dns_response_rule;
    dns_response_rule.id = 12;
    dns_response_rule.action = BLOCK_EVENT;
    dns_response_rule.applied_events = {DNS_RESPONSE};
    rules.push_back(dns_response_rule);

    auto organized = owlsm::RulesOrganizer::organizeRules(rules);

    EXPECT_EQ(organized.find(NETWORK), organized.end());
    EXPECT_EQ(organized.find(DNS_QUERY), organized.end());
    EXPECT_EQ(organized.find(DNS_RESPONSE), organized.end());
}

TEST_F(RulesOrganizerTest, filter_dns_disabled_removes_only_dns_rules)
{
    owlsm::globals::g_config.features.network_monitoring.enabled = true;
    owlsm::globals::g_config.features.network_monitoring.events.dns = false;

    std::vector<owlsm::config::Rule> rules;

    owlsm::config::Rule network_rule;
    network_rule.id = 20;
    network_rule.action = BLOCK_EVENT;
    network_rule.applied_events = {NETWORK};
    rules.push_back(network_rule);

    owlsm::config::Rule dns_query_rule;
    dns_query_rule.id = 21;
    dns_query_rule.action = BLOCK_EVENT;
    dns_query_rule.applied_events = {DNS_QUERY};
    rules.push_back(dns_query_rule);

    owlsm::config::Rule dns_response_rule;
    dns_response_rule.id = 22;
    dns_response_rule.action = BLOCK_EVENT;
    dns_response_rule.applied_events = {DNS_RESPONSE};
    rules.push_back(dns_response_rule);

    auto organized = owlsm::RulesOrganizer::organizeRules(rules);

    ASSERT_NE(organized.find(NETWORK), organized.end());
    EXPECT_EQ(organized[NETWORK].size(), 1);
    EXPECT_EQ(organized[NETWORK][0]->id, 20);
    EXPECT_EQ(organized.find(DNS_QUERY), organized.end());
    EXPECT_EQ(organized.find(DNS_RESPONSE), organized.end());
}

