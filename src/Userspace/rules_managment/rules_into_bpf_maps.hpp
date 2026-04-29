#pragma once

#include "configuration/rule.hpp"
#include "bpf_header_includes.h"
#include "rules_structs.h"

#include <unordered_map>
#include <unistd.h>
#include <vector>
#include <memory>
#include <cstring>

class RulesIntoBpfMapsTest;
class MapPopulatorTest;

namespace owlsm 
{

class RulesIntoBpfMaps
{
public:
    void createRuleMapsFromOrganizedRules(
        const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules,
        const std::unordered_map<int, config::RuleString>& id_to_string,
        const std::unordered_map<int, config::Predicate>& id_to_predicate,
        const std::unordered_map<int, config::RuleIP>& id_to_ip);
    
private:
    void populatePredicatesMap(const std::unordered_map<int, config::Predicate>& id_to_predicate);
    void populateRulesStringsMap(const std::unordered_map<int, config::RuleString>& id_to_string);
    void populateIdxToDFAMap(const std::unordered_map<int, config::RuleString>& id_to_string);
    void populateIdxToAcceptingStatesMap();
    void populateRulesIpsMap(const std::unordered_map<int, config::RuleIP>& id_to_ip);
    void populateEventRuleMaps(const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules);
    int createPinMap(enum bpf_map_type type,const std::string& map_name, size_t value_size, size_t max_entries, int flags);
    void freezeMap(int fd);
    
    std::unordered_map<int, unsigned long long> m_regex_accepting_states;
    
    std::string eventTypeToString(event_type type)
    {
        switch (type)
        {
            case EXEC:        return "exec_rules";
            case FORK:        return "fork_rules";
            case EXIT:        return "exit_rules";
            case FILE_CREATE: return "file_create_rules";
            case CHOWN:       return "chown_rules";
            case CHMOD:       return "chmod_rules";
            case WRITE:       return "write_rules";
            case READ:        return "read_rules";
            case UNLINK:      return "unlink_rules";
            case RENAME:      return "rename_rules";
            case NETWORK:     return "network_rules";
            case DNS_QUERY:   return "dns_query_rules";
            case DNS_RESPONSE:return "dns_response_rules";
            case MKDIR:       return "mkdir_rules";
            case RMDIR:       return "rmdir_rules";
            default:          return "unknown_rules";
        }
    }
    
    friend class ::RulesIntoBpfMapsTest;
    friend class ::MapPopulatorTest;
};
}
