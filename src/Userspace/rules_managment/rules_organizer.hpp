#pragma once

#include "configuration/rule.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <magic_enum/magic_enum.hpp>
#include <semver/semver.hpp>
#include <algorithm>
#include <unordered_map>
#include <memory>

namespace owlsm
{
using OrganizedRules = std::unordered_map<event_type, std::vector<std::shared_ptr<config::Rule>>>;
class RulesOrganizer
{
public:
    RulesOrganizer() = default;
    virtual ~RulesOrganizer() = default;
    
    static void addEndRules(std::vector<config::Rule>& rules)
    {
        config::Rule end_rule = {};
        end_rule.id = __INT_MAX__;
        end_rule.action = ALLOW_EVENT;
        end_rule.applied_events = {EXEC, FILE_CREATE, CHOWN, CHMOD, WRITE, READ, UNLINK, RENAME, NETWORK, DNS_QUERY, DNS_RESPONSE, MKDIR, RMDIR};
        end_rule.is_end_of_rules = true;
        rules.push_back(end_rule);
    }

    static OrganizedRules organizeRules(std::vector<config::Rule>& rules)
    {
        auto organized = organizeByEventType(rules);
        filterOutIrrelevantRules(organized);
        return organized;
    }

private:
    static OrganizedRules organizeByEventType(std::vector<config::Rule>& rules)
    {
        OrganizedRules organized;
        
        std::vector<std::shared_ptr<config::Rule>> rule_ptrs;
        rule_ptrs.reserve(rules.size());
        for (auto& rule : rules)
        {
            rule_ptrs.push_back(std::make_shared<config::Rule>(rule));
        }
        
        for (const auto& rule_ptr : rule_ptrs)
        {
            for (const auto& event : rule_ptr->applied_events)
            {
                organized[event].push_back(rule_ptr);
            }
        }
        
        for (auto& [event, rules_vec] : organized)
        {
            std::sort(rules_vec.begin(), rules_vec.end(), 
                [](const std::shared_ptr<config::Rule>& a, const std::shared_ptr<config::Rule>& b)
                {
                    return a->id < b->id;
                });
        }
        
        return organized;
    }

    static void filterOutIrrelevantRules(OrganizedRules& organized)
    {
        filterOutRulesForDisabledProbes(organized);
        filterOutRulesByVersion(organized);
    }

    static void filterOutRulesByVersion(OrganizedRules& organized)
    {
        semver::version<int, int, int> zero_version;
        semver::version<int, int, int> current_version;
        semver::parse(OWLSM_VERSION_STR, current_version);
        
        for (auto& [event, rules_vec] : organized)
        {
            auto it = std::remove_if(rules_vec.begin(), rules_vec.end(), 
                [&current_version, &zero_version](const std::shared_ptr<config::Rule>& rule)
                {
                    if (rule->min_version != zero_version && current_version < rule->min_version)
                    {
                        LOG_INFO("Removing rule " << rule->id << 
                                " from event " << magic_enum::enum_name(rule->applied_events[0]) << ". Version below minimum supported version.");
                        return true;
                    }
                    if (rule->max_version != zero_version && current_version > rule->max_version)
                    {
                        LOG_INFO("Removing rule " << rule->id <<
                                " from event " << magic_enum::enum_name(rule->applied_events[0]) <<
                                ". Version above maximum supported version.");
                        return true;
                    }
                    return false;
                });
            rules_vec.erase(it, rules_vec.end());
        }
    }

    static void filterOutRulesForDisabledProbes(OrganizedRules& organized)
    {
        if (!globals::g_config.features.file_monitoring.enabled)
        {
            removeEventType(organized, CHMOD);
            removeEventType(organized, CHOWN);
            removeEventType(organized, FILE_CREATE);
            removeEventType(organized, MKDIR);
            removeEventType(organized, RMDIR);
            removeEventType(organized, UNLINK);
            removeEventType(organized, RENAME);
            removeEventType(organized, WRITE);
            removeEventType(organized, READ);
        }
        else
        {
            if (!globals::g_config.features.file_monitoring.events.chmod)
            {
                removeEventType(organized, CHMOD);
            }
            if (!globals::g_config.features.file_monitoring.events.chown)
            {
                removeEventType(organized, CHOWN);
            }
            if (!globals::g_config.features.file_monitoring.events.file_create)
            {
                removeEventType(organized, FILE_CREATE);
            }
            if (!globals::g_config.features.file_monitoring.events.mkdir)
            {
                removeEventType(organized, MKDIR);
            }
            if (!globals::g_config.features.file_monitoring.events.rmdir)
            {
                removeEventType(organized, RMDIR);
            }
            if (!globals::g_config.features.file_monitoring.events.unlink)
            {
                removeEventType(organized, UNLINK);
            }
            if (!globals::g_config.features.file_monitoring.events.rename)
            {
                removeEventType(organized, RENAME);
            }
            if (!globals::g_config.features.file_monitoring.events.write)
            {
                removeEventType(organized, WRITE);
            }
            if (!globals::g_config.features.file_monitoring.events.read)
            {
                removeEventType(organized, READ);
            }
        }
        
        if (!globals::g_config.features.network_monitoring.enabled)
        {
            removeEventType(organized, NETWORK);
            removeEventType(organized, DNS_QUERY);
            removeEventType(organized, DNS_RESPONSE);
        }
        else if (!globals::g_config.features.network_monitoring.events.dns)
        {
            removeEventType(organized, DNS_QUERY);
            removeEventType(organized, DNS_RESPONSE);
        }
    }

    static void removeEventType(OrganizedRules& organized, event_type type)
    {
        auto it = organized.find(type);
        if (it != organized.end())
        {
            LOG_INFO("Removing all rules for event type " << magic_enum::enum_name(type) << ". Probe disabled in config");
            organized.erase(it);
        }
    }
};

}

