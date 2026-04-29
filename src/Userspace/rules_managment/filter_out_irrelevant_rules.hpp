#pragma once

#include "configuration/rule.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <semver/semver.hpp>
#include <algorithm>

namespace owlsm
{

class FilterOutIrrelevantRules
{
public:
    FilterOutIrrelevantRules() = default;
    virtual ~FilterOutIrrelevantRules() = default;

    static void filterOutIrrelevantRules(std::vector<config::Rule>& rules)
    {
        filterOutRulesByVersion(rules);
        filterOutRulesForDisabledProbes(rules);
    }

private:
    static void filterOutRulesByVersion(std::vector<config::Rule>& rules)
    {
        semver::version<int, int, int> zero_version;
        semver::version<int, int, int> current_version;
        semver::parse(OWLSM_VERSION_STR, current_version);
        auto it = std::remove_if(rules.begin(), rules.end(), [&current_version, &zero_version](const config::Rule& rule)
        {
            if (rule.min_version != zero_version && current_version < rule.min_version)
            {
                LOG_INFO("Removing rule " << rule.id << ". Version below minimum supported version.");
                return true;
            }
            if (rule.max_version != zero_version && current_version > rule.max_version)
            {
                LOG_INFO("Removing rule " << rule.id << ". Version above maximum supported version.");
                return true;
            }
            return false;
        });
        rules.erase(it, rules.end());
    }

    static void filterOutRulesForDisabledProbes(std::vector<config::Rule>& rules)
    {
        if (!globals::g_config.features.file_monitoring.enabled)
        {
            removeRulesByType(rules, CHMOD);
            removeRulesByType(rules, CHOWN);
            removeRulesByType(rules, FILE_CREATE);
            removeRulesByType(rules, MKDIR);
            removeRulesByType(rules, RMDIR);
            removeRulesByType(rules, UNLINK);
            removeRulesByType(rules, RENAME);
            removeRulesByType(rules, WRITE);
            removeRulesByType(rules, READ);
        }
        if (!globals::g_config.features.file_monitoring.events.chmod)
        {
            removeRulesByType(rules, CHMOD);
        }
        if (!globals::g_config.features.file_monitoring.events.chown)
        {
            removeRulesByType(rules, CHOWN);
        }
        if (!globals::g_config.features.file_monitoring.events.file_create)
        {
            removeRulesByType(rules, FILE_CREATE);
        }
        if (!globals::g_config.features.file_monitoring.events.mkdir)
        {
            removeRulesByType(rules, MKDIR);
        }
        if (!globals::g_config.features.file_monitoring.events.rmdir)
        {
            removeRulesByType(rules, RMDIR);
        }
        if (!globals::g_config.features.file_monitoring.events.unlink)
        {
            removeRulesByType(rules, UNLINK);
        }
        if (!globals::g_config.features.file_monitoring.events.rename)
        {
            removeRulesByType(rules, RENAME);
        }
        if (!globals::g_config.features.file_monitoring.events.write)
        {
            removeRulesByType(rules, WRITE);
        }
        if (!globals::g_config.features.file_monitoring.events.read)
        {
            removeRulesByType(rules, READ);
        }

        if (!globals::g_config.features.network_monitoring.enabled)
        {
            removeRulesByType(rules, NETWORK);
            removeRulesByType(rules, DNS_QUERY);
            removeRulesByType(rules, DNS_RESPONSE);
        }
        else if (!globals::g_config.features.network_monitoring.events.dns)
        {
            removeRulesByType(rules, DNS_QUERY);
            removeRulesByType(rules, DNS_RESPONSE);
        }
    }

    static void removeRulesByType(std::vector<config::Rule>& rules, enum event_type type)
    {
        auto it = std::remove_if(rules.begin(), rules.end(), [&type](const config::Rule& rule)
        {
            if (rule.type == type)
            {
                LOG_INFO("Removing rule " << rule.id << ". Probe disabled in config");
                return true;
            }
            return false;
        });
        rules.erase(it, rules.end());
    }
};

}
