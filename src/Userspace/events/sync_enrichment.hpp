#pragma once

#include "events/event.hpp"
#include "rules_managment/rules_metadata_tracker.hpp"
#include "logger.hpp"
#include "globals/global_objects.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <unordered_map>

namespace owlsm::events
{

class SyncEventEnrichment
{
public:
    explicit SyncEventEnrichment()
        : m_rules_metadata(owlsm::globals::g_config.rules_config.rules) {}

    void enrich(std::shared_ptr<Event>& event)
    {
        if (event->is_enriched)
        {
            LOG_WARN("Event already enriched. event id: " << event->id);
            return;
        }

        try
        {
            if (event->type == DNS_QUERY)
            {
                handleDnsQueryEvent(event);
            }
            else if (event->type == DNS_RESPONSE)
            {
                handleDnsResponseEvent(event);
            }

            if (event->matched_rule_id > 0)
            {
                event->matched_rule_metadata = m_rules_metadata.get_metadata(event->matched_rule_id);
                LOG_DEBUG("Enriched event with rule metadata: " << event->matched_rule_metadata.description);
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to enrich event with rule metadata: " << e.what());
        }

        event->is_enriched = true;
    }

private:
    struct DnsFlowKey
    {
        unsigned char ip_type = 0;
        unsigned char protocol = 0;
        unsigned short txid = 0;
        unsigned short client_port = 0;
        std::array<unsigned int, 4> client_ip = {0, 0, 0, 0};
        std::array<unsigned int, 4> dns_server_ip = {0, 0, 0, 0};

        bool operator==(const DnsFlowKey& other) const
        {
            return ip_type == other.ip_type &&
                protocol == other.protocol &&
                txid == other.txid &&
                client_port == other.client_port &&
                client_ip == other.client_ip &&
                dns_server_ip == other.dns_server_ip;
        }
    };

    struct DnsFlowKeyHasher
    {
        size_t operator()(const DnsFlowKey& key) const
        {
            size_t h = 0;
            auto hash_mix = [&h](const unsigned long long value)
            {
                h ^= std::hash<unsigned long long>{}(value) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            };

            hash_mix(key.ip_type);
            hash_mix(key.protocol);
            hash_mix(key.txid);
            hash_mix(key.client_port);
            for (const auto part : key.client_ip) { hash_mix(part); }
            for (const auto part : key.dns_server_ip) { hash_mix(part); }
            return h;
        }
    };

    static constexpr size_t DNS_QUERY_CACHE_MAX_SIZE = 4096;
    static constexpr std::chrono::seconds DNS_QUERY_CACHE_TTL{30};

    bool networkToDnsFlowKey(const NetworkEventData& network,
        const unsigned short txid,
        const bool from_query,
        DnsFlowKey& out_key) const
    {
        out_key.ip_type = network.ip_type;
        out_key.protocol = network.protocol;
        out_key.txid = txid;

        if (network.ip_type == AF_INET)
        {
            const auto *ipv4 = std::get_if<Ipv4Addresses>(&network.addresses);
            if (!ipv4)
            {
                return false;
            }
            if (from_query)
            {
                out_key.client_port = network.source_port;
                out_key.client_ip[0] = ipv4->source_ip;
                out_key.dns_server_ip[0] = ipv4->destination_ip;
            }
            else
            {
                out_key.client_port = network.destination_port;
                out_key.client_ip[0] = ipv4->destination_ip;
                out_key.dns_server_ip[0] = ipv4->source_ip;
            }
            return true;
        }

        const auto *ipv6 = std::get_if<Ipv6Addresses>(&network.addresses);
        if (!ipv6)
        {
            return false;
        }
        if (from_query)
        {
            out_key.client_port = network.source_port;
            std::copy(std::begin(ipv6->source_ip), std::end(ipv6->source_ip), out_key.client_ip.begin());
            std::copy(std::begin(ipv6->destination_ip), std::end(ipv6->destination_ip), out_key.dns_server_ip.begin());
        }
        else
        {
            out_key.client_port = network.destination_port;
            std::copy(std::begin(ipv6->destination_ip), std::end(ipv6->destination_ip), out_key.client_ip.begin());
            std::copy(std::begin(ipv6->source_ip), std::end(ipv6->source_ip), out_key.dns_server_ip.begin());
        }
        return true;
    }

    struct DnsQueryCacheEntry
    {
        std::chrono::steady_clock::time_point seen_at;
        Process process;
        Process parent_process;
    };

    void pruneDnsQueryCache(const std::chrono::steady_clock::time_point now)
    {
        while (!m_dns_query_lru.empty())
        {
            const auto it = m_dns_query_cache.find(m_dns_query_lru.front());
            if (it == m_dns_query_cache.end())
            {
                m_dns_query_lru.pop_front();
                continue;
            }
            if (now - it->second.seen_at > DNS_QUERY_CACHE_TTL)
            {
                m_dns_query_cache.erase(it);
                m_dns_query_lru.pop_front();
                continue;
            }
            break;
        }
    }

    void cacheDnsQuery(const DnsFlowKey& key, const Event& query_event)
    {
        const auto now = std::chrono::steady_clock::now();
        pruneDnsQueryCache(now);
        eraseDnsQueryKeyFromLru(key);

        DnsQueryCacheEntry entry = {};
        entry.seen_at = now;
        entry.process = query_event.process;
        entry.parent_process = query_event.parent_process;
        m_dns_query_cache[key] = std::move(entry);
        m_dns_query_lru.push_back(key);

        while (m_dns_query_cache.size() > DNS_QUERY_CACHE_MAX_SIZE && !m_dns_query_lru.empty())
        {
            const auto oldest = m_dns_query_lru.front();
            m_dns_query_lru.pop_front();
            const auto it = m_dns_query_cache.find(oldest);
            if (it != m_dns_query_cache.end())
            {
                m_dns_query_cache.erase(it);
            }
        }
    }

    bool consumeCachedDnsQuery(const DnsFlowKey& key, DnsQueryCacheEntry& out_query_entry)
    {
        const auto now = std::chrono::steady_clock::now();
        pruneDnsQueryCache(now);

        const auto it = m_dns_query_cache.find(key);
        if (it == m_dns_query_cache.end())
        {
            return false;
        }
        out_query_entry = it->second;
        m_dns_query_cache.erase(it);
        eraseDnsQueryKeyFromLru(key);
        return true;
    }

    void eraseDnsQueryKeyFromLru(const DnsFlowKey& key)
    {
        const auto it = std::remove(m_dns_query_lru.begin(), m_dns_query_lru.end(), key);
        if (it != m_dns_query_lru.end())
        {
            m_dns_query_lru.erase(it, m_dns_query_lru.end());
        }
    }

    void handleDnsQueryEvent(std::shared_ptr<Event>& event)
    {
        const auto *dns = std::get_if<DnsQueryEventData>(&event->data);
        if (!dns || !dns->parse_success)
        {
            const auto parse_error = dns ? dns->parse_error_reason : "variant mismatch";
            LOG_ERROR("Dropping DNS_QUERY event id=" << event->id
                << " parse_failed reason='" << parse_error << "'");
            event->action = EXCLUDE_EVENT;
            return;
        }

        DnsFlowKey key = {};
        if (!networkToDnsFlowKey(dns->network, dns->txid, true, key))
        {
            LOG_ERROR("Dropping DNS_QUERY event id=" << event->id
                << " invalid network tuple for txid=" << dns->txid);
            event->action = EXCLUDE_EVENT;
            return;
        }
        cacheDnsQuery(key, *event);
    }

    void handleDnsResponseEvent(std::shared_ptr<Event>& event)
    {
        const auto *dns = std::get_if<DnsResponseEventData>(&event->data);
        if (!dns || !dns->parse_success)
        {
            const auto parse_error = dns ? dns->parse_error_reason : "variant mismatch";
            LOG_ERROR("Dropping DNS_RESPONSE event id=" << event->id
                << " parse_failed reason='" << parse_error << "'");
            event->action = EXCLUDE_EVENT;
            return;
        }

        if (dns->answer_count > dns->answers.size())
        {
            LOG_ERROR("DNS_RESPONSE event id=" << event->id
                << " answers truncated parsed=" << dns->answers.size()
                << " reported=" << dns->answer_count);
        }

        DnsFlowKey key = {};
        if (!networkToDnsFlowKey(dns->network, dns->txid, false, key))
        {
            LOG_ERROR("Dropping DNS_RESPONSE event id=" << event->id
                << " invalid network tuple for txid=" << dns->txid);
            event->action = EXCLUDE_EVENT;
            return;
        }

        DnsQueryCacheEntry query_entry = {};
        if (!consumeCachedDnsQuery(key, query_entry))
        {
            LOG_ERROR("Dropping DNS_RESPONSE event id=" << event->id
                << " no cached DNS_QUERY match for txid=" << dns->txid);
            event->action = EXCLUDE_EVENT;
            return;
        }

        event->process = std::move(query_entry.process);
        event->parent_process = std::move(query_entry.parent_process);
    }

    RulesMetadataTracker m_rules_metadata;
    std::unordered_map<DnsFlowKey, DnsQueryCacheEntry, DnsFlowKeyHasher> m_dns_query_cache;
    std::deque<DnsFlowKey> m_dns_query_lru;
};

class SyncErrorEnrichment
{
public:
    SyncErrorEnrichment() = default;

    void enrich(std::shared_ptr<Error>& error)
    {
        if (error->is_enriched)
        {
            LOG_WARN("Error already enriched");
            return;
        }

        error->is_enriched = true;
    }
};

}

