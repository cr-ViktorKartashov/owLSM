#pragma once

#include "events_structs.h"
#include "configuration/rule.hpp"

#include <variant>
#include <algorithm>
#include <cstring>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <arpa/inet.h>

namespace owlsm::events
{

template <typename LenType, size_t BufferSize>
inline size_t sanitizeStringLength(const char (&buffer)[BufferSize], const LenType reported_len)
{
    static_assert(BufferSize > 0, "Buffer must not be empty");

    size_t bounded_len = 0;
    if constexpr (std::is_signed_v<LenType>)
    {
        if (reported_len <= 0)
        {
            return 0;
        }
        bounded_len = static_cast<size_t>(reported_len);
    }
    else
    {
        bounded_len = static_cast<size_t>(reported_len);
    }

    if (bounded_len >= BufferSize)
    {
        bounded_len = BufferSize - 1;
    }

    return strnlen(buffer, bounded_len);
}

inline bool readDnsU16Be(const unsigned char *packet, const size_t packet_len, const size_t offset, unsigned short &out)
{
    if (!packet || offset + 1 >= packet_len)
    {
        return false;
    }

    out = (static_cast<unsigned short>(packet[offset]) << 8) |
        static_cast<unsigned short>(packet[offset + 1]);
    return true;
}

inline bool readDnsU32Be(const unsigned char *packet, const size_t packet_len, const size_t offset, unsigned int &out)
{
    unsigned short hi = 0;
    unsigned short lo = 0;
    if (!readDnsU16Be(packet, packet_len, offset, hi) ||
        !readDnsU16Be(packet, packet_len, offset + 2, lo))
    {
        return false;
    }
    out = (static_cast<unsigned int>(hi) << 16) | static_cast<unsigned int>(lo);
    return true;
}

inline bool parseDnsNameAtOffset(const unsigned char *packet,
    size_t packet_len,
    size_t start_offset,
    std::string &name,
    size_t *consumed_bytes = nullptr)
{
    if (!packet || start_offset >= packet_len)
    {
        return false;
    }

    constexpr size_t MAX_POINTER_JUMPS = 16;
    size_t current_offset = start_offset;
    size_t local_consumed = 0;
    size_t pointer_jumps = 0;
    bool followed_pointer = false;

    name.clear();
    name.reserve(DNS_MAX_NAME_LENGTH);

    for (size_t label_idx = 0; label_idx < DNS_MAX_NAME_LENGTH; ++label_idx)
    {
        if (current_offset >= packet_len)
        {
            return false;
        }

        const auto label_len = static_cast<unsigned char>(packet[current_offset]);
        if ((label_len & 0xC0) == 0xC0)
        {
            if (current_offset + 1 >= packet_len)
            {
                return false;
            }

            const size_t pointer_offset = (static_cast<size_t>(label_len & 0x3F) << 8) |
                static_cast<size_t>(packet[current_offset + 1]);
            if (pointer_offset >= packet_len)
            {
                return false;
            }
            if (++pointer_jumps > MAX_POINTER_JUMPS)
            {
                return false;
            }

            if (!followed_pointer)
            {
                local_consumed += 2;
                followed_pointer = true;
            }
            current_offset = pointer_offset;
            continue;
        }

        if (label_len == 0)
        {
            if (!followed_pointer)
            {
                ++local_consumed;
            }
            if (consumed_bytes)
            {
                *consumed_bytes = local_consumed;
            }
            return true;
        }

        if ((label_len & 0xC0) != 0 || label_len > 63)
        {
            return false;
        }

        ++current_offset;
        if (current_offset + label_len > packet_len)
        {
            return false;
        }

        if (!name.empty())
        {
            name.push_back('.');
        }
        if (name.size() + label_len >= DNS_MAX_NAME_LENGTH)
        {
            return false;
        }
        name.append(reinterpret_cast<const char *>(packet + current_offset), label_len);

        if (!followed_pointer)
        {
            local_consumed += static_cast<size_t>(1 + label_len);
        }
        current_offset += label_len;
    }

    return false;
}

inline std::string dnsAnswerDataToString(unsigned short type, const unsigned char *data, size_t data_len)
{
    if (!data || data_len == 0)
    {
        return {};
    }

    if (type == 1 && data_len == 4)
    {
        char buf[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, data, buf, sizeof(buf)) != nullptr)
        {
            return std::string(buf);
        }
    }
    if (type == 28 && data_len == 16)
    {
        char buf[INET6_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET6, data, buf, sizeof(buf)) != nullptr)
        {
            return std::string(buf);
        }
    }

    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(data_len * 2);
    for (size_t i = 0; i < data_len; ++i)
    {
        const unsigned char byte = data[i];
        out.push_back(hex_chars[byte >> 4]);
        out.push_back(hex_chars[byte & 0x0F]);
    }
    return out;
}

inline const char *parseDnsQueryFromRawPacket(const dns_query_event_t& e, unsigned short& txid, unsigned short& question_type, std::string& question)
{
    if (e.raw_packet_len < 12 || e.raw_packet_len > DNS_PACKET_CAPTURE_LENGTH)
    {
        return "raw DNS packet length is invalid";
    }

    unsigned short qd_count = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, 4, qd_count) || qd_count == 0)
    {
        return "DNS qd_count is missing/zero";
    }

    unsigned short parsed_txid = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, 0, parsed_txid))
    {
        return "failed reading DNS txid";
    }

    size_t offset = 12;
    std::string parsed_question;
    size_t question_encoded_len = 0;
    if (!parseDnsNameAtOffset(e.raw_packet, e.raw_packet_len, offset, parsed_question, &question_encoded_len))
    {
        return "failed decoding DNS question name";
    }
    offset += question_encoded_len;

    if (offset + 4 > e.raw_packet_len)
    {
        return "DNS question is not terminated or lacks qtype/qclass";
    }

    unsigned short parsed_question_type = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, offset, parsed_question_type))
    {
        return "failed reading DNS question type";
    }

    txid = parsed_txid;
    question_type = parsed_question_type;
    question = std::move(parsed_question);
    return nullptr;
}

struct Path
{
    std::string value;

    Path() = default;
    explicit Path(const path_t& p)
        : value(p.value, sanitizeStringLength(p.value, p.length))
    {}
};

struct CommandLine
{
    std::string value;

    CommandLine() = default;
    explicit CommandLine(const command_line_t& c)
        : value(c.value, sanitizeStringLength(c.value, c.length))
    {}
};

struct Filename
{
    std::string value;

    Filename() = default;
    explicit Filename(const filename_t& f)
        : value(f.value, sanitizeStringLength(f.value, f.length))
    {}
};

struct Owner
{
    unsigned int uid = 0;
    unsigned int gid = 0;

    Owner() = default;
    explicit Owner(const owner_t& o) : uid(o.uid), gid(o.gid) {}
};

struct StdioFileDescriptorsAtProcessCreation
{
    file_type stdin_fd = UNKNOWN_FILE_TYPE;
    file_type stdout_fd = UNKNOWN_FILE_TYPE;
    file_type stderr_fd = UNKNOWN_FILE_TYPE;

    StdioFileDescriptorsAtProcessCreation() = default;
    explicit StdioFileDescriptorsAtProcessCreation(const stdio_file_descriptors_at_process_creation_t& s)
        : stdin_fd(s.stdin), stdout_fd(s.stdout), stderr_fd(s.stderr) {}
};

struct File
{
    unsigned long inode = 0;
    unsigned int dev = 0;
    unsigned long long unique_inode_id = 0;
    Path path;
    Owner owner;
    unsigned short mode = 0;
    file_type type = UNKNOWN_FILE_TYPE;
    unsigned char suid = 0;
    unsigned char sgid = 0;
    unsigned long long last_modified_seconds = 0;
    unsigned int nlink = 0;
    Filename filename;

    File() = default;
    explicit File(const file_t& f)
        : inode(f.inode), dev(f.dev), unique_inode_id(f.unique_inode_id), path(f.path), owner(f.owner)
        , mode(f.mode) , type(f.type) , suid(f.suid) , sgid(f.sgid) , last_modified_seconds(f.last_modified_seconds)
        , nlink(f.nlink) , filename(f.filename) {}
};

struct Process
{
    unsigned int pid = 0;
    unsigned int ppid = 0;
    unsigned long long unique_process_id = 0;
    unsigned long long unique_ppid_id = 0;
    unsigned int ruid = 0;
    unsigned int rgid = 0;
    unsigned int euid = 0;
    unsigned int egid = 0;
    unsigned int suid = 0;
    unsigned long long cgroup_id = 0;
    unsigned long long start_time = 0;
    unsigned int ptrace_flags = 0;
    File file;
    CommandLine cmd;
    StdioFileDescriptorsAtProcessCreation stdio_file_descriptors_at_process_creation;
    CommandLine shell_command;

    Process() = default;
    explicit Process(const process_t& p)
        : pid(p.pid) , ppid(p.ppid) , unique_process_id(p.unique_process_id) , unique_ppid_id(p.unique_ppid_id)
        , ruid(p.ruid) , rgid(p.rgid) , euid(p.euid) , egid(p.egid) , suid(p.suid) , cgroup_id(p.cgroup_id)
        , start_time(p.start_time) , ptrace_flags(p.ptrace_flags) , file(p.file) , cmd(p.cmd)
        , stdio_file_descriptors_at_process_creation(p.stdio_file_descriptors_at_process_creation) , shell_command(p.shell_command) {}
};

struct ChownEventData
{
    File file;
    unsigned int requested_owner_uid = 0;
    unsigned int requested_owner_gid = 0;

    ChownEventData() = default;
    explicit ChownEventData(const chown_event_t& e)
        : file(e.file) , requested_owner_uid(e.requested_owner_uid) , requested_owner_gid(e.requested_owner_gid) {}
};

struct ChmodEventData
{
    File file;
    unsigned short requested_mode = 0;

    ChmodEventData() = default;
    explicit ChmodEventData(const chmod_event_t& e)
        : file(e.file) , requested_mode(e.requested_mode) {}
};

struct ForkEventData
{
    ForkEventData() = default;
    explicit ForkEventData(const fork_event_t&) {}
};

struct ExecEventData
{
    Process new_process;

    ExecEventData() = default;
    explicit ExecEventData(const exec_event_t& e)
        : new_process(e.new_process) {}
};

struct ExitEventData
{
    unsigned int exit_code = 0;
    unsigned int signal = 0;

    ExitEventData() = default;
    explicit ExitEventData(const exit_event_t& e)
        : exit_code(e.exit_code) , signal(e.signal) {}
};

struct GenericFileEventData
{
    File file;

    GenericFileEventData() = default;
    explicit GenericFileEventData(const file_create_event_t& e) : file(e.file) {}
    explicit GenericFileEventData(const write_event_t& e) : file(e.file) {}
};

struct RenameEventData
{
    unsigned int flags = 0;
    File source_file;
    File destination_file;

    RenameEventData() = default;
    explicit RenameEventData(const rename_event_t& e)
        : flags(e.flags), source_file(e.source_file), destination_file(e.destination_file) {}
};

struct Ipv4Addresses
{
    unsigned int source_ip = 0;
    unsigned int destination_ip = 0;
};

struct Ipv6Addresses
{
    unsigned int source_ip[4] = {0};
    unsigned int destination_ip[4] = {0};
};

struct NetworkEventData
{
    connection_direction direction = INCOMING;
    unsigned char protocol = 0;
    unsigned char ip_type = 0;
    unsigned short source_port = 0;
    unsigned short destination_port = 0;
    std::variant<Ipv4Addresses, Ipv6Addresses> addresses;

    NetworkEventData() : addresses(Ipv4Addresses{}) {}
    explicit NetworkEventData(const network_event_t& e)
        : direction(e.direction), protocol(e.protocol), ip_type(e.ip_type), source_port(e.source_port)
        , destination_port(e.destination_port)
    {
        if (ip_type == AF_INET)
        {
            Ipv4Addresses ipv4;
            ipv4.source_ip = e.addresses.ipv4.source_ip;
            ipv4.destination_ip = e.addresses.ipv4.destination_ip;
            addresses = ipv4;
        }
        else
        {
            Ipv6Addresses ipv6;
            std::memcpy(ipv6.source_ip, e.addresses.ipv6.source_ip, sizeof(ipv6.source_ip));
            std::memcpy(ipv6.destination_ip, e.addresses.ipv6.destination_ip, sizeof(ipv6.destination_ip));
            addresses = ipv6;
        }
    }
};

struct DnsAnswer
{
    unsigned short type = 0;
    unsigned short data_length = 0;
    unsigned int ttl = 0;
    std::string data;

    DnsAnswer() = default;
    explicit DnsAnswer(const dns_answer_t& answer)
        : type(answer.type)
        , data_length(answer.data_length)
        , ttl(answer.ttl)
        , data(answer.data, sanitizeStringLength(answer.data, answer.data_len))
    {}
};

inline const char *parseDnsResponseFromRawPacket(const dns_response_event_t& e,
    unsigned short& txid,
    unsigned short& question_type,
    unsigned short& answer_count,
    unsigned char& rcode,
    std::string& question,
    std::vector<DnsAnswer>& answers)
{
    if (e.raw_packet_len < 12 || e.raw_packet_len > DNS_PACKET_CAPTURE_LENGTH)
    {
        return "raw DNS response packet length is invalid";
    }

    unsigned short qd_count = 0;
    unsigned short an_count = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, 4, qd_count) || qd_count == 0)
    {
        return "DNS response qd_count is missing/zero";
    }
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, 6, an_count))
    {
        return "failed reading DNS response answer count";
    }

    unsigned short parsed_txid = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, 0, parsed_txid))
    {
        return "failed reading DNS response txid";
    }

    unsigned char parsed_rcode = static_cast<unsigned char>(e.raw_packet[3] & 0x0F);

    size_t offset = 12;
    std::string parsed_question;
    size_t question_encoded_len = 0;
    if (!parseDnsNameAtOffset(e.raw_packet, e.raw_packet_len, offset, parsed_question, &question_encoded_len))
    {
        return "failed decoding DNS response question name";
    }
    offset += question_encoded_len;

    if (offset + 4 > e.raw_packet_len)
    {
        return "DNS response question is not terminated or lacks qtype/qclass";
    }

    unsigned short parsed_question_type = 0;
    if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, offset, parsed_question_type))
    {
        return "failed reading DNS response question type";
    }
    offset += 4; // qtype + qclass

    std::vector<DnsAnswer> parsed_answers;
    const unsigned short total_answers = an_count > DNS_MAX_RESPONSES ? DNS_MAX_RESPONSES : an_count;
    parsed_answers.reserve(total_answers);
    for (unsigned short i = 0; i < total_answers; ++i)
    {
        if (offset + 12 > e.raw_packet_len)
        {
            return "DNS response answer header exceeds packet length";
        }

        unsigned short name_ptr = 0;
        unsigned short type = 0;
        unsigned short data_len = 0;
        unsigned int ttl = 0;
        if (!readDnsU16Be(e.raw_packet, e.raw_packet_len, offset, name_ptr) ||
            !readDnsU16Be(e.raw_packet, e.raw_packet_len, offset + 2, type) ||
            !readDnsU32Be(e.raw_packet, e.raw_packet_len, offset + 6, ttl) ||
            !readDnsU16Be(e.raw_packet, e.raw_packet_len, offset + 10, data_len))
        {
            return "failed reading DNS response answer header";
        }
        if ((name_ptr & 0xC000) != 0xC000)
        {
            return "DNS response answer uses unsupported non-compressed name";
        }
        offset += 12;

        if (offset + data_len > e.raw_packet_len)
        {
            return "DNS response answer data exceeds packet boundary";
        }

        DnsAnswer ans;
        ans.type = type;
        ans.data_length = data_len;
        ans.ttl = ttl;
        if (type == 5)
        {
            std::string cname;
            size_t cname_encoded_len = 0;
            if (parseDnsNameAtOffset(e.raw_packet, e.raw_packet_len, offset, cname, &cname_encoded_len) &&
                cname_encoded_len == data_len)
            {
                ans.data = std::move(cname);
            }
            else
            {
                const size_t copy_len = data_len > DNS_MAX_NAME_LENGTH ? DNS_MAX_NAME_LENGTH : data_len;
                ans.data.assign(reinterpret_cast<const char*>(e.raw_packet + offset), copy_len);
            }
        }
        else
        {
            const size_t copy_len = data_len > DNS_MAX_NAME_LENGTH ? DNS_MAX_NAME_LENGTH : data_len;
            ans.data.assign(reinterpret_cast<const char*>(e.raw_packet + offset), copy_len);
        }
        parsed_answers.emplace_back(std::move(ans));
        offset += data_len;
    }

    txid = parsed_txid;
    question_type = parsed_question_type;
    answer_count = an_count;
    rcode = parsed_rcode;
    question = std::move(parsed_question);
    answers = std::move(parsed_answers);
    return nullptr;
}

struct DnsQueryEventData
{
    NetworkEventData network;
    unsigned short txid = 0;
    unsigned short question_type = 0;
    std::string question;
    std::string parse_error_reason;
    bool parse_success = false;

    DnsQueryEventData() = default;
    explicit DnsQueryEventData(const dns_query_event_t& e)
        : network(e.network)
        , txid(e.txid)
        , question_type(e.question_type)
        , question(e.question, sanitizeStringLength(e.question, e.question_len))
    {
        if (const char *parse_error = parseDnsQueryFromRawPacket(e, txid, question_type, question))
        {
            parse_error_reason = parse_error;
            parse_success = false;
            return;
        }
        parse_success = true;
    }
};

struct DnsResponseEventData
{
    NetworkEventData network;
    unsigned short txid = 0;
    unsigned short question_type = 0;
    unsigned short answer_count = 0;
    unsigned char rcode = 0;
    std::string question;
    std::vector<DnsAnswer> answers;
    std::string parse_error_reason;
    bool parse_success = false;

    DnsResponseEventData() = default;
    explicit DnsResponseEventData(const dns_response_event_t& e)
        : network(e.network)
        , txid(e.txid)
        , question_type(e.question_type)
        , answer_count(e.answer_count)
        , rcode(e.rcode)
        , question(e.question, sanitizeStringLength(e.question, e.question_len))
    {
        if (const char *parse_error = parseDnsResponseFromRawPacket(e, txid, question_type, answer_count, rcode, question, answers))
        {
            parse_error_reason = parse_error;
            parse_success = false;
            return;
        }
        /* convert binary answer payloads to readable strings */
        for (auto &ans : answers)
        {
            std::string converted;
            const size_t safe_len = std::min<size_t>(
                ans.data.size(),
                static_cast<size_t>(DNS_MAX_NAME_LENGTH));
            if (safe_len > 0)
            {
                if (ans.type == 5)
                {
                    converted = ans.data;
                }
                else
                {
                    converted = dnsAnswerDataToString(ans.type,
                        reinterpret_cast<const unsigned char*>(ans.data.data()), safe_len);
                    if (converted.empty())
                    {
                        /* fallback: hex representation */
                        converted = dnsAnswerDataToString(0,
                            reinterpret_cast<const unsigned char*>(ans.data.data()), safe_len);
                    }
                }
            }
            ans.data = std::move(converted);
        }
        parse_success = true;
    }
};

using EventData = std::variant<
    ChownEventData,
    ChmodEventData,
    ForkEventData,
    ExecEventData,
    ExitEventData,
    GenericFileEventData,
    RenameEventData,
    NetworkEventData,
    DnsQueryEventData,
    DnsResponseEventData
>;

struct Event
{
    using RawType = event_t;

    unsigned long long id = 0;
    event_type type = EXEC;
    rule_action action = ALLOW_EVENT;
    unsigned char had_error_while_handling = 0;
    unsigned long long time = 0;
    Process process;
    Process parent_process;
    EventData data;

    unsigned int matched_rule_id = 0;
    config::RuleMetadata matched_rule_metadata;
    bool is_enriched = false;

    Event() = default;

    explicit Event(const RawType& ev)
        : id(ev.id), type(ev.type), action(ev.action), had_error_while_handling(ev.had_error_while_handling)
        , time(ev.time), process(ev.process), parent_process(ev.parent_process), matched_rule_id(ev.matched_rule_id)
    {
        switch (ev.type)
        {
        case CHOWN: data = ChownEventData(ev.data.chown); break;
        case CHMOD: data = ChmodEventData(ev.data.chmod); break;
        case FORK:  data = ForkEventData(ev.data.fork); break;
        case EXEC:  data = ExecEventData(ev.data.exec); break;
        case EXIT:  data = ExitEventData(ev.data.exit); break;
        case FILE_CREATE: data = GenericFileEventData(ev.data.file_create); break;
        case WRITE: data = GenericFileEventData(ev.data.write); break;
        case READ:  data = GenericFileEventData(ev.data.read); break;
        case UNLINK: data = GenericFileEventData(ev.data.unlink); break;
        case RENAME: data = RenameEventData(ev.data.rename); break;
        case NETWORK: data = NetworkEventData(ev.data.network); break;
        case DNS_QUERY: data = DnsQueryEventData(ev.data.dns_query); break;
        case DNS_RESPONSE: data = DnsResponseEventData(ev.data.dns_response); break;
        case MKDIR: data = GenericFileEventData(ev.data.mkdir); break;
        case RMDIR: data = GenericFileEventData(ev.data.rmdir); break;
        }
    }
};

struct Error
{
    using RawType = error_report_t;

    int error_code = 0;
    std::string location;
    std::string details;
    std::string hook_name;

    bool is_enriched = false;

    Error() = default;

    explicit Error(const RawType& e)
        : error_code(e.error_code)
        , location(e.location, strnlen(e.location, ERROR_DETAILS_MAX / 4))
        , details(e.details, strnlen(e.details, ERROR_DETAILS_MAX))
        , hook_name(e.hook_name, strnlen(e.hook_name, HOOK_NAME_MAX_LENGTH))
    {}
};

}

