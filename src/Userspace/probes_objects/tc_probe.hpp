#pragma once

#include "abstract_probe.hpp"

#include <net/if.h>
#include <cerrno>
#include <cstring>
#include <vector>

namespace owlsm
{
class TcProbe : public AbstractProbe
{
public:
    TcProbe()
        : AbstractProbe(probe_type::TC) {}

    virtual ~TcProbe() override = default;

    virtual void bpfOpen() override
    {
        bpf_program__set_autoattach(m_skel->progs.dns_response_tc_ingress, false);
    }

    virtual void bpfAttach() override
    {
        const int prog_fd = bpf_program__fd(m_skel->progs.dns_response_tc_ingress);
        if (prog_fd < 0)
        {
            throw std::runtime_error("failed to get dns_response_tc_ingress fd");
        }

        struct if_nameindex *ifaces = if_nameindex();
        if (!ifaces)
        {
            throw std::runtime_error("if_nameindex failed. errno: " + std::to_string(errno));
        }

        for (struct if_nameindex *it = ifaces; it && it->if_index != 0; ++it)
        {
            bpf_tc_hook hook = {};
            hook.sz = sizeof(hook);
            hook.ifindex = static_cast<int>(it->if_index);
            hook.attach_point = BPF_TC_INGRESS;

            const int create_ret = bpf_tc_hook_create(&hook);
            if (create_ret != 0 && create_ret != -EEXIST)
            {
                LOG_WARN("Skipping tc hook create on ifindex " << hook.ifindex << ". errno: " << -create_ret);
                continue;
            }
            const bool created_here = (create_ret == 0);

            bpf_tc_opts detach_opts = {};
            detach_opts.sz = sizeof(detach_opts);
            detach_opts.handle = 1;
            detach_opts.priority = 1;

            const int detach_ret = bpf_tc_detach(&hook, &detach_opts);
            if (detach_ret != 0 && detach_ret != -ENOENT && detach_ret != -EOPNOTSUPP)
            {
                LOG_WARN("tc detach on ifindex " << hook.ifindex << " returned errno: " << -detach_ret << " (" << std::strerror(detach_ret < 0 ? -detach_ret : detach_ret) << ")");
            }

            bpf_tc_opts attach_opts = {};
            attach_opts.sz = sizeof(attach_opts);
            attach_opts.prog_fd = prog_fd;
            attach_opts.handle = 1;
            attach_opts.priority = 1;
            attach_opts.flags = 0;

            /* Try attaching without replace first (less intrusive). If it fails, retry with replace. */
            int attach_ret = bpf_tc_attach(&hook, &attach_opts);
            if (attach_ret != 0)
            {
                int err = attach_ret < 0 ? -attach_ret : attach_ret;
                LOG_WARN("tc attach (no-replace) on ifindex " << hook.ifindex << " failed: errno=" << err << " (" << std::strerror(err) << ")");

                attach_opts.flags = BPF_TC_F_REPLACE;
                int attach_ret2 = bpf_tc_attach(&hook, &attach_opts);
                if (attach_ret2 != 0)
                {
                    int err2 = attach_ret2 < 0 ? -attach_ret2 : attach_ret2;
                    LOG_WARN("tc attach (replace) on ifindex " << hook.ifindex << " failed: errno=" << err2 << " (" << std::strerror(err2) << ")");
                    continue;
                }
                attach_ret = attach_ret2;
            }

            TcHookState hook_state = {};
            hook_state.hook = hook;
            hook_state.created = created_here;
            m_attached_hooks.push_back(hook_state);
            LOG_INFO("attached tc ingress dns_response hook on ifindex " << hook.ifindex);
        }

        if_freenameindex(ifaces);
        if (m_attached_hooks.empty())
        {
            throw std::runtime_error("failed to attach dns_response_tc_ingress to any interface");
        }
    }

    virtual void bpfDetach() override
    {
        for (auto &hook_state : m_attached_hooks)
        {
            bpf_tc_opts opts = {};
            opts.sz = sizeof(opts);
            opts.handle = 1;
            opts.priority = 1;
            bpf_tc_detach(&hook_state.hook, &opts);
            if (hook_state.created)
            {
                const int destroy_ret = bpf_tc_hook_destroy(&hook_state.hook);
                if (destroy_ret != 0)
                {
                    int err = destroy_ret < 0 ? -destroy_ret : destroy_ret;
                    LOG_WARN("tc hook destroy on ifindex " << hook_state.hook.ifindex
                        << " failed: errno=" << err << " (" << std::strerror(err) << ")");
                }
            }
        }
        m_attached_hooks.clear();
    }

private:
    struct TcHookState
    {
        bpf_tc_hook hook = {};
        bool created = false;
    };

    std::vector<TcHookState> m_attached_hooks;
};
}
