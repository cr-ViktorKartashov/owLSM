#include "ringbuffers_messages_handlers.hpp"

#include <cstdio>
#include <iostream>

namespace owlsm
{
    void RingbuffersMessagesHandlers::start(std::shared_ptr<struct ring_buffer>& event_ringbuffer, std::shared_ptr<struct ring_buffer>& error_ringbuffer)
    {
        std::cout.flush();
        std::cerr.flush();
        std::fflush(stdout);
        std::fflush(stderr);

        m_event_handler = std::make_unique<EventHandler>(event_ringbuffer, STDOUT_FILENO);
        m_error_handler = std::make_unique<ErrorHandler>(error_ringbuffer, STDERR_FILENO);
        m_event_handler->start();
        m_error_handler->start();
    }

    void RingbuffersMessagesHandlers::destroy()
    {
        if (m_event_handler)
        {
            m_event_handler->destroy();
            m_event_handler = nullptr;
        }
        if (m_error_handler)
        {
            m_error_handler->destroy();
            m_error_handler = nullptr;
        }
    }

    int RingbuffersMessagesHandlers::handleEvent(void* ctx, void* data, size_t len)
    {
        return m_event_handler->eventReceivedCallback(ctx, data, len);
    }

    int RingbuffersMessagesHandlers::handleError(void* ctx, void* data, size_t len)
    {
        return m_error_handler->eventReceivedCallback(ctx, data, len);
    }

    int handleEventCallback(void* ctx, void* data, size_t len)
    {
        return g_ringbuffers_messages_handlers.handleEvent(ctx, data, len);
    }

    int handleErrorCallback(void* ctx, void* data, size_t len)
    {
        return g_ringbuffers_messages_handlers.handleError(ctx, data, len);
    }

    RingbuffersMessagesHandlers g_ringbuffers_messages_handlers {};
}