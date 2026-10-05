/*
 * windows_driver_transport.h
 *
 * Windows Filter Manager communication-port transport implementation.
 *
 * Phase 1.31 — Kernel/User-Mode Message Transport Foundation (corrected)
 *
 * Communication directions:
 *
 *   KERNEL -> USER (primary Phase 1.31 path):
 *     FltSendMessage   (kernel)
 *       -> FilterGetMessage  (user receiver)
 *         -> FilterReplyMessage (user reply)
 *
 *   USER -> KERNEL (secondary path, via MessageNotifyCallback):
 *     FilterSendMessage (user) -> SentinalPortMessageNotify (kernel callback)
 *
 * Synchronization design (corrected for disconnect/receive deadlock):
 *
 *   m_mutex         — short-lived state guard. Protects m_state and m_handle.
 *                     NEVER held across a blocking operation.
 *
 *   m_receiveMutex  — receive-operation serializer. Held for the duration of
 *                     one complete receiveAndReply() cycle (get + validate + reply).
 *                     disconnect() acquires this AFTER signaling shutdown to
 *                     ensure no active receive is using the handle before it
 *                     is closed.
 *
 *   m_shutdownEvent — manual-reset event (Windows HANDLE, stored as void*).
 *                     Set by disconnect() to unblock FilterGetMessage via
 *                     WaitForMultipleObjects in DefaultFilterPortDevice.
 *                     Reset by connect() for reconnect support.
 *
 * Safe disconnect() sequence:
 *   1. Lock m_mutex: set Disconnecting, capture handle, m_handle=nullptr. Unlock.
 *   2. SetEvent(m_shutdownEvent) — unblocks any active FilterGetMessage.
 *   3. Lock m_receiveMutex — blocks until receiveAndReply() completes its cycle.
 *   4. Unlock m_receiveMutex.
 *   5. Close captured handle (safe: receiveAndReply() has finished using it).
 *   6. ResetEvent(m_shutdownEvent) — ready for reconnect.
 *   7. Lock m_mutex: set Disconnected. Unlock.
 *
 * No mutex is held during FilterGetMessage. The handle remains valid throughout
 * receiveAndReply() because disconnect() cannot close it until step 5, which
 * cannot happen until receiveAndReply() releases m_receiveMutex (step 3).
 */

#pragma once

#include <sentinal/common.h>
#include <sentinal/driver_contract.h>
#include <sentinal/driver_unicode_contract.h>
#include <memory>
#include <mutex>

namespace sentinel::service {

/* =========================================================================
 * Transport Connection State
 * ========================================================================= */

enum class TransportState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting
};

/* =========================================================================
 * Filter Manager transport header mirrors
 *
 * These structs mirror the Windows FILTER_MESSAGE_HEADER and
 * FILTER_REPLY_HEADER from <fltUser.h> using fixed-width integer types
 * so the header remains free of Windows SDK dependencies.
 *
 * Layout on x64 (verified by static_assert in windows_driver_transport.cpp):
 *
 *   FILTER_MESSAGE_HEADER:
 *     ULONG    ReplyLength  -> uint32_t replyLength  offset 0,  size 4
 *     (natural padding)                              offset 4,  size 4
 *     ULONGLONG MessageId   -> uint64_t messageId    offset 8,  size 8
 *     total: 16 bytes
 *
 *   FILTER_REPLY_HEADER:
 *     NTSTATUS Status       -> int32_t  status       offset 0,  size 4
 *     (natural padding)                              offset 4,  size 4
 *     ULONGLONG MessageId   -> uint64_t messageId    offset 8,  size 8
 *     total: 16 bytes
 *
 * NOTE: Do NOT use #pragma pack on these structs. The natural compiler
 * padding is what makes them match the Windows SDK types (16 bytes each).
 * Packing would yield 12 bytes and break the layout verification asserts.
 *
 * IMPORTANT: These fields are Filter Manager transport metadata only.
 * Never conflate them with the application ABI (SentinalDriverUnicode*).
 * ========================================================================= */

struct SentinalFltMessageHeader {
    uint32_t replyLength;  /* FILTER_MESSAGE_HEADER.ReplyLength */
    uint32_t _pad0;        /* explicit padding matching FILTER_MESSAGE_HEADER layout */
    uint64_t messageId;    /* FILTER_MESSAGE_HEADER.MessageId */
};                         /* total: 16 bytes with natural alignment */

struct SentinalFltReplyHeader {
    int32_t  status;       /* FILTER_REPLY_HEADER.Status (NTSTATUS) */
    uint32_t _pad0;        /* explicit padding matching FILTER_REPLY_HEADER layout */
    uint64_t messageId;    /* FILTER_REPLY_HEADER.MessageId */
};                         /* total: 16 bytes with natural alignment */

static_assert(sizeof(SentinalFltMessageHeader) == 16,
    "SentinalFltMessageHeader must be 16 bytes to match FILTER_MESSAGE_HEADER");
static_assert(sizeof(SentinalFltReplyHeader) == 16,
    "SentinalFltReplyHeader must be 16 bytes to match FILTER_REPLY_HEADER");

/* =========================================================================
 * Kernel-originated message receive buffer (FilterGetMessage)
 *
 * Filter Manager prepends FILTER_MESSAGE_HEADER to the kernel's payload
 * when delivering a kernel-originated message to user mode.
 *
 * Buffer passed to FilterGetMessage must be:
 *   [SentinalFltMessageHeader (16)] + [SentinalDriverUnicodeProtectionRequest (2096)]
 *   total: 2112 bytes
 *
 * The header field is Filter Manager transport metadata; only the payload
 * field carries our application ABI. Do not conflate them.
 * ========================================================================= */

struct SentinalKernelMessageBuffer {
    SentinalFltMessageHeader               header;  /* Filter Manager transport header */
    SentinalDriverUnicodeProtectionRequest payload; /* application ABI payload */
};

/* =========================================================================
 * Reply buffer for FilterReplyMessage (user -> kernel response)
 *
 * Buffer passed to FilterReplyMessage must be:
 *   [SentinalFltReplyHeader (16)] + [SentinalDriverUnicodeProtectionResponse (40)]
 *   total: 56 bytes
 *
 * header.messageId must match the messageId from the received FILTER_MESSAGE_HEADER.
 * header.status = 0 (STATUS_SUCCESS) for a valid transport-level reply.
 * ========================================================================= */

struct SentinalReplyBuffer {
    SentinalFltReplyHeader                  header;  /* Filter Manager transport header */
    SentinalDriverUnicodeProtectionResponse payload; /* application ABI payload */
};

/* =========================================================================
 * IWindowsDriverTransport Interface
 * ========================================================================= */

class IWindowsDriverTransport {
public:
    virtual ~IWindowsDriverTransport() = default;

    virtual SentinalStatus connect() = 0;

    virtual SentinalStatus disconnect() = 0;

    virtual bool isConnected() const noexcept = 0;

    /*
     * exchange() — user-mode -> kernel path (FilterSendMessage).
     * Invokes SentinalPortMessageNotify on the kernel side.
     * Not the receiver for FltSendMessage kernel-originated messages.
     */
    virtual SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) = 0;

    /*
     * exchangeUnicode() — user-mode -> kernel (FilterSendMessage), Unicode ABI.
     * Default: not supported.
     */
    virtual SentinalStatus exchangeUnicode(
        const SentinalDriverUnicodeProtectionRequest& request,
        SentinalDriverUnicodeProtectionResponse& outResponse
    ) {
        (void)request;
        (void)outResponse;
        return SENTINAL_STATUS_NOT_FOUND;
    }

    /*
     * receiveAndReply() — kernel -> user-mode path.
     *
     * Uses FilterGetMessage to receive one kernel-originated protection request,
     * validates the payload, constructs a deterministic development response,
     * and sends it back via FilterReplyMessage.
     *
     * This is the CORRECT receiver for messages sent by kernel via FltSendMessage.
     * Do NOT use exchange() for this purpose.
     *
     * Blocks until a message arrives, the port is closed, or disconnect() signals
     * the shutdown event.
     *
     * Concurrency: only one receiveAndReply() is active at a time (enforced by
     * m_receiveMutex). m_mutex is NOT held during the blocking FilterGetMessage call.
     *
     * outRequest:  optional — filled with the validated received request on success
     * outResponse: optional — filled with the response sent back on success
     *
     * Returns:
     *   SENTINAL_STATUS_SUCCESS          — round-trip completed
     *   SENTINAL_STATUS_ACCESS_DENIED    — not connected, or shutdown signaled
     *   SENTINAL_STATUS_INVALID_PARAMETER — message failed validation
     *   SENTINAL_STATUS_UNSPECIFIED_ERROR — FilterGetMessage or FilterReplyMessage failed
     */
    virtual SentinalStatus receiveAndReply(
        SentinalDriverUnicodeProtectionRequest*  outRequest  = nullptr,
        SentinalDriverUnicodeProtectionResponse* outResponse = nullptr
    ) {
        (void)outRequest;
        (void)outResponse;
        return SENTINAL_STATUS_NOT_FOUND;
    }
};

/* =========================================================================
 * Filter Port Device Abstraction (enables mock-based unit testing)
 * ========================================================================= */

class IFilterPortDevice {
public:
    virtual ~IFilterPortDevice() = default;

    /* Connect to the Filter Manager communication port */
    virtual SentinalStatus connectPort(const wchar_t* portName, void** outHandle) = 0;

    /*
     * sendMessage() — user-mode -> kernel (FilterSendMessage).
     * Invokes the kernel MessageNotifyCallback (SentinalPortMessageNotify).
     * Not the receiver for FltSendMessage kernel-originated messages.
     */
    virtual SentinalStatus sendMessage(
        void* portHandle,
        const void* inBuffer,
        uint32_t inSize,
        void* outBuffer,
        uint32_t outSize,
        uint32_t* bytesReturned
    ) = 0;

    /*
     * getKernelMessage() — receive kernel-originated message (FilterGetMessage).
     *
     * messageBuffer must point to a SentinalKernelMessageBuffer.
     * messageBufferSize must equal sizeof(SentinalKernelMessageBuffer).
     * shutdownEvent is an optional platform signal (Windows HANDLE stored as void*).
     *   When signaled by disconnect(), the blocking FilterGetMessage is cancelled
     *   via CancelIoEx and this function returns SENTINAL_STATUS_ACCESS_DENIED.
     *   Mock implementations may ignore this parameter.
     *
     * Uses overlapped I/O with WaitForMultipleObjects([ioEvent, shutdownEvent])
     * in the production implementation. This ensures that disconnect() can
     * always unblock a waiting receive without deadlocking.
     */
    virtual SentinalStatus getKernelMessage(
        void* portHandle,
        void* messageBuffer,
        uint32_t messageBufferSize,
        void* shutdownEvent
    ) = 0;

    /*
     * replyToKernel() — send reply to kernel (FilterReplyMessage).
     *
     * replyBuffer must point to a SentinalReplyBuffer.
     * replyBuffer->header.messageId must match the messageId from getKernelMessage.
     */
    virtual SentinalStatus replyToKernel(
        void* portHandle,
        const void* replyBuffer,
        uint32_t replyBufferSize
    ) = 0;

    /* Close the communication port handle */
    virtual void closePort(void* portHandle) = 0;
};

/* =========================================================================
 * WindowsDriverTransport
 * ========================================================================= */

class WindowsDriverTransport final
    : public IWindowsDriverTransport
{
public:
    WindowsDriverTransport();

    explicit WindowsDriverTransport(
        std::shared_ptr<IFilterPortDevice> device
    );

    ~WindowsDriverTransport() override;

    /*
     * connect() — connect to the Filter Manager communication port.
     * Resets the shutdown event to allow a fresh receive session.
     * Returns SENTINAL_STATUS_SUCCESS if already connected (idempotent).
     */
    SentinalStatus connect() override;

    /*
     * disconnect() — safe disconnect with active-receive coordination.
     *
     * Safe sequence:
     *   1. Lock m_mutex briefly: set Disconnecting, capture handle, clear m_handle.
     *   2. Signal m_shutdownEvent to unblock any active FilterGetMessage.
     *   3. Acquire m_receiveMutex (blocks until receiveAndReply() finishes).
     *   4. Release m_receiveMutex.
     *   5. Close captured handle (safe: receiveAndReply() is done with it).
     *   6. Reset m_shutdownEvent for reconnect.
     *   7. Lock m_mutex briefly: set Disconnected.
     *
     * NEVER deadlocks: m_mutex is released in step 1 before the serialization
     * wait in step 3. m_shutdownEvent causes getKernelMessage() to return
     * ACCESS_DENIED, which causes receiveAndReply() to return and release
     * m_receiveMutex, which allows step 3 to proceed.
     *
     * Safe to call multiple times (idempotent).
     */
    SentinalStatus disconnect() override;

    bool isConnected() const noexcept override;

    TransportState state() const noexcept;

    /*
     * exchange() — user->kernel via FilterSendMessage.
     * Holds m_mutex for the duration (bounded: kernel callback is fast).
     */
    SentinalStatus exchange(
        const SentinalDriverProtectionRequest& request,
        SentinalDriverProtectionResponse& outResponse
    ) override;

    /*
     * exchangeUnicode() — user->kernel via FilterSendMessage, Unicode ABI.
     */
    SentinalStatus exchangeUnicode(
        const SentinalDriverUnicodeProtectionRequest& request,
        SentinalDriverUnicodeProtectionResponse& outResponse
    ) override;

    /*
     * receiveAndReply() — kernel->user via FilterGetMessage + FilterReplyMessage.
     *
     * Mutex behavior:
     *   - Acquires m_receiveMutex for the ENTIRE cycle (get + validate + reply).
     *   - Acquires m_mutex BRIEFLY to check state and capture handle.
     *   - m_mutex is released BEFORE FilterGetMessage is called.
     *   - m_mutex is NEVER held during the blocking FilterGetMessage call.
     *
     * This ensures disconnect() can never deadlock waiting for m_mutex while
     * this function is blocked inside FilterGetMessage.
     *
     * Transport failure or shutdown NEVER becomes ALLOW.
     * Malformed request NEVER receives a reply.
     */
    SentinalStatus receiveAndReply(
        SentinalDriverUnicodeProtectionRequest*  outRequest  = nullptr,
        SentinalDriverUnicodeProtectionResponse* outResponse = nullptr
    ) override;

private:
    std::shared_ptr<IFilterPortDevice> m_device;
    void*          m_handle{nullptr};
    TransportState m_state{TransportState::Disconnected};

    /*
     * m_mutex: short-lived state guard.
     * Protects m_state and m_handle.
     * NEVER held during FilterGetMessage or any other potentially-blocking call.
     */
    mutable std::mutex m_mutex;

    /*
     * m_receiveMutex: receive-operation serializer.
     * Held for the full duration of receiveAndReply() (get + validate + reply).
     * disconnect() acquires this after signaling shutdown, guaranteeing it
     * cannot close the handle until the active receive finishes.
     */
    mutable std::mutex m_receiveMutex;

    /*
     * m_shutdownEvent: Windows HANDLE (stored as void*) manual-reset event.
     * Set by disconnect() to signal DefaultFilterPortDevice::getKernelMessage()
     * to cancel its overlapped FilterGetMessage and return ACCESS_DENIED.
     * Reset by connect() to allow a fresh receive session after reconnect.
     * Created once in the constructor; closed in the destructor.
     * nullptr on non-Windows platforms.
     */
    void* m_shutdownEvent{nullptr};
};

} // namespace sentinel::service
