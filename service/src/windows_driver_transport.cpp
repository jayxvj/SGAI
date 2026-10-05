/*
 * windows_driver_transport.cpp
 *
 * Windows Filter Manager communication-port transport implementation.
 *
 * Phase 1.31 — Kernel/User-Mode Message Transport Foundation (corrected)
 *
 * Disconnect/receive deadlock fix:
 *
 *   Previously: m_mutex held during FilterGetMessage → disconnect() deadlocked.
 *
 *   Now:
 *     m_mutex         — short-lived, released BEFORE FilterGetMessage is called.
 *     m_receiveMutex  — held for full receiveAndReply() cycle; disconnect() waits
 *                       on this AFTER signaling m_shutdownEvent.
 *     m_shutdownEvent — signals DefaultFilterPortDevice::getKernelMessage() to
 *                       cancel its overlapped FilterGetMessage via CancelIoEx.
 *
 *   Sequence ensuring no deadlock, no use-after-close, no handle race:
 *
 *     Thread A (receiveAndReply):
 *       1. acquire m_receiveMutex
 *       2. acquire m_mutex briefly → check state, capture handle → release m_mutex
 *       3. call getKernelMessage(capturedHandle, ..., m_shutdownEvent)  ← blocks here
 *
 *     Thread B (disconnect):
 *       1. acquire m_mutex briefly → Disconnecting, m_handle=nullptr → release m_mutex
 *       2. SetEvent(m_shutdownEvent)  ← unblocks Thread A's FilterGetMessage
 *       3. acquire m_receiveMutex     ← BLOCKS until Thread A releases it
 *       4. release m_receiveMutex
 *       5. close capturedHandle       ← SAFE: Thread A is done with it
 *       6. ResetEvent(m_shutdownEvent)
 *       7. acquire m_mutex briefly → Disconnected → release m_mutex
 */

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltUser.h>
#endif /* _WIN32 */

#include "service/windows_driver_transport.h"
#include <cstring>

#if defined(_WIN32)
/*
 * Layout verification: mirror structs must exactly match the Windows SDK types.
 * Any mismatch is a compile-time error, not a runtime hazard.
 */
static_assert(sizeof(sentinel::service::SentinalFltMessageHeader) == sizeof(FILTER_MESSAGE_HEADER),
    "SentinalFltMessageHeader size must match FILTER_MESSAGE_HEADER");
static_assert(offsetof(sentinel::service::SentinalFltMessageHeader, messageId) ==
              offsetof(FILTER_MESSAGE_HEADER, MessageId),
    "SentinalFltMessageHeader.messageId offset must match FILTER_MESSAGE_HEADER.MessageId");
static_assert(sizeof(sentinel::service::SentinalFltReplyHeader) == sizeof(FILTER_REPLY_HEADER),
    "SentinalFltReplyHeader size must match FILTER_REPLY_HEADER");
static_assert(offsetof(sentinel::service::SentinalFltReplyHeader, messageId) ==
              offsetof(FILTER_REPLY_HEADER, MessageId),
    "SentinalFltReplyHeader.messageId offset must match FILTER_REPLY_HEADER.MessageId");
#endif /* _WIN32 */

namespace sentinel::service {

/* =========================================================================
 * DefaultFilterPortDevice — production implementation using fltlib APIs
 * ========================================================================= */

namespace {

class DefaultFilterPortDevice final : public IFilterPortDevice {
public:

    /* ------------------------------------------------------------------
     * connectPort / closePort
     * ------------------------------------------------------------------ */

    SentinalStatus connectPort(const wchar_t* portName, void** outHandle) override {
#if defined(_WIN32)
        if (portName == nullptr || outHandle == nullptr) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        HANDLE hPort = INVALID_HANDLE_VALUE;
        HRESULT hr = FilterConnectCommunicationPort(
            portName,
            0,
            nullptr,
            0,
            nullptr,
            &hPort
        );

        if (FAILED(hr) || hPort == INVALID_HANDLE_VALUE) {
            *outHandle = nullptr;
            return SENTINAL_STATUS_NOT_FOUND;
        }

        *outHandle = static_cast<void*>(hPort);
        return SENTINAL_STATUS_SUCCESS;
#else
        (void)portName;
        (void)outHandle;
        return SENTINAL_STATUS_NOT_SUPPORTED;
#endif
    }

    void closePort(void* portHandle) override {
#if defined(_WIN32)
        if (portHandle != nullptr && portHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(static_cast<HANDLE>(portHandle));
        }
#else
        (void)portHandle;
#endif
    }

    /* ------------------------------------------------------------------
     * sendMessage — USER -> KERNEL (FilterSendMessage)
     *
     * Sends a user-mode message to the kernel MessageNotifyCallback
     * (SentinalPortMessageNotify). This is NOT the receiver for
     * FltSendMessage kernel-originated messages.
     * ------------------------------------------------------------------ */

    SentinalStatus sendMessage(
        void* portHandle,
        const void* inBuffer,
        uint32_t inSize,
        void* outBuffer,
        uint32_t outSize,
        uint32_t* bytesReturned
    ) override {
#if defined(_WIN32)
        if (portHandle == nullptr || portHandle == INVALID_HANDLE_VALUE ||
            inBuffer == nullptr || outBuffer == nullptr) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        DWORD returned = 0;
        HRESULT hr = FilterSendMessage(
            static_cast<HANDLE>(portHandle),
            const_cast<void*>(inBuffer),
            static_cast<DWORD>(inSize),
            outBuffer,
            static_cast<DWORD>(outSize),
            &returned
        );

        if (FAILED(hr)) {
            return SENTINAL_STATUS_UNSPECIFIED_ERROR;
        }

        if (bytesReturned != nullptr) {
            *bytesReturned = static_cast<uint32_t>(returned);
        }

        return SENTINAL_STATUS_SUCCESS;
#else
        (void)portHandle;
        (void)inBuffer;
        (void)inSize;
        (void)outBuffer;
        (void)outSize;
        (void)bytesReturned;
        return SENTINAL_STATUS_NOT_SUPPORTED;
#endif
    }

    /* ------------------------------------------------------------------
     * getKernelMessage — KERNEL -> USER receive (FilterGetMessage)
     *
     * Uses overlapped I/O with WaitForMultipleObjects so that disconnect()
     * can cancel the blocking wait by signaling shutdownEvent.
     *
     * Sequence:
     *   1. Create a local auto-reset event (ioEvent) for the OVERLAPPED.
     *   2. Call FilterGetMessage with OVERLAPPED.
     *      - Returns S_OK if a message is immediately available.
     *      - Returns ERROR_IO_PENDING if no message yet (wait required).
     *   3. If pending: WaitForMultipleObjects([ioEvent, shutdownEvent]).
     *      - ioEvent fires when FilterGetMessage completes.
     *      - shutdownEvent fires when disconnect() wants to cancel.
     *   4. If shutdown signaled: CancelIoEx, drain IO, return ACCESS_DENIED.
     *   5. If IO completes: GetOverlappedResult, return SUCCESS.
     *
     * Buffer lifetime: messageBuffer is caller-stack-allocated in
     * receiveAndReply(). It remains valid for the entire overlapped
     * operation because the overlapped IO completes before this function
     * returns (either via WaitForMultipleObjects or GetOverlappedResult).
     *
     * CancelIoEx is called from within this function (in the receive thread),
     * on capturedHandle which is still valid at this point (disconnect() has
     * not closed it yet — it is waiting on m_receiveMutex which receiveAndReply()
     * releases only AFTER this function returns).
     * ------------------------------------------------------------------ */

    SentinalStatus getKernelMessage(
        void* portHandle,
        void* messageBuffer,
        uint32_t messageBufferSize,
        void* shutdownEvent
    ) override {
#if defined(_WIN32)
        if (portHandle == nullptr || portHandle == INVALID_HANDLE_VALUE ||
            messageBuffer == nullptr) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        if (messageBufferSize < static_cast<uint32_t>(sizeof(SentinalKernelMessageBuffer))) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        /*
         * Create a local event for the overlapped operation.
         * Manual-reset so we can safely check it after WaitForMultipleObjects.
         */
        HANDLE ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (ioEvent == nullptr || ioEvent == INVALID_HANDLE_VALUE) {
            return SENTINAL_STATUS_UNSPECIFIED_ERROR;
        }

        OVERLAPPED ov = {};
        ov.hEvent = ioEvent;

        /*
         * FilterGetMessage with OVERLAPPED writes FILTER_MESSAGE_HEADER
         * (mirrored by SentinalFltMessageHeader) followed by the kernel
         * payload (SentinalDriverUnicodeProtectionRequest) into messageBuffer.
         *
         * The cast is safe: SentinalKernelMessageBuffer.header mirrors
         * FILTER_MESSAGE_HEADER exactly (verified by static_assert above).
         */
        HRESULT hr = FilterGetMessage(
            static_cast<HANDLE>(portHandle),
            static_cast<PFILTER_MESSAGE_HEADER>(messageBuffer),
            static_cast<DWORD>(messageBufferSize),
            &ov
        );

        SentinalStatus result = SENTINAL_STATUS_SUCCESS;

        if (SUCCEEDED(hr)) {
            /*
             * Message was immediately available. Data is in messageBuffer.
             * The overlapped event will also fire (or is already set).
             * No need to wait; the buffer is populated.
             */
            result = SENTINAL_STATUS_SUCCESS;
        } else if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            /*
             * No message available yet. Wait for IO completion or shutdown.
             */
            if (shutdownEvent != nullptr) {
                HANDLE waitHandles[2] = {
                    ioEvent,
                    static_cast<HANDLE>(shutdownEvent)
                };
                DWORD waitResult = WaitForMultipleObjects(
                    2, waitHandles, FALSE, INFINITE
                );

                if (waitResult == WAIT_OBJECT_0) {
                    /* IO completed — get final status */
                    DWORD transferred = 0;
                    if (!GetOverlappedResult(
                            static_cast<HANDLE>(portHandle),
                            &ov, &transferred, FALSE)) {
                        result = SENTINAL_STATUS_UNSPECIFIED_ERROR;
                    }
                } else if (waitResult == WAIT_OBJECT_0 + 1) {
                    /*
                     * Shutdown signaled by disconnect().
                     * Cancel the pending IO and wait for cancellation to drain.
                     * CancelIoEx is safe here: portHandle (capturedHandle in
                     * receiveAndReply) is still valid because disconnect()
                     * waits on m_receiveMutex before closing it.
                     */
                    CancelIoEx(static_cast<HANDLE>(portHandle), &ov);
                    WaitForSingleObject(ioEvent, INFINITE);
                    result = SENTINAL_STATUS_ACCESS_DENIED;
                } else {
                    result = SENTINAL_STATUS_UNSPECIFIED_ERROR;
                }
            } else {
                /*
                 * No shutdown event provided — synchronous wait.
                 * Caller accepts that this may block indefinitely.
                 */
                DWORD waitResult = WaitForSingleObject(ioEvent, INFINITE);
                if (waitResult == WAIT_OBJECT_0) {
                    DWORD transferred = 0;
                    if (!GetOverlappedResult(
                            static_cast<HANDLE>(portHandle),
                            &ov, &transferred, FALSE)) {
                        result = SENTINAL_STATUS_UNSPECIFIED_ERROR;
                    }
                } else {
                    result = SENTINAL_STATUS_UNSPECIFIED_ERROR;
                }
            }
        } else {
            /* FilterGetMessage failed immediately */
            result = SENTINAL_STATUS_UNSPECIFIED_ERROR;
        }

        CloseHandle(ioEvent);
        return result;
#else
        (void)portHandle;
        (void)messageBuffer;
        (void)messageBufferSize;
        (void)shutdownEvent;
        return SENTINAL_STATUS_NOT_SUPPORTED;
#endif
    }

    /* ------------------------------------------------------------------
     * replyToKernel — USER -> KERNEL reply (FilterReplyMessage)
     *
     * replyBuffer must be a SentinalReplyBuffer with header.messageId
     * matching the messageId from the corresponding getKernelMessage call.
     * ------------------------------------------------------------------ */

    SentinalStatus replyToKernel(
        void* portHandle,
        const void* replyBuffer,
        uint32_t replyBufferSize
    ) override {
#if defined(_WIN32)
        if (portHandle == nullptr || portHandle == INVALID_HANDLE_VALUE ||
            replyBuffer == nullptr) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        if (replyBufferSize < static_cast<uint32_t>(sizeof(SentinalReplyBuffer))) {
            return SENTINAL_STATUS_INVALID_PARAMETER;
        }

        /*
         * Cast is safe: SentinalReplyBuffer.header mirrors FILTER_REPLY_HEADER
         * exactly (verified by static_assert above).
         */
        HRESULT hr = FilterReplyMessage(
            static_cast<HANDLE>(portHandle),
            static_cast<PFILTER_REPLY_HEADER>(const_cast<void*>(replyBuffer)),
            static_cast<DWORD>(replyBufferSize)
        );

        if (FAILED(hr)) {
            return SENTINAL_STATUS_UNSPECIFIED_ERROR;
        }

        return SENTINAL_STATUS_SUCCESS;
#else
        (void)portHandle;
        (void)replyBuffer;
        (void)replyBufferSize;
        return SENTINAL_STATUS_NOT_SUPPORTED;
#endif
    }
};

} // anonymous namespace

/* =========================================================================
 * WindowsDriverTransport — constructor / destructor
 * ========================================================================= */

WindowsDriverTransport::WindowsDriverTransport()
    : WindowsDriverTransport(std::make_shared<DefaultFilterPortDevice>())
{
}

WindowsDriverTransport::WindowsDriverTransport(
    std::shared_ptr<IFilterPortDevice> device
)
    : m_device(std::move(device))
{
    /*
     * Create the manual-reset shutdown event (initially non-signaled).
     * This event is reused across connect/disconnect cycles; connect()
     * resets it before each new session.
     */
#if defined(_WIN32)
    m_shutdownEvent = static_cast<void*>(
        CreateEventW(nullptr, TRUE, FALSE, nullptr)  /* manual-reset, not signaled */
    );
#endif
}

WindowsDriverTransport::~WindowsDriverTransport() {
    (void)disconnect();
#if defined(_WIN32)
    if (m_shutdownEvent != nullptr) {
        CloseHandle(static_cast<HANDLE>(m_shutdownEvent));
        m_shutdownEvent = nullptr;
    }
#endif
}

/* =========================================================================
 * connect()
 * ========================================================================= */

SentinalStatus WindowsDriverTransport::connect() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_state == TransportState::Connected) {
        return SENTINAL_STATUS_SUCCESS;
    }

    m_state = TransportState::Connecting;

    /*
     * Reset the shutdown event so a new receive session can start cleanly
     * after a prior disconnect (reconnect support).
     */
#if defined(_WIN32)
    if (m_shutdownEvent != nullptr) {
        ResetEvent(static_cast<HANDLE>(m_shutdownEvent));
    }
#endif

    void* handle = nullptr;
    SentinalStatus status = m_device->connectPort(
        L"\\SentinalAI\\ProtectionPort", &handle
    );

    if (status != SENTINAL_STATUS_SUCCESS) {
        m_state = TransportState::Disconnected;
        m_handle = nullptr;
        return status;
    }

    m_handle = handle;
    m_state = TransportState::Connected;
    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * disconnect()
 *
 * Safe sequence — see file-level comment for the full proof.
 * ========================================================================= */

SentinalStatus WindowsDriverTransport::disconnect() {
    /*
     * Step 1: Atomically transition to Disconnecting and capture the handle.
     * m_handle is cleared here so subsequent receiveAndReply() calls that
     * check after acquiring m_receiveMutex will see nullptr and return
     * ACCESS_DENIED instead of using a closed handle.
     */
    void* capturedHandle = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == TransportState::Disconnected) {
            return SENTINAL_STATUS_SUCCESS; /* idempotent */
        }
        m_state = TransportState::Disconnecting;
        capturedHandle = m_handle;
        m_handle = nullptr;
    }
    /* m_mutex released — receiveAndReply() can now observe Disconnecting */

    /*
     * Step 2: Signal shutdown to unblock any active FilterGetMessage.
     * DefaultFilterPortDevice::getKernelMessage() observes this via
     * WaitForMultipleObjects, calls CancelIoEx, and returns ACCESS_DENIED.
     * receiveAndReply() then returns and releases m_receiveMutex.
     */
#if defined(_WIN32)
    if (m_shutdownEvent != nullptr) {
        SetEvent(static_cast<HANDLE>(m_shutdownEvent));
    }
#endif

    /*
     * Step 3: Wait for any active receiveAndReply() to complete.
     * This guarantees that capturedHandle is no longer used by any receive
     * operation before we close it in step 4.
     *
     * This cannot deadlock because:
     *   - m_mutex is NOT held here (released in step 1).
     *   - m_shutdownEvent is signaled (step 2), so getKernelMessage()
     *     will cancel its IO and return, allowing receiveAndReply() to
     *     release m_receiveMutex.
     */
    {
        std::lock_guard<std::mutex> receiveLock(m_receiveMutex);
        /* no body needed — acquiring the lock is the synchronization point */
    }

    /*
     * Step 4: Close the captured handle.
     * Safe: receiveAndReply() has released m_receiveMutex (step 3 completed),
     * confirming it is no longer using capturedHandle.
     */
    if (capturedHandle != nullptr) {
        m_device->closePort(capturedHandle);
    }

    /*
     * Step 5: Reset shutdown event for reconnect support.
     * connect() also resets this, but resetting here keeps the invariant
     * that m_shutdownEvent is non-signaled while disconnected.
     */
#if defined(_WIN32)
    if (m_shutdownEvent != nullptr) {
        ResetEvent(static_cast<HANDLE>(m_shutdownEvent));
    }
#endif

    /*
     * Step 6: Mark as fully disconnected.
     */
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = TransportState::Disconnected;
    }

    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * isConnected() / state()
 * ========================================================================= */

bool WindowsDriverTransport::isConnected() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return (m_state == TransportState::Connected && m_handle != nullptr);
}

TransportState WindowsDriverTransport::state() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

/* =========================================================================
 * exchange() — USER -> KERNEL via FilterSendMessage
 *
 * Holds m_mutex for the duration. FilterSendMessage invokes the kernel
 * MessageNotifyCallback synchronously and returns; this is bounded and
 * not a deadlock concern with disconnect() because disconnect() releases
 * m_mutex in step 1 of its sequence before waiting on m_receiveMutex.
 * ========================================================================= */

SentinalStatus WindowsDriverTransport::exchange(
    const SentinalDriverProtectionRequest& request,
    SentinalDriverProtectionResponse& outResponse
) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_state != TransportState::Connected || m_handle == nullptr) {
        return SENTINAL_STATUS_ACCESS_DENIED;
    }

    SentinalStatus status = SentinalDriverValidateProtectionRequest(&request);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    /* Convert ANSI request to Unicode contract for kernel transport */
    SentinalDriverUnicodeProtectionRequest uniReq;
    std::memset(&uniReq, 0, sizeof(uniReq));

    uniReq.header.size         = static_cast<uint32_t>(sizeof(uniReq));
    uniReq.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    uniReq.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    uniReq.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_REQUEST;
    uniReq.header.reserved     = 0;

    uniReq.requestId  = request.requestId;
    uniReq.operation  = request.operation;
    uniReq.source     = request.source;
    uniReq.pathLength = request.pathLength;
    uniReq.reserved0  = 0;

    for (uint32_t i = 0; i < request.pathLength; ++i) {
        uniReq.path[i] = static_cast<uint16_t>(request.path[i]);
    }
    uniReq.path[request.pathLength] = 0x0000u;
    uniReq.reserved  = 0;
    uniReq.reserved1 = 0;

    SentinalDriverUnicodeProtectionResponse uniResp;
    std::memset(&uniResp, 0, sizeof(uniResp));
    uint32_t bytesReturned = 0;

    status = m_device->sendMessage(
        m_handle,
        &uniReq,
        static_cast<uint32_t>(sizeof(uniReq)),
        &uniResp,
        static_cast<uint32_t>(sizeof(uniResp)),
        &bytesReturned
    );

    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (bytesReturned != sizeof(uniResp)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    status = SentinalDriverUnicodeValidateProtectionResponse(&uniResp);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (uniResp.requestId != request.requestId) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalDriverProtectionResponse resp;
    std::memset(&resp, 0, sizeof(resp));

    resp.header.size         = static_cast<uint32_t>(sizeof(resp));
    resp.header.majorVersion = SENTINAL_DRIVER_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = SENTINAL_DRIVER_CONTRACT_MINOR_VERSION;
    resp.header.messageType  = SENTINAL_DRIVER_MESSAGE_PROTECTION_RESPONSE;
    resp.header.reserved     = 0;

    resp.requestId = uniResp.requestId;
    resp.decision  = uniResp.decision;
    resp.status    = uniResp.status;
    resp.reserved  = 0;

    outResponse = resp;
    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * exchangeUnicode() — USER -> KERNEL via FilterSendMessage, Unicode ABI
 * ========================================================================= */

SentinalStatus WindowsDriverTransport::exchangeUnicode(
    const SentinalDriverUnicodeProtectionRequest& request,
    SentinalDriverUnicodeProtectionResponse& outResponse
) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_state != TransportState::Connected || m_handle == nullptr) {
        return SENTINAL_STATUS_ACCESS_DENIED;
    }

    SentinalStatus status = SentinalDriverUnicodeValidateProtectionRequest(&request);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    SentinalDriverUnicodeProtectionResponse uniResp;
    std::memset(&uniResp, 0, sizeof(uniResp));
    uint32_t bytesReturned = 0;

    status = m_device->sendMessage(
        m_handle,
        &request,
        static_cast<uint32_t>(sizeof(request)),
        &uniResp,
        static_cast<uint32_t>(sizeof(uniResp)),
        &bytesReturned
    );

    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (bytesReturned != sizeof(uniResp)) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    status = SentinalDriverUnicodeValidateProtectionResponse(&uniResp);
    if (status != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    if (uniResp.requestId != request.requestId) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    outResponse = uniResp;
    return SENTINAL_STATUS_SUCCESS;
}

/* =========================================================================
 * receiveAndReply() — KERNEL -> USER via FilterGetMessage + FilterReplyMessage
 *
 * Mutex discipline:
 *   m_receiveMutex  held for entire function (one receive at a time)
 *   m_mutex         held BRIEFLY (state check + handle capture only)
 *   m_mutex         NOT held during FilterGetMessage
 *
 * Handle lifetime guarantee:
 *   capturedHandle is valid for the entire function because disconnect()
 *   cannot close it until AFTER m_receiveMutex is released here (RAII
 *   at function exit), which is AFTER getKernelMessage() and
 *   replyToKernel() have both completed.
 *
 * Development transport behavior:
 *   Response decision = ALLOW is a transport-test stub only.
 *   It is NOT connected to enforcement. Policy integration is a later phase.
 * ========================================================================= */

SentinalStatus WindowsDriverTransport::receiveAndReply(
    SentinalDriverUnicodeProtectionRequest*  outRequest,
    SentinalDriverUnicodeProtectionResponse* outResponse
) {
    /*
     * Step 1: Acquire receive serialization lock.
     * Only one receiveAndReply() runs at a time.
     * disconnect() waits on this lock (after signaling shutdown) to
     * guarantee the handle is not in use before it is closed.
     */
    std::lock_guard<std::mutex> receiveLock(m_receiveMutex);

    /*
     * Step 2: Brief state check — capture handle, verify connected.
     * m_mutex is acquired and released here. It is NOT held below.
     *
     * After this block, disconnect() can freely modify m_state and m_handle.
     * The captured handle remains valid because disconnect() waits on
     * m_receiveMutex (step 1 above) before closing it.
     */
    void* capturedHandle;
    {
        std::lock_guard<std::mutex> stateLock(m_mutex);
        if (m_state != TransportState::Connected || m_handle == nullptr) {
            return SENTINAL_STATUS_ACCESS_DENIED;
        }
        capturedHandle = m_handle;
    }
    /* m_mutex released — disconnect() can now set m_state / m_handle */

    /*
     * Step 3: Receive the kernel-originated message.
     *
     * m_mutex is NOT held during this blocking call.
     *
     * If disconnect() signals m_shutdownEvent, getKernelMessage() cancels
     * the overlapped FilterGetMessage via CancelIoEx and returns
     * SENTINAL_STATUS_ACCESS_DENIED. We then propagate that failure
     * and return before touching the handle further.
     *
     * Buffer layout (msgBuf):
     *   [SentinalFltMessageHeader (16)]                   — FM transport
     *   [SentinalDriverUnicodeProtectionRequest (2096)]   — application ABI
     *   total: 2112 bytes
     */
    SentinalKernelMessageBuffer msgBuf;
    std::memset(&msgBuf, 0, sizeof(msgBuf));

    SentinalStatus status = m_device->getKernelMessage(
        capturedHandle,
        &msgBuf,
        static_cast<uint32_t>(sizeof(msgBuf)),
        m_shutdownEvent          /* signals cancellation on disconnect() */
    );

    if (status != SENTINAL_STATUS_SUCCESS) {
        /* Transport failure or shutdown — NEVER convert to ALLOW */
        return status;
    }

    /*
     * Step 4: Validate the received application payload.
     * The FM transport header (msgBuf.header) is metadata; we validate
     * only the application ABI payload.
     * A malformed request receives NO reply (we return without calling
     * FilterReplyMessage so the kernel's FltSendMessage will time out).
     */
    SentinalStatus validationStatus =
        SentinalDriverUnicodeValidateProtectionRequest(&msgBuf.payload);
    if (validationStatus != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_INVALID_PARAMETER;
    }

    /*
     * Step 5: Construct deterministic development response.
     *
     * Development transport behavior only — ALLOW is a transport-test stub.
     * This response is NOT connected to enforcement or policy evaluation.
     * Production policy integration is a later phase.
     * ponytail: transport stub; upgrade path = real policy engine phase.
     */
    SentinalDriverUnicodeProtectionResponse resp;
    std::memset(&resp, 0, sizeof(resp));

    resp.header.size         = static_cast<uint32_t>(sizeof(resp));
    resp.header.majorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MAJOR_VERSION;
    resp.header.minorVersion = SENTINAL_DRIVER_UNICODE_CONTRACT_MINOR_VERSION;
    resp.header.messageType  = SENTINAL_DRIVER_UNICODE_MESSAGE_PROTECTION_RESPONSE;
    resp.header.reserved     = 0;

    resp.requestId = msgBuf.payload.requestId; /* echo exactly */
    resp.decision  = static_cast<uint32_t>(SENTINAL_DECISION_ALLOW);
    resp.status    = static_cast<uint32_t>(SENTINAL_STATUS_SUCCESS);
    resp.reserved  = 0;
    resp.reserved1 = 0;

    /* Step 6: Validate response before sending — never send an invalid response */
    validationStatus = SentinalDriverUnicodeValidateProtectionResponse(&resp);
    if (validationStatus != SENTINAL_STATUS_SUCCESS) {
        return SENTINAL_STATUS_UNSPECIFIED_ERROR;
    }

    /*
     * Step 7: Build reply buffer.
     *
     * Layout (replyBuf):
     *   [SentinalFltReplyHeader (16)]                      — FM transport
     *   [SentinalDriverUnicodeProtectionResponse (40)]     — application ABI
     *   total: 56 bytes
     *
     * header.messageId must equal msgBuf.header.messageId so Filter Manager
     * can correlate this reply to the correct FltSendMessage call in kernel.
     * header.status = 0 (STATUS_SUCCESS) for the transport layer.
     */
    SentinalReplyBuffer replyBuf;
    std::memset(&replyBuf, 0, sizeof(replyBuf));
    replyBuf.header.messageId = msgBuf.header.messageId; /* FM correlation */
    replyBuf.header.status    = 0;                        /* STATUS_SUCCESS */
    replyBuf.payload          = resp;

    /*
     * Step 8: Send reply to kernel.
     * capturedHandle is still valid here (disconnect() is waiting on
     * m_receiveMutex which we hold until this function returns).
     */
    status = m_device->replyToKernel(
        capturedHandle,
        &replyBuf,
        static_cast<uint32_t>(sizeof(replyBuf))
    );

    if (status != SENTINAL_STATUS_SUCCESS) {
        return status;
    }

    if (outRequest  != nullptr) *outRequest  = msgBuf.payload;
    if (outResponse != nullptr) *outResponse = resp;

    return SENTINAL_STATUS_SUCCESS;
    /* m_receiveMutex released here (RAII) — disconnect() may now proceed to close handle */
}

} // namespace sentinel::service
