/*
 * sentinal_driver_contract_adapter.h
 *
 * Kernel-side contract adapter: converts internal kernel observation events
 * into the shared SentinalDriverProtectionRequest contract.
 *
 * Phase 1.27 — Kernel Contract Adapter
 *
 * This header is kernel-mode only. C-compatible.
 */

#ifndef SENTINAL_DRIVER_CONTRACT_ADAPTER_H
#define SENTINAL_DRIVER_CONTRACT_ADAPTER_H

#include <fltKernel.h>
#include <sentinal/driver_contract.h>
#include "sentinal_observation_event.h"

#define SENTINAL_DRIVER_SOURCE_KERNEL 2U

/*
 * Converts a validated SENTINAL_OBSERVATION_EVENT into a
 * SentinalDriverProtectionRequest.
 *
 * Validates all inputs and ensures the resulting request conforms to
 * the shared contract. The caller's output buffer (Request) is
 * modified ONLY upon complete success.
 *
 * Safe for invocation at IRQL <= DISPATCH_LEVEL.
 * No memory allocation, no user-buffer access, no blocking.
 */
NTSTATUS
SentinalObservationToDriverRequest(
    _In_  const SENTINAL_OBSERVATION_EVENT* Event,
    _In_  ULONGLONG                         RequestId,
    _Out_ SentinalDriverProtectionRequest*  Request
);

#endif /* SENTINAL_DRIVER_CONTRACT_ADAPTER_H */
