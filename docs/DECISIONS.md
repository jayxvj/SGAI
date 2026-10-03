# Architecture Decisions

## ADR-001: Windows File-System Minifilter

Status: Accepted

Sentinal AI will use a Windows file-system minifilter for security-critical file-system enforcement.

Reason:

User-mode polling alone is insufficient for a product that needs reliable file-system enforcement.

The minifilter will be responsible for observing and enforcing protected file operations.

---

## ADR-002: User Mode vs Kernel Mode

Status: Accepted

Security-critical enforcement stays in kernel mode.

Complex functionality such as:

- Face recognition
- Liveness detection
- AI inference
- Incident report generation
- UI
- Evidence presentation

remains in user mode.

Reason:

Keeping the kernel component small reduces complexity and limits the impact of driver defects.

---

## ADR-003: Protection Targets

Status: Accepted

Sentinal AI supports both:

- Individual files
- Folder-based protection

Folder protection is the primary scalable workflow.

---

## ADR-004: Face Authentication

Status: Accepted

Face authentication is a major Sentinal AI feature but is not itself the kernel enforcement mechanism.

Reason:

Identity verification and file-system enforcement have different responsibilities.