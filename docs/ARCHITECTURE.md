# Sentinal AI Architecture

## High-Level Architecture

                    SENTINAL AI
                         |
          +--------------+--------------+
          |              |              |
      Desktop        Service          AI
       UI           Security Core     Engine
          |              |              |
          +--------------+--------------+
                         |
                    Secure IPC
                         |
                SentinelGuard.sys
                    Kernel Layer
                         |
                Windows File System

## Components

### SentinelGuard.sys

Responsibilities:

- Observe protected file-system operations
- Enforce protected path policies
- Allow or deny file operations
- Report security events to SentinelService

### SentinelService

Responsibilities:

- Manage security policies
- Maintain protected targets
- Communicate with the kernel driver
- Coordinate authentication
- Process security events
- Manage incident records
- Manage evidence
- Coordinate alarms
- Maintain service health

### Sentinel Desktop

Responsibilities:

- Initial setup
- Administrator enrollment
- File/folder selection
- Security policy configuration
- Dashboard
- Incident viewer
- Recovery
- Settings

### Sentinel AI

Responsibilities:

- Face enrollment
- Face authentication
- Liveness detection
- Behavioral anomaly analysis

## Protection Targets

Sentinal supports:

- Individual files
- Multiple files
- Entire folders
- Recursive folder protection

Folder protection should automatically cover eligible new files created inside a protected directory.

## Security Boundary

The kernel driver is responsible for final file-system enforcement.

User-mode components must not be treated as the ultimate security boundary.

## Development Rule

Every security feature must be:

1. Implemented
2. Tested
3. Attempted to bypass
4. Documented

A feature is not considered complete merely because the normal use case works.