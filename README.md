# Sentinal AI

Sentinal AI is a Windows security system designed to protect user-selected files and folders through layered protection, identity verification, file-system monitoring, threat detection, incident response, and optional encryption.

## Project Goals

Sentinal AI is being developed as a production-oriented Windows security application with:

- Individual file protection
- Folder protection
- Real-time file-system monitoring
- Kernel-level enforcement
- Administrator face authentication
- Liveness verification
- Intruder evidence capture
- Security incident reporting
- Local and mobile alerts
- Security alarms
- File integrity monitoring
- Process-aware access policies
- AI-assisted anomaly detection
- Optional encrypted vault protection
- Recovery mechanisms

## Architecture

Sentinal AI is divided into several security layers:

1. SentinelGuard
   - Windows file-system minifilter
   - Security enforcement layer

2. SentinelService
   - Windows service
   - Policy engine
   - Event processing
   - Driver communication
   - Authentication coordination
   - Incident management

3. Sentinel Desktop
   - WinUI 3 desktop application
   - Configuration and dashboard

4. Sentinel AI
   - Face authentication
   - Liveness detection
   - Behavioral/anomaly analysis

5. Sentinel Mobile
   - Optional secure companion interface

## Development Status

Phase 0 - Development foundation

Phase 1 - User-mode protection engine

Phase 2 - Face authentication

Phase 3 - Intruder response

Phase 4 - Windows service

Phase 5 - Kernel minifilter

Phase 6 - Kernel/user-mode communication

Phase 7 - Encryption and vault

Phase 8 - AI security engine

Phase 9 - Security hardening

Phase 10 - Production packaging

## Security Principle

Sentinal AI follows a layered security model:

Kernel = enforce  
Service = coordinate and decide  
AI = analyze  
UI = present  
Installer = deploy

No single user-mode component should be the sole security boundary.