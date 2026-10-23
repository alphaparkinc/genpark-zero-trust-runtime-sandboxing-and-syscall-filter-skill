"""Zero-Trust Runtime Sandboxing & Syscall Filter.
100% Python Standard Library.
"""

class ZeroTrustSyscallFilter:
    """Enforces strict syscall whitelisting and egress IP block checks for sandboxed code execution."""

    ALLOWED_SYSCALLS = {"read", "write", "openat", "close", "fstat", "mmap", "exit_group"}
    BLOCKED_SYSCALLS = {"ptrace", "sys_chroot", "mount", "setuid", "reboot", "init_module"}

    @classmethod
    def evaluate_sandbox_calls(cls, syscall_log: list, egress_ips: list, allowed_cidrs: list = ["10.0.0.0/8"]) -> dict:
        violations = []
        for call in syscall_log:
            name = call.get("syscall", "")
            if name in cls.BLOCKED_SYSCALLS:
                violations.append(f"Blocked high-risk syscall detected: '{name}'")
            elif name not in cls.ALLOWED_SYSCALLS:
                violations.append(f"Non-whitelisted syscall detected: '{name}'")

        disallowed_egress = []
        for ip in egress_ips:
            if not ip.startswith("10."):
                disallowed_egress.append(ip)

        is_safe = len(violations) == 0 and len(disallowed_egress) == 0
        return {
            "sandbox_secure": is_safe,
            "violations_count": len(violations) + len(disallowed_egress),
            "syscall_violations": violations,
            "disallowed_egress_ips": disallowed_egress
        }
