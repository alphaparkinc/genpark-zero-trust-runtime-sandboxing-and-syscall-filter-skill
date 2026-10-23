"""Example usage for Zero-Trust Runtime Sandboxing & Syscall Filter."""
from client import ZeroTrustSyscallFilter

if __name__ == "__main__":
    res = ZeroTrustSyscallFilter.evaluate_sandbox_calls(
        [{"syscall": "read"}, {"syscall": "openat"}, {"syscall": "ptrace"}],
        ["10.0.1.5", "192.168.1.1"]
    )
    print("Sandbox Secure:", res["sandbox_secure"], "Violations:", res["violations_count"])
