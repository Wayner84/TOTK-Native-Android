import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "tools" / "audit_android_thread_registers.py"
SPEC = importlib.util.spec_from_file_location("thread_register_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ThreadRegisterAuditTests(unittest.TestCase):
    def test_allows_x18_snapshot_read(self):
        self.assertIsNone(MODULE.audit_instruction("  10: aa1203e8  mov x8, x18"))

    def test_rejects_x18_write(self):
        self.assertIsNotNone(MODULE.audit_instruction("  10: aa0003f2  mov x18, x0"))
        self.assertIsNotNone(MODULE.audit_instruction("  14: f9400012  ldr x18, [x0]"))
        self.assertIsNotNone(MODULE.audit_instruction("  18: a9404c11  ldp x17, x18, [x0]"))
        self.assertIsNotNone(MODULE.audit_instruction("  1c: c8007c32  stxr w18, x0, [x1]"))
        self.assertIsNotNone(MODULE.audit_instruction("  20: f8008640  str x0, [x18], #8"))

    def test_allows_read_only_x18_store_operands(self):
        self.assertIsNone(MODULE.audit_instruction("  10: c8007c20  stxr w0, x18, [x1]"))
        self.assertIsNone(MODULE.audit_instruction("  14: f9000260  str x0, [x18]"))

    def test_allows_thread_pointer_snapshot_reads(self):
        self.assertIsNone(MODULE.audit_instruction("  10: d53bd048  mrs x8, TPIDR_EL0"))
        self.assertIsNone(MODULE.audit_instruction("  14: d53bd069  mrs x9, TPIDRRO_EL0"))

    def test_rejects_thread_pointer_writes(self):
        self.assertIsNotNone(MODULE.audit_instruction("  10: d51bd040  msr TPIDR_EL0, x0"))
        self.assertIsNotNone(MODULE.audit_instruction("  14: d51bd061  msr TPIDRRO_EL0, x1"))


if __name__ == "__main__":
    unittest.main()
