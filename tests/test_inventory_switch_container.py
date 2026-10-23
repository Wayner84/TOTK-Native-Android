import os
import struct
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from inventory_switch_container import FormatError, inventory


def pfs0(entries):
    names = bytearray()
    records = bytearray()
    data = bytearray()
    for name, payload in entries:
        name_offset = len(names)
        names += name.encode("utf-8") + b"\0"
        records += struct.pack("<QQII", len(data), len(payload), name_offset, 0)
        data += payload
    return b"PFS0" + struct.pack("<III", len(entries), len(names), 0) + records + names + data


class InventoryTests(unittest.TestCase):
    def write(self, payload):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".nsp")
        handle.write(payload)
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))
        return Path(handle.name)

    def test_lists_valid_pfs0_without_extraction(self):
        path = self.write(pfs0([("a.nca", b"abc"), ("b.cnmt.nca", b"12345")]))
        result = inventory(path)
        self.assertEqual("PFS0", result["container"]["format"])
        self.assertEqual(["a.nca", "b.cnmt.nca"], [x["name"] for x in result["container"]["files"]])
        self.assertEqual([3, 5], [x["size"] for x in result["container"]["files"]])

    def test_rejects_out_of_bounds_entry(self):
        payload = bytearray(pfs0([("a.nca", b"abc")]))
        struct.pack_into("<Q", payload, 24, 9999)
        with self.assertRaises(FormatError):
            inventory(self.write(payload))

    def test_rejects_unsafe_name(self):
        with self.assertRaises(FormatError):
            inventory(self.write(pfs0([("../escape", b"abc")])))

    def test_rejects_unterminated_name(self):
        payload = bytearray(pfs0([("abc", b"x")]))
        header_string_end = 16 + 24 + len("abc")
        payload[header_string_end] = ord("X")
        with self.assertRaises(FormatError):
            inventory(self.write(payload))

    def test_reads_bounded_cnmt_xml_metadata(self):
        xml = (b'<?xml version="1.0"?><ContentMeta><Type>Patch</Type>'
               b'<Id>0x0100</Id><Version>720896</Version><OriginalId>0x0001</OriginalId>'
               b'<Content><Type>Program</Type><Id>abcd</Id><Size>4</Size></Content>'
               b'</ContentMeta>')
        result = inventory(self.write(pfs0([("meta.cnmt.xml", xml)])))
        self.assertEqual("Patch", result["content_meta"]["type"])
        self.assertEqual("720896", result["content_meta"]["version"])
        self.assertEqual("Program", result["content_meta"]["contents"][0]["type"])

    def test_rejects_multiple_cnmt_xml_records(self):
        xml = b"<ContentMeta/>"
        with self.assertRaises(FormatError):
            inventory(self.write(pfs0([("a.cnmt.xml", xml), ("b.cnmt.xml", xml)])))


if __name__ == "__main__":
    unittest.main()
