import hashlib, json, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import build_entry_binding as source
import build_entry_binding_transport as transport


def fixture():
    d={'schema':source.SCHEMA,'version':source.VERSION,'module_count':3,'module_order':list(source.ORDER),
       'trusted_manifest_sha256':'11'*32,'relocation_stream_sha256':'22'*32,'modules':[],'entries':{},'self_digest':''}
    for i,n in enumerate(source.ORDER):
        d['modules'].append({'module':n,'image_size':0x1000+i*0x1000,'writable_begin':0x800,'writable_size':0x100,
          'dt_init':0x100,'init_array':None,'ctor_flag':0x820,'carrier_size':100+i,'carrier_sha256':f'{i+1:064x}'})
    d['entries']={'nn_init_start':{'provider_id':2,'offset':0x200,'identity_source':'verified-elf-linkage'},'nn_main':{'provider_id':0,'offset':0x300,'identity_source':'verified-elf-linkage'}}
    p=dict(d); p.pop('self_digest'); d['self_digest']=source.sha(source.canonical(p)); return d

class TransportTests(unittest.TestCase):
    def setUp(self): self.doc=fixture(); self.raw=transport.pack(self.doc)
    def mutate(self, offset, value):
        b=bytearray(self.raw); b[offset:offset+len(value)]=value; b[transport.PAYLOAD_SIZE:]=hashlib.sha256(b[:transport.PAYLOAD_SIZE]).digest(); return bytes(b)
    def redigest(self, doc):
        p=dict(doc); p.pop('self_digest'); doc['self_digest']=source.sha(source.canonical(p)); return doc
    def module_offset(self, index, field):
        offset = field if isinstance(field, int) else getattr(transport, field)
        return transport.HEADER_SIZE + index*transport.MODULE_SIZE + offset
    def test_deterministic(self): self.assertEqual(self.raw,transport.pack(self.doc))
    def test_round_trip(self): self.assertTrue(transport.validate_bytes(self.raw))
    def test_exact_length(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.raw+b'x')
    def test_magic(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(0,b'BADMAGIC'))
    def test_version(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(8,(2).to_bytes(2,'little')))
    def test_header_reserved(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(10,b'\1\0'))
    def test_count(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(12,(2).to_bytes(4,'little')))
    def test_total(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(16,(1).to_bytes(4,'little')))
    def test_payload_digest(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.raw[:-1]+bytes([self.raw[-1]^1]))
    def test_header_identity(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(20,b'\0'*32))
    def test_module_role(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(transport.HEADER_SIZE,b'\7'))
    def test_module_reserved(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(transport.HEADER_SIZE+2,b'\1\0'))
    def test_module_digest(self):
        off=self.module_offset(0, 'MODULE_CARRIER_DIGEST_OFFSET')
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\0'*32))
    def test_module_image(self):
        off=transport.HEADER_SIZE+4
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\0'*8))
    def test_writable_overflow(self):
        off=transport.HEADER_SIZE+12
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(0xffffffffffffffff).to_bytes(8,'little')))
    def test_dt_alignment(self):
        off=transport.HEADER_SIZE+28
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(3).to_bytes(8,'little')))
    def test_ctor_alignment(self):
        off=transport.HEADER_SIZE+36
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(0x821).to_bytes(8,'little')))
    def test_init_array_present(self):
        d=fixture(); d['modules'][0]['init_array']={'offset':0x400,'size':8}; p=dict(d); p.pop('self_digest'); d['self_digest']=source.sha(source.canonical(p)); self.assertTrue(transport.validate_bytes(transport.pack(d)))
    def test_init_array_alignment(self):
        d=fixture(); d['modules'][0]['init_array']={'offset':0x401,'size':8}; self.redigest(d)
        with self.assertRaises(ValueError): transport.pack(d)
    def test_init_array_range(self):
        d=fixture(); d['modules'][0]['init_array']={'offset':0x1000,'size':8}; self.redigest(d)
        with self.assertRaises(ValueError): transport.pack(d)
    def test_entry_provider(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\3'))
    def test_entry_reserved(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+1
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\1'))
    def test_entry_alignment(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+4
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(3).to_bytes(8,'little')))
    def test_entry_range(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+4
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(0x3000).to_bytes(8,'little')))
    def test_entry_order(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\0'))
    def test_trailing_bytes(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.raw+b'\0')
    def test_json_validate_only(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'binding.json'; p.write_bytes(source.canonical(self.doc)); transport.main(['--binding',str(p),'--validate-only'])
    def test_json_validate_does_not_binary_validate(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'binding.json'; p.write_bytes(source.canonical(self.doc))
            with self.assertRaises(ValueError): transport.validate_bytes(p.read_bytes())
    def test_binary_validate_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'x.bin'; p.write_bytes(self.raw); before=p.read_bytes(); transport.main(['--binding',str(p),'--validate-only']); self.assertEqual(before,p.read_bytes())
    def test_atomic_build(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'binding.json'; out=Path(td)/'x.bin'; src.write_bytes(source.canonical(self.doc)); transport.build(src,out); self.assertTrue(transport.validate_bytes(out.read_bytes())); self.assertEqual(list(Path(td).glob('x.bin.*')),[])
    def test_cli_output_required(self):
        with self.assertRaises(SystemExit): transport.main(['--binding','x.json'])
    def test_cli_validate_output_forbidden(self):
        with self.assertRaises(SystemExit): transport.main(['--binding','x.bin','--validate-only','--output','x'])
    def test_canonical_rejection_delegated(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'binding.json'; p.write_text(json.dumps(self.doc)+'\n')
            with self.assertRaises((ValueError, json.JSONDecodeError)): transport.main(['--binding',str(p),'--validate-only'])

    def test_header_identity_is_canonical_digest(self):
        self.assertEqual(self.raw[transport.HEADER_IDENTITY_OFFSET:transport.HEADER_IDENTITY_OFFSET+32], hashlib.sha256(source.canonical(self.doc)).digest())
    def test_header_identity_nonzero(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(transport.HEADER_IDENTITY_OFFSET,b'\0'*32))
    def test_exact_end_init_array_valid(self):
        d=fixture(); d['modules'][0]['init_array']={'offset':0xff8,'size':8}; self.redigest(d); self.assertTrue(transport.validate_bytes(transport.pack(d)))
    def test_zero_writable_rejected(self):
        b=self.mutate(self.module_offset(0, 12), b'\0'*8)
        with self.assertRaises(ValueError): transport.validate_bytes(b)
    def test_entry_identity_string(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+16
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'bad'+b'\0'*13))
    def test_entry_tail_reserved(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+32
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\1'))
    def test_entry_dt_alias(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+4
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(0x100).to_bytes(8,'little')))
    def test_entry_ctor_alias(self):
        off=transport.HEADER_SIZE+3*transport.MODULE_SIZE+4
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,(0x820).to_bytes(8,'little')))
    def test_module_tail_reserved(self):
        off=self.module_offset(0, transport.MODULE_SIZE-44)
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\1'))
    def test_module_relocation_reserved(self):
        off=self.module_offset(0, transport.MODULE_CARRIER_DIGEST_OFFSET+32)
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(off,b'\1'))
    def test_carrier_size_zero(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(self.module_offset(0, 60), b'\0'*8))
    def test_header_manifest_zero(self):
        with self.assertRaises(ValueError): transport.validate_bytes(self.mutate(20+32,b'\0'*32))
