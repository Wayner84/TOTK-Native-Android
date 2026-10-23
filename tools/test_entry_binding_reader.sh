#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"; out="$ROOT/build/host-tests/entry-binding-fixtures"; rm -rf "$out"; mkdir -p "$out"
python - "$(cygpath -w "$out")" <<'PY'
import hashlib, pathlib, struct, sys
out=pathlib.Path(sys.argv[1]); H=160; M=176; E=36; P=H+3*M+2*E; N=P+32
b=bytearray(P); struct.pack_into('<8sHHII',b,0,b'TOTK-EBT\0',1,0,3,N)
for off in (20,52,84,116): b[off:off+32]=bytes(range(1,33))
for i in range(3):
 o=H+i*M; struct.pack_into('<BBHQQQQQQQQ',b,o,i,i,0,0x1000,0x100,0x200,0x40,0x100,0x200,0x20,1); b[o+68:o+100]=bytes(range(1,33))
base=H+3*M
for i,(provider,offset) in enumerate(((2,0x80),(0,0x84))): struct.pack_into('<BBHQ',b,base+i*E,provider,0,0,offset); b[base+i*E+12:base+i*E+28]=b'verified-elf\0\0\0\0'
valid=bytes(b)+hashlib.sha256(b).digest(); (out/'valid').write_bytes(valid)
assert hashlib.sha256(b'').hexdigest()=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert hashlib.sha256(b'abc').hexdigest()=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

z=bytearray(valid); z[H+68:H+76]=b'\0'*8; z[H+76]=1; z[P:]=hashlib.sha256(z[:P]).digest(); (out/'carrier_digest_leading_zero').write_bytes(z)
def emit(name, mutate, digest=True):
 x=bytearray(valid); mutate(x)
 if digest: x[P:]=hashlib.sha256(x[:P]).digest()
 (out/name).write_bytes(x)
def u64(o,v): struct.pack_into('<Q',x,o,v)
for n,fn in [('payload_digest',lambda x:x.__setitem__(slice(P,P+1),b'X')),('magic',lambda x:x.__setitem__(0,ord('X'))),('version',lambda x:struct.pack_into('<H',x,8,2)),('version_reserved',lambda x:struct.pack_into('<H',x,10,1)),('count',lambda x:struct.pack_into('<I',x,12,2)),('total',lambda x:struct.pack_into('<I',x,16,1))]: emit(n,fn,n!='payload_digest')
trailing=bytearray(valid); trailing.extend(b'X'); (out/'trailing').write_bytes(trailing)
for i in range(4): emit(f'header_identity_{i}',lambda x,i=i:x.__setitem__(slice(20+32*i,52+32*i),b'\0'*32),True)
emit('header_reserved',lambda x:x.__setitem__(148,1))
for i in range(3): emit(f'carrier_digest_{i}',lambda x,i=i:x.__setitem__(slice(H+i*M+68,H+i*M+100),b'\0'*32))
for n,fn in [('module_role_0',lambda x:x.__setitem__(160,3)),('module_id_1',lambda x:x.__setitem__(337,2)),('module_reserved',lambda x:struct.pack_into('<H',x,162,1)),('module_tail',lambda x:x.__setitem__(292,1)),('module_identity',lambda x:x.__setitem__(260,1)),('carrier_size',lambda x:struct.pack_into('<Q',x,220,0)),('image_zero',lambda x:struct.pack_into('<Q',x,164,0)),('writable_zero',lambda x:struct.pack_into('<Q',x,180,0)),('writable_overflow',lambda x:struct.pack_into('<QQ',x,172,0xffffffffffffffff,2)),('writable_beyond',lambda x:struct.pack_into('<QQ',x,172,0x300,0x200)),('dt_zero',lambda x:struct.pack_into('<Q',x,188,0)),('dt_misaligned',lambda x:struct.pack_into('<Q',x,188,3)),('dt_out',lambda x:struct.pack_into('<Q',x,188,0x1000)),('ctor_misaligned',lambda x:struct.pack_into('<Q',x,196,3)),('ctor_before',lambda x:struct.pack_into('<Q',x,196,0x10)),('ctor_end',lambda x:struct.pack_into('<Q',x,196,0x300)),('init_mixed_zero_a',lambda x:struct.pack_into('<Q',x,204,0)),('init_mixed_zero_b',lambda x:struct.pack_into('<Q',x,212,0)),('init_alignment_offset',lambda x:struct.pack_into('<Q',x,204,3)),('init_alignment_size',lambda x:struct.pack_into('<Q',x,212,3)),('init_overflow',lambda x:struct.pack_into('<QQ',x,204,0xffffffffffffffff,8)),('init_beyond',lambda x:struct.pack_into('<QQ',x,204,0xff0,32))]: emit(n,fn)
for i in range(2):
 for n,fn in [(f'entry_provider_{i}',lambda x,i=i:x.__setitem__(base+i*E,3)),(f'entry_range_{i}',lambda x,i=i:struct.pack_into('<Q',x,base+i*E+4,0x1000)),(f'entry_alignment_{i}',lambda x,i=i:struct.pack_into('<Q',x,base+i*E+4,3)),(f'provider_policy_{i}',lambda x,i=i:x.__setitem__(base+i*E,0 if i==0 else 2)),(f'entry_identity_{i}',lambda x,i=i:x.__setitem__(base+i*E+12,ord('X'))),(f'entry_reserved_{i}',lambda x,i=i:x.__setitem__(base+i*E+1,1)),(f'entry_tail_{i}',lambda x,i=i:x.__setitem__(base+i*E+28,1))]: emit(n,fn)
for n,fn in [('dt_alias',lambda x:struct.pack_into('<Q',x,base+4,0x40)),('ctor_alias',lambda x:struct.pack_into('<Q',x,base+4,0x100)),('init_alias',lambda x:struct.pack_into('<Q',x,base+4,0x200)),('entry_distinction',lambda x:(x.__setitem__(base+E,2),struct.pack_into('<Q',x,base+E+4,0x80)))]: emit(n,fn)
for cut in (0,159,160,335,791): (out/f'truncated_{cut}').write_bytes(valid[:cut])
expected={'valid','carrier_digest_leading_zero'}
expected.update(f'truncated_{cut}' for cut in (0,159,160,335,791))
expected.update(['trailing','payload_digest','magic','version','version_reserved','count','total','header_reserved'])
expected.update(f'header_identity_{i}' for i in range(4))
expected.update(['module_role_0','module_id_1','module_reserved','module_tail','module_identity','carrier_size','carrier_digest_0','carrier_digest_1','carrier_digest_2','image_zero','writable_zero','writable_overflow','writable_beyond','dt_zero','dt_misaligned','dt_out','ctor_misaligned','ctor_before','ctor_end','init_mixed_zero_a','init_mixed_zero_b','init_alignment_offset','init_alignment_size','init_overflow','init_beyond','dt_alias','ctor_alias','init_alias','entry_distinction'])
expected.update(f'{kind}_{i}' for i in range(2) for kind in ('entry_provider','entry_range','entry_alignment','provider_policy','entry_identity','entry_reserved','entry_tail'))
if {p.name for p in out.iterdir()} != expected: raise SystemExit('fixture manifest mismatch')
PY
g++ -std=c++20 -DENTRY_BINDING_READER_TESTING -Wall -Wextra -Wpedantic -Werror -O0 \
  -static-libgcc -static-libstdc++ -Iandroid/src \
  android/src/entry_binding_reader.cpp tests/entry_binding_reader_test.cpp \
  -o build/host-tests/entry_binding_reader_test
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -O0 -Iandroid/src \
  -c android/src/entry_binding_reader.cpp \
  -o build/host-tests/entry_binding_reader.production.o
args=(build/host-tests/entry-binding-fixtures)
[[ -f private/entry-bindings/v143.entry-binding.bin ]] && \
  args+=(private/entry-bindings/v143.entry-binding.bin)
output=$(./build/host-tests/entry_binding_reader_test "${args[@]}")
printf '%s\n' "$output"
expected_checks=86
[[ "$output" != *"result=FAIL"* ]]
[[ "$(grep -c '^test=' <<< "$output")" -eq "$expected_checks" ]]
[[ "$output" == *"summary: $expected_checks checks, PASS"* ]]
