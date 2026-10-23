#!/usr/bin/env python3
"""Build and validate the private 1.4.3 entry binding (fail closed)."""
from __future__ import annotations
import argparse, hashlib, json, os, re, struct, tempfile
from pathlib import Path
import summarize_nso_linkage as linkage
from build_relocation_stream import validate_stream

ORDER=("main","subsdk0","sdk"); SCHEMA="totk-entry-binding-v1"; VERSION="1.4.3"
START="_ZN2nn4init5StartEmmPFvvES2_S2_"; MAIN="nnMain"; U64=(1<<64)-1
INIT=12; INIT_ARRAY=25; INIT_ARRAYSZ=27

def check(ok,msg):
    if not ok: raise ValueError(msg)
def integer(v,msg): check(type(v) is int and 0<=v<=U64,msg); return v
def digest(v,msg): check(type(v) is str and len(v)==64 and all(c in '0123456789abcdef' for c in v),msg)
def canonical(x): return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def sha(x): return hashlib.sha256(x).hexdigest()
def checked_end(begin,size,msg):
    integer(begin,msg); integer(size,msg)
    check(size <= U64 - begin,msg)
    return begin + size
def singleton(rows,tag,required=False):
    vals=[r[1] for r in rows if type(r) is list and len(r)==2 and r[0]==tag]
    check(len(vals)<=1 and (not required or len(vals)==1),f"dynamic tag {tag} duplicate or missing")
    return vals[0] if vals else None

def read_manifest(path):
    raw=Path(path).read_bytes(); check(raw.endswith(b'\n'),"manifest newline")
    rows=[]
    for line in raw.decode('utf-8').splitlines():
        p=line.split('\t'); check(len(p)==3,"manifest row shape")
        check(p[0] in (*ORDER,'relocations') and p[0] not in [r[0] for r in rows],"manifest row identity")
        check(re.fullmatch(r"(?:0|[1-9][0-9]*)",p[1],re.ASCII) is not None,"manifest size")
        digest(p[2],"manifest digest"); rows.append((p[0],int(p[1]),p[2]))
    check([r[0] for r in rows]==[*ORDER,'relocations'],"manifest order/row count")
    return raw,rows

def decode_ctor(mod,dt):
    off=linkage.virtual_to_file(mod['segments_private'],dt+16,8)
    with mod['elf_private'].open('rb') as f:
        f.seek(off); raw=f.read(8); check(len(raw)==8,"ctor truncated"); a,w=struct.unpack('<II',raw)
    check(a & 0x9f00001f == (0x90000000|19),"ctor ADRP")
    check(w & 0xffc003ff == (0xb9400008|(19<<5)),"ctor LDR")
    imm=((a>>29)&3)|(((a>>5)&0x7ffff)<<2); imm=(imm^(1<<20))-(1<<20)
    return ((dt+16)&~4095)+(imm<<12)+((w>>10)&0xfff)*4

def symbol(mod,name):
    found=[s for s in mod['exports_private'] if s['name']==name]
    check(len(found)==1 and found[0].get('defined') is True,f"symbol {name} missing/ambiguous/undefined")
    v=found[0]['value']; check(type(v) is int and v%4==0 and v!=0,"symbol alignment/value")
    image=max(s['address']+s['size']+s['extra'] for s in mod['segments_private'])
    check(0<v<image,"symbol provider range"); return v

def resolve_entry(mods,name,expected):
    """Resolve exactly as the authoritative first-definition planner does."""
    by={m['module']:m for m in mods}; selected=None
    for provider in ORDER:
        mod=by[provider]
        image=max(s['address']+s['size']+s['extra'] for s in mod['segments_private'])
        matches=[]
        for candidate in mod['exports_private']:
            if candidate.get('binding') not in (1,2,10) or candidate.get('value',0)>=image:
                continue
            if candidate.get('name')==name:
                matches.append(candidate)
        check(len(matches)<=1,f"symbol {name} ambiguous")
        if matches:
            check(selected is None,f"symbol {name} ambiguous")
            selected=(provider,matches[0],image)
        if selected is not None: break
    check(selected is not None,f"symbol {name} missing/undefined")
    provider,candidate,image=selected
    check(provider==expected,f"symbol {name} provider mismatch")
    check(candidate.get('defined') is True,"symbol definition is not approved")
    value=candidate.get('value'); check(type(value) is int and 0<value<image and value%4==0,"symbol identity/range/alignment")
    return value

def build(manifest,relocations,root):
    mb,rows=read_manifest(manifest); stream=validate_stream(Path(relocations))
    check(type(stream) is dict and stream.get('modules')==3,"stream return/module count")
    # validate_stream's public descriptors are intentionally required for geometry checks.
    check(isinstance(stream.get('descriptors'),list) and len(stream['descriptors'])==3,"stream descriptors unavailable")
    mods=[linkage.load_module(root,n) for n in ORDER]
    by={m['module']:m for m in mods}; carriers=rows[:3]; relrow=rows[3]
    relbytes=Path(relocations).read_bytes(); check((relrow[1],relrow[2])==(len(relbytes),sha(relbytes)),"relocation carrier mismatch")
    out={'schema':SCHEMA,'version':VERSION,'module_count':3,'module_order':list(ORDER),'trusted_manifest_sha256':sha(mb),'relocation_stream_sha256':sha(relbytes),'modules':[],'entries':{}}
    for idx,(name,size,digest0) in enumerate(carriers):
        mod=by[name]; carrier=Path(root,f'{name}.elf'); cb=carrier.read_bytes(); check((size,digest0)==(len(cb),sha(cb)),f"carrier mismatch {name}")
        image=max(s['address']+s['size']+s['extra'] for s in mod['segments_private']); data=mod['segments_private'][2]; wb=data['address']; initialized_we=wb+data['size']; ws=data['size']+data['extra']; we=wb+ws
        desc=stream['descriptors'][idx]; check(desc[0]==idx and desc[3]==image and desc[4]==wb and desc[5]==we and desc[2]==linkage.MODULE_LAYOUT_START+idx*linkage.MODULE_SLOT_SIZE,"stream geometry mismatch")
        dt=singleton(mod['dynamic_private'],INIT,True); ia=singleton(mod['dynamic_private'],INIT_ARRAY); ias=singleton(mod['dynamic_private'],INIT_ARRAYSZ)
        check(ia is None and ias is None or (ia is not None and ias is not None),"init-array canonical absence")
        if ia is not None: check(ia%8==0 and ias%8==0 and ias>0 and ia+ias<=image,"init-array geometry")
        ctor=decode_ctor(mod,dt); check(wb<=ctor<initialized_we and ctor%4==0,"ctor range")
        out['modules'].append({'module':name,'image_size':image,'writable_begin':wb,'writable_size':ws,'dt_init':dt,'init_array':None if ia is None else {'offset':ia,'size':ias},'ctor_flag':ctor,'carrier_size':size,'carrier_sha256':digest0})
    init=resolve_entry(mods,START,'sdk'); nn=resolve_entry(mods,MAIN,'main')
    out['entries']={'nn_init_start':{'provider_id':2,'offset':init,'identity_source':'verified-elf-linkage'},'nn_main':{'provider_id':0,'offset':nn,'identity_source':'verified-elf-linkage'}}
    out['self_digest']=sha(canonical(out)); validate(out); return out

def validate(doc):
    check(type(doc) is dict and set(doc)=={'schema','version','module_count','module_order','trusted_manifest_sha256','relocation_stream_sha256','modules','entries','self_digest'},"exact top-level keys")
    check(doc['schema']==SCHEMA and doc['version']==VERSION and doc['module_count']==3 and doc['module_order']==list(ORDER),"schema/version/order")
    for k in ('trusted_manifest_sha256','relocation_stream_sha256','self_digest'): digest(doc[k],k)
    check(type(doc['modules']) is list and len(doc['modules'])==3,"modules")
    for i,m in enumerate(doc['modules']):
        check(type(m) is dict and set(m)=={'module','image_size','writable_begin','writable_size','dt_init','init_array','ctor_flag','carrier_size','carrier_sha256'},"module keys")
        check(m['module']==ORDER[i],"module identity")
        for k in ('image_size','writable_begin','writable_size','dt_init','ctor_flag','carrier_size'): integer(m[k],k)
        digest(m['carrier_sha256'],'carrier sha')
        check(m['image_size']>0 and m['carrier_size']>0 and m['writable_size']>0,"nonempty module geometry")
        writable_end=checked_end(m['writable_begin'],m['writable_size'],"writable bounds")
        check(writable_end<=m['image_size'],"writable bounds")
        check(m['dt_init']>0 and m['dt_init']%4==0 and m['dt_init']<m['image_size'],"DT_INIT bounds")
        check(m['ctor_flag']%4==0 and m['writable_begin']<=m['ctor_flag']<writable_end,"ctor bounds")
        ia=m['init_array']
        if ia is not None:
            check(type(ia) is dict and set(ia)=={'offset','size'},"init-array keys")
            offset=integer(ia.get('offset'),"init-array offset"); size=integer(ia.get('size'),"init-array size")
            check(offset>0 and size>0 and offset%8==0 and size%8==0,"init-array alignment")
            check(checked_end(offset,size,"init-array overflow")<=m['image_size'],"init-array bounds")
    e=doc['entries']; check(type(e) is dict and set(e)=={'nn_init_start','nn_main'},"entries keys")
    for k,q in e.items():
        check(type(q) is dict and set(q)=={'provider_id','offset','identity_source'},k)
        provider=integer(q['provider_id'],f"{k} provider"); offset=integer(q['offset'],f"{k} offset")
        check(provider<3 and offset>0 and offset%4==0 and q['identity_source']=='verified-elf-linkage',k)
        m=doc['modules'][provider]; check(offset<m['image_size'],k)
        check(offset not in (m['dt_init'],m['ctor_flag']),f"{k} metadata alias")
        ia=m['init_array']
        check(ia is None or not (ia['offset']<=offset<ia['offset']+ia['size']),f"{k} init-array alias")
    check(e['nn_init_start']['provider_id']==2 and e['nn_main']['provider_id']==0,"entry providers")
    check(not (e['nn_init_start']['provider_id']==e['nn_main']['provider_id'] and e['nn_init_start']['offset']==e['nn_main']['offset']),"entry distinction")
    p=dict(doc); got=p.pop('self_digest'); check(got==sha(canonical(p)),"self digest"); return True

def read(path):
    b=Path(path).read_bytes(); check(b.endswith(b'\n') and b.count(b'\n')==1,"canonical framing"); x=json.loads(b); validate(x); check(canonical(x)==b,"noncanonical JSON"); return x

def atomic(path,x):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); fd,t=tempfile.mkstemp(dir=p.parent,prefix=p.name+'.')
    try:
        with os.fdopen(fd,'wb') as f: f.write(canonical(x)); f.flush(); os.fsync(f.fileno())
        os.replace(t,p)
        if os.name != 'nt':
            d=os.open(p.parent,os.O_RDONLY); os.fsync(d); os.close(d)
        read(p)
    finally:
        if os.path.exists(t): os.unlink(t)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--manifest',type=Path); ap.add_argument('--relocations',type=Path); ap.add_argument('--input',type=Path); ap.add_argument('--output',type=Path); ap.add_argument('--binding',type=Path); ap.add_argument('--validate-only',action='store_true'); a=ap.parse_args()
    if a.validate_only:
        check(a.binding is not None and all(x is None for x in (a.manifest,a.relocations,a.input,a.output)),"validate-only arguments")
        read(a.binding)
    else:
        check(all(x is not None for x in (a.manifest,a.relocations,a.input,a.output)),"build arguments")
        atomic(a.output,build(a.manifest,a.relocations,a.input))
    print('PASS: entry-binding validated; mapped=false executed=false')
if __name__=='__main__': main()
