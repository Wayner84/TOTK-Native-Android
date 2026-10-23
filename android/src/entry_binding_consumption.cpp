#include "entry_binding_consumption.h"
#include "file_identity.h"
#include <cstring>
#include <limits>
namespace {
using U=std::uint64_t;
constexpr std::size_t kAuthoritativeModuleCount = kGuestModuleCount;
bool add(U a,U b,U& o){if(b>std::numeric_limits<U>::max()-a)return false;o=a+b;return true;}
bool guest_image(U base, U offset, U& result) { return add(base, offset, result); }
bool range(U a,U b,U p){return a<=p&&p<b;}
bool equal_entry(const PortableEntryBinding::Entry&a,const PortableEntryBinding::Entry&b){return a.provider==b.provider&&a.offset==b.offset;}
bool equal_binding(const PortableEntryBinding&a,const PortableEntryBinding&b){
 if(a.module_count!=b.module_count||a.trusted_manifest_digest!=b.trusted_manifest_digest||a.relocation_digest!=b.relocation_digest||a.source_self_digest!=b.source_self_digest||a.canonical_file_digest!=b.canonical_file_digest)return false;
 for(size_t i=0;i<kGuestModuleCount;i++){const auto&x=a.modules[i];const auto&y=b.modules[i];if(x.id!=y.id||x.image_size!=y.image_size||x.writable_begin!=y.writable_begin||x.writable_size!=y.writable_size||x.dt_init!=y.dt_init||x.ctor_flag!=y.ctor_flag||x.init_array!=y.init_array||x.init_array_size!=y.init_array_size||x.carrier_size!=y.carrier_size||x.carrier_digest!=y.carrier_digest)return false;}
 return equal_entry(a.nn_init_start,b.nn_init_start)&&equal_entry(a.nn_main,b.nn_main);
}
bool equal_stream(const RelocationStreamSummary&a,const RelocationStreamSummary&b){
 if(a.file_bytes!=b.file_bytes||a.module_count!=b.module_count||a.record_count!=b.record_count||a.abs64_count!=b.abs64_count||a.glob_dat_count!=b.glob_dat_count||a.jump_slot_count!=b.jump_slot_count||a.relative_count!=b.relative_count||a.rela_count!=b.rela_count||a.relr_count!=b.relr_count)return false;
 for(size_t i=0;i<relocation_stream_max_modules;i++){const auto&x=a.modules[i];const auto&y=b.modules[i];if(x.guest_offset!=y.guest_offset||x.image_size!=y.image_size||x.writable_begin!=y.writable_begin||x.writable_end!=y.writable_end||x.record_count!=y.record_count)return false;}return true;
}
bool equal_layout(const PrivateModuleSetLayout&a,const PrivateModuleSetLayout&b){
 if(a.module_count!=b.module_count||a.total_image_size!=b.total_image_size||a.total_file_bytes!=b.total_file_bytes||a.total_zero_fill!=b.total_zero_fill)return false;
 for(size_t i=0;i<private_module_count;i++){const auto&x=a.modules[i];const auto&y=b.modules[i];if(x.file_size!=y.file_size||x.segment_count!=y.segment_count||x.image_size!=y.image_size)return false;for(size_t j=0;j<private_elf_max_segments;j++){const auto&u=x.segments[j];const auto&v=y.segments[j];if(u.file_offset!=v.file_offset||u.virtual_address!=v.virtual_address||u.file_size!=v.file_size||u.memory_size!=v.memory_size||u.flags!=v.flags)return false;}}return true;
}
EntryBindingResult build(const PortableEntryBinding& b,const RelocationStreamSummary& s,const PrivateModuleSetLayout& l,U base,GuestStartupPlan& out){
 if(b.module_count!=kAuthoritativeModuleCount||s.module_count!=kAuthoritativeModuleCount||l.module_count!=kAuthoritativeModuleCount)return EntryBindingResult::invalid_count;
 if((base&3)!=0)return EntryBindingResult::alignment;
 GuestStartupInput in{}; in.module_count=3;
 for(size_t i=0;i<3;i++){
  const auto& bm=b.modules[i]; const auto& sm=s.modules[i]; const auto& lm=l.modules[i];
  if(bm.id!=static_cast<GuestModuleId>(i))return EntryBindingResult::invalid_order;
  if(bm.carrier_size!=lm.file_size)return EntryBindingResult::carrier_mismatch;
  if(bm.image_size!=lm.image_size)return EntryBindingResult::layout_mismatch;
  if(sm.image_size!=bm.image_size||sm.image_size!=lm.image_size)return EntryBindingResult::stream_mismatch;
  U wend=0,ib=0,ie=0,wb=0,we=0,dt=0,ctor=0,ia=0;
  if(!add(bm.writable_begin,bm.writable_size,wend)||wend>bm.image_size)return EntryBindingResult::metadata_mismatch;
  if(sm.writable_begin!=bm.writable_begin||sm.writable_end!=wend)return EntryBindingResult::stream_mismatch;
  if(!add(base,sm.guest_offset,ib)||!add(ib,sm.image_size,ie)||!add(ib,sm.writable_begin,wb)||!add(ib,sm.writable_end,we))return EntryBindingResult::overflow;
  if((ib&3)|| (bm.dt_init&3)||(bm.ctor_flag&3))return EntryBindingResult::alignment;
  if(!add(ib,bm.dt_init,dt)||!add(ib,bm.ctor_flag,ctor))return EntryBindingResult::overflow;
  if(bm.init_array_size){
   if((bm.init_array&7)||(bm.init_array_size&7))return EntryBindingResult::alignment;
   if(!add(ib,bm.init_array,ia))return EntryBindingResult::overflow;
   U ae=0; if(!add(ia,bm.init_array_size,ae)||ae==0)return EntryBindingResult::overflow;
   if(!range(wb,we,ia)||!range(wb,we,ae-1))return EntryBindingResult::containment;
  } else if (bm.init_array != 0) return EntryBindingResult::metadata_mismatch;
  if(!range(ib,ie,dt)||!range(wb,we,ctor))return EntryBindingResult::containment;
  auto& m=in.modules[i];m.id=bm.id;m.image_begin=ib;m.image_end=ie;m.writable_begin=wb;m.writable_end=we;m.dt_init=dt;m.ctor_flag=ctor;m.init_array=ia;m.init_array_size=bm.init_array_size;
 }
 // Keep offset arithmetic explicit and overflow-safe.
 auto make=[&](PortableEntryBinding::Entry e,U& dst)->EntryBindingResult{if(e.provider>=3)return EntryBindingResult::provider_mismatch;if(e.offset&3)return EntryBindingResult::alignment;if(e.offset>=s.modules[e.provider].image_size)return EntryBindingResult::containment;U p=0;if(!add(base,s.modules[e.provider].guest_offset,p)||!add(p,e.offset,dst))return EntryBindingResult::overflow;return range(in.modules[e.provider].image_begin,in.modules[e.provider].image_end,dst)?EntryBindingResult::ok:EntryBindingResult::containment;};
 in.nn_init_provider=b.nn_init_start.provider;in.nn_main_provider=b.nn_main.provider;auto r=make(b.nn_init_start,in.nn_init_start);if(r!=EntryBindingResult::ok)return r;r=make(b.nn_main,in.nn_main);if(r!=EntryBindingResult::ok)return r;
 if (guest_startup_plan_validate(in, &out) != GuestStartupResult::ok) {
  return EntryBindingResult::plan_validation;
 }
 return EntryBindingResult::ok;
}
}
#ifdef ENTRY_BINDING_CONSUMPTION_TESTING
EntryBindingResult test_admit_entry_binding(const PortableEntryBinding&b,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,std::uint64_t base,GuestStartupPlan&o){return build(b,s,l,base,o);}
#endif
bool entry_binding_capability_matches_mapping(const EntryBindingAdmissionCapability&c,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,U base){
 return c.admitted_&&c.guest_base_==base&&equal_stream(c.stream_,s)&&equal_layout(c.layout_,l);
}
bool entry_binding_capability_matches_consumption(const EntryBindingAdmissionCapability&c,const PortableEntryBinding&b,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,U base){
 return entry_binding_capability_matches_mapping(c,s,l,base)&&equal_binding(c.binding_,b);
}

EntryBindingResult admit_entry_binding_live(const PortableEntryBinding& b, std::FILE* const* files, std::FILE* relocation,
 const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,std::uint64_t base,GuestStartupPlan&o,EntryBindingAdmissionCapability& capability){
 capability = {};
 if (!files || !relocation) return EntryBindingResult::null_input;
 for (std::size_t i=0;i<kAuthoritativeModuleCount;++i) {
  if (!files[i]) return EntryBindingResult::null_input;
  std::uint64_t size=0; std::array<std::uint8_t,32> digest{};
  if (sha256_file_identity(files[i], b.modules[i].carrier_size, size, digest) != FileIdentityResult::ok) return EntryBindingResult::read_failed;
  if (size != b.modules[i].carrier_size || digest != b.modules[i].carrier_digest) return EntryBindingResult::carrier_mismatch;
 }
 std::uint64_t relocation_size=0; std::array<std::uint8_t,32> relocation_digest{};
 if (sha256_file_identity(relocation, s.file_bytes, relocation_size, relocation_digest) != FileIdentityResult::ok) return EntryBindingResult::read_failed;
 if (relocation_size != s.file_bytes || relocation_digest != b.relocation_digest) return EntryBindingResult::stream_mismatch;
 const auto result=build(b,s,l,base,o); if(result!=EntryBindingResult::ok)return result;
 capability.admitted_ = true; capability.binding_ = b; capability.stream_ = s; capability.layout_ = l; capability.guest_base_ = base;
 return EntryBindingResult::ok;
}
static EntryBindingResult consume_entry_binding_impl(const PortableEntryBinding&b,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,const RelocationDestinationModule*d,std::size_t n,std::uint64_t base,const GuestStartupPlan&p,EntryBindingObservation&o){
 if (!d) return EntryBindingResult::null_input;
 if (n != kAuthoritativeModuleCount) return EntryBindingResult::invalid_count;
 for (size_t i = 0; i < 3; i++) {
  const auto& x = d[i];
  U expected_image = 0;
  if (!guest_image(base, s.modules[i].guest_offset, expected_image)) return EntryBindingResult::overflow;
  if (x.image != reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(expected_image))) return EntryBindingResult::destination_mismatch;
  if (!x.mapped || !x.writable || x.executable) return EntryBindingResult::invalid_state;
  if (x.guest_offset != s.modules[i].guest_offset || x.image_size != s.modules[i].image_size ||
      x.writable_begin != s.modules[i].writable_begin || x.writable_end != s.modules[i].writable_end)
   return EntryBindingResult::destination_mismatch;
 }
 GuestStartupPlan c{};auto r=build(b,s,l,base,c);if(r!=EntryBindingResult::ok)return r;if(std::memcmp(&c,&p,sizeof c)!=0)return EntryBindingResult::plan_mismatch;if(guest_startup_plan_revalidate(&p)!=GuestStartupResult::ok)return EntryBindingResult::revalidation_failed;o={true,true,3};return EntryBindingResult::ok;
}
EntryBindingResult consume_admitted_entry_binding(const EntryBindingAdmissionCapability&capability,const PortableEntryBinding&b,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,const RelocationDestinationModule*d,std::size_t n,std::uint64_t base,const GuestStartupPlan&p,EntryBindingObservation&o){
 if(!entry_binding_capability_matches_consumption(capability,b,s,l,base))return EntryBindingResult::revalidation_failed;
 return consume_entry_binding_impl(b,s,l,d,n,base,p,o);
}
#ifdef ENTRY_BINDING_CONSUMPTION_TESTING
EntryBindingResult test_consume_entry_binding(const PortableEntryBinding&b,const RelocationStreamSummary&s,const PrivateModuleSetLayout&l,const RelocationDestinationModule*d,std::size_t n,std::uint64_t base,const GuestStartupPlan&p,EntryBindingObservation&o){return consume_entry_binding_impl(b,s,l,d,n,base,p,o);}
#endif
const char* entry_binding_result_name(EntryBindingResult r){switch(r){case EntryBindingResult::ok:return"ok";case EntryBindingResult::null_input:return"null_input";case EntryBindingResult::invalid_count:return"invalid_count";case EntryBindingResult::invalid_order:return"invalid_order";case EntryBindingResult::carrier_mismatch:return"carrier_mismatch";case EntryBindingResult::layout_mismatch:return"layout_mismatch";case EntryBindingResult::stream_mismatch:return"stream_mismatch";case EntryBindingResult::destination_mismatch:return"destination_mismatch";case EntryBindingResult::invalid_state:return"invalid_state";case EntryBindingResult::overflow:return"overflow";case EntryBindingResult::alignment:return"alignment";case EntryBindingResult::metadata_mismatch:return"metadata_mismatch";case EntryBindingResult::read_failed:return"read_failed";case EntryBindingResult::provider_mismatch:return"provider_mismatch";case EntryBindingResult::containment:return"containment";case EntryBindingResult::plan_validation:return"plan_validation";case EntryBindingResult::plan_mismatch:return"plan_mismatch";case EntryBindingResult::revalidation_failed:return"revalidation_failed";}return"unknown";}
