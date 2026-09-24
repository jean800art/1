-- HD2-Addon: mods/lequla/ate_health_ammo
-- E/AT-12 only: max health 300 -> 3000 and magazine capacity 30 -> 300.
local ffi=require('ffi')
ffi.cdef[[
typedef void* HANDLE; typedef void* LPVOID; typedef unsigned long DWORD;
typedef unsigned long long SIZE_T; typedef unsigned long long uintptr_t;
typedef struct { LPVOID BaseAddress; LPVOID AllocationBase; DWORD AllocationProtect;
 SIZE_T RegionSize; DWORD State; DWORD Protect; DWORD Type; } MEMORY_BASIC_INFORMATION;
HANDLE OpenProcess(DWORD,int,DWORD); DWORD GetCurrentProcessId(void);
int ReadProcessMemory(HANDLE,const void*,void*,SIZE_T,SIZE_T*);
int WriteProcessMemory(HANDLE,void*,const void*,SIZE_T,SIZE_T*);
SIZE_T VirtualQuery(const void*,MEMORY_BASIC_INFORMATION*,SIZE_T);
int VirtualProtect(void*,SIZE_T,DWORD,DWORD*); int CloseHandle(HANDLE);
DWORD GetModuleFileNameA(HANDLE,char*,DWORD);
long BCryptOpenAlgorithmProvider(void**,const uint16_t*,const uint16_t*,DWORD);
long BCryptGetProperty(void*,const uint16_t*,uint8_t*,DWORD,DWORD*,DWORD);
long BCryptCreateHash(void*,void**,uint8_t*,DWORD,uint8_t*,DWORD,DWORD);
long BCryptHashData(void*,const uint8_t*,DWORD,DWORD);
long BCryptFinishHash(void*,uint8_t*,DWORD,DWORD);
long BCryptDestroyHash(void*); long BCryptCloseAlgorithmProvider(void*,DWORD);
]]

local NAME='ATE-HealthAmmo-v1'
if rawget(_G,NAME) then return end
local EXPECTED_EXE_SIZE=15160936
local EXPECTED_EXE_SHA256='D8E23968D1412B07E06785321727D63EDF74E711214D6F6ADEB3BFCA95CA6827'
local TARGET_ID='79C40E98E4C9112B' -- 0x2B11C9E4980EC479, little-endian
local SPECS={
 {name='health',hash=0xB3915DE3,stride=22096,max_size=20000000,offset=0,old=300,new=3000},
 {name='magazine',hash=0xFB8D88A3,stride=160,max_size=1000000,offset=136,old=30,new=300},
}
local state={phase='pending',frame=0,round=0,plans={},empty=0}
rawset(_G,NAME,state)
local k=ffi.load('kernel32')
local function unhex(s)return(s:gsub('%x%x',function(x)return string.char(tonumber(x,16))end))end
local function hex(s)return(s:gsub('.',function(c)return string.format('%02X',c:byte())end))end
local function u32(s,o)
 local a,b,c,d=s:byte(o+1,o+4);if not d then return nil end
 return a+b*256+c*65536+d*16777216
end
local function p32(n)return string.char(n%256,math.floor(n/256)%256,math.floor(n/65536)%256,math.floor(n/16777216)%256)end
local function addr(p)return tonumber(ffi.cast('uintptr_t',p))end
local proc,logfile,backupfile
local function note(s)
 s=string.format('[%s][frame %d][round %d] %s',os.date('%Y-%m-%d %H:%M:%S'),state.frame,state.round,tostring(s))
 print('['..NAME..'] '..s)
 if logfile then pcall(function()assert(logfile:write(s..'\n'));assert(logfile:flush())end)end
end
local function read(a,n)
 if not a or a<0x10000 or n<1 or n>524288 then return nil end
 local b,z=ffi.new('uint8_t[?]',n),ffi.new('SIZE_T[1]')
 if k.ReadProcessMemory(proc,ffi.cast('const void*',a),b,n,z)==0 or tonumber(z[0])~=n then return nil end
 return ffi.string(b,n)
end
local function replace(s,o,v)return s:sub(1,o)..v..s:sub(o+#v+1)end
local function header(at,t)
 local h=read(at,24)
 return h and h:sub(1,4)=='LDLD' and u32(h,4)==1 and u32(h,8)==t.hash and
  u32(h,12)>0 and u32(h,12)<=t.max_size and h:byte(17)==1
end
local function valid_record(t,r)
 if #r~=t.stride then return false end
 if t.name=='health' then
  local v=u32(r,t.offset)
  return v==t.old or v==t.new
 end
 return (u32(r,136)==30 or u32(r,136)==300) and u32(r,140)==0 and
  u32(r,144)==6 and u32(r,148)==0 and u32(r,152)==0 and r:byte(157)==1
end
local function resolve(at,t)
 assert(header(at,t),'table header mismatch')
 local size=u32(assert(read(at,24)),12)
 local hits={}
 local maxslots=math.min(8192,math.floor(size/16))
 for slots=1,maxslots do
  local rest=size-slots*16
  if rest>0 and rest%t.stride==0 then
   local count=rest/t.stride
   if slots>=count then
    local map=read(at+24,slots*16)
    if map then
     local n,index=0,nil
     local id=unhex(TARGET_ID)
     for o=0,slots*16-16,16 do
      if map:sub(o+1,o+8)==id then n=n+1;index=u32(map,o+8) end
     end
     if n==1 and index and index<count then
      local data=24+slots*16
      local record_at=at+data+index*t.stride
      local raw=read(record_at,t.stride)
      if raw and valid_record(t,raw) then
       hits[#hits+1]={name=t.name,at=at,size=size,slots=slots,count=count,stride=t.stride,
        data=data,index=index,map=map,address=record_at,original=raw,
        offset=t.offset,value=p32(t.new),spec=t}
      end
     end
    end
   end
  end
 end
 assert(#hits==1,'target layout not unique; candidates='..#hits)
 return hits[1]
end
local function guard_ok(p)
 if not header(p.at,p.spec) then return false end
 local map=read(p.at+24,p.slots*16)
 return map==p.map
end
local function write_pages(a,s)
 local offset=0
 while offset<#s do
  local at=a+offset;local n=math.min(#s-offset,4096-at%4096)
  local old,restored=ffi.new('DWORD[1]'),ffi.new('DWORD[1]')
  if k.VirtualProtect(ffi.cast('void*',at),n,4,old)==0 then return false,'protect failed' end
  local z=ffi.new('SIZE_T[1]')
  local ok,result=pcall(k.WriteProcessMemory,proc,ffi.cast('void*',at),ffi.cast('const void*',s:sub(offset+1,offset+n)),n,z)
  local restored_ok=k.VirtualProtect(ffi.cast('void*',at),n,tonumber(old[0]),restored)~=0
  if not restored_ok then restored_ok=k.VirtualProtect(ffi.cast('void*',at),n,tonumber(old[0]),restored)~=0 end
  if not restored_ok then return false,'restore protection failed' end
  if not ok or result==0 or tonumber(z[0])~=n then return false,'write failed or partial' end
  offset=offset+n
 end
 return true
end
local function apply(p)
 assert(guard_ok(p),'table unloaded or index changed')
 local raw=assert(read(p.address,p.stride),'record unreadable')
 assert(valid_record(p.spec,raw),'target record guard changed')
 local want=replace(p.original,p.offset,p.value)
 if raw==want then return false end
 assert(raw==p.original,'record differs from baseline; refusing write')
 assert(backupfile,'backup log unavailable')
 assert(backupfile:write(string.format('BACKUP %s table=0x%X record=0x%X length=%d original=%s\n',p.name,p.at,p.address,#raw,hex(raw))))
 assert(backupfile:flush(),'backup flush failed')
 assert(guard_ok(p) and read(p.address,#raw)==raw,'record changed after backup')
 local ok,why=write_pages(p.address+p.offset,p.value)
 if not ok or read(p.address,#raw)~=want then
  local rollback=write_pages(p.address+p.offset,raw:sub(p.offset+1,p.offset+#p.value))
  note('WRITE_FAILED '..p.name..' '..tostring(why)..' rollback='..tostring(rollback and read(p.address,#raw)==raw))
  error('write/readback failed')
 end
 note(string.format('APPLIED %s index=%d offset=0x%X %d->%d readback=PASS',p.name,p.index,p.offset,p.name=='health' and u32(raw,p.offset) or 30,p.name=='health' and 3000 or 300))
 return true
end
local function wide(s)
 local w=ffi.new('uint16_t[?]',#s+1);for i=1,#s do w[i-1]=s:byte(i) end;return w
end
local function verify_build(checkpoint)
 local pathbuf=ffi.new('char[32768]');local n=k.GetModuleFileNameA(nil,pathbuf,32768)
 assert(n>0 and n<32768,'executable path unavailable')
 local file=assert(io.open(ffi.string(pathbuf,n),'rb'),'cannot open executable')
 local bcrypt=ffi.load('bcrypt');local provider,hash=ffi.new('void*[1]'),ffi.new('void*[1]')
 local po,ho=false,false;local result
 local ok,why=pcall(function()
  assert(bcrypt.BCryptOpenAlgorithmProvider(provider,wide('SHA256'),nil,0)==0,'SHA256 unavailable');po=true
  local length,got=ffi.new('DWORD[1]'),ffi.new('DWORD[1]')
  assert(bcrypt.BCryptGetProperty(provider[0],wide('ObjectLength'),ffi.cast('uint8_t*',length),4,got,0)==0,'hash size unavailable')
  local obj=ffi.new('uint8_t[?]',tonumber(length[0]))
  assert(bcrypt.BCryptCreateHash(provider[0],hash,obj,tonumber(length[0]),nil,0,0)==0,'create hash failed');ho=true
  local total=0
  while true do
   local chunk=file:read(262144);if not chunk then break end
   total=total+#chunk;assert(bcrypt.BCryptHashData(hash[0],ffi.cast('const uint8_t*',chunk),#chunk,0)==0,'hash update failed');checkpoint()
  end
  local digest=ffi.new('uint8_t[32]');assert(bcrypt.BCryptFinishHash(hash[0],digest,32,0)==0,'finish hash failed')
  result=hex(ffi.string(digest,32));note('BUILD bytes='..total..' sha256='..result)
  assert(total==EXPECTED_EXE_SIZE and result==EXPECTED_EXE_SHA256,'unsupported executable; refusing writes')
 end)
 file:close();if ho then bcrypt.BCryptDestroyHash(hash[0]) end;if po then bcrypt.BCryptCloseAlgorithmProvider(provider[0],0) end
 assert(ok,why)
end
local function scan(checkpoint)
 state.round=state.round+1
 local regions,mbi={},ffi.new('MEMORY_BASIC_INFORMATION[1]');local cursor=0x100000000
 while cursor<0x7FFFFFFFFFFF do
  if k.VirtualQuery(ffi.cast('const void*',cursor),mbi,ffi.sizeof(mbi))==0 then break end
  local base,size=addr(mbi[0].BaseAddress),tonumber(mbi[0].RegionSize)
  if not base or not size or size<=0 or base+size<=cursor then break end
  local prot=tonumber(mbi[0].Protect)
  if tonumber(mbi[0].State)==0x1000 and prot%256~=1 and math.floor(prot/256)%2==0 then
   local first=math.max(base,0x100000000);regions[#regions+1]={base=first,size=base+size-first}
  end
  cursor=base+size;checkpoint()
 end
 table.sort(regions,function(a,b)return a.size>b.size end)
 local found,seen,bytes,matchedBlocks={}, {},0,0;local began=os.time()
 note('SCAN_START readable_regions='..#regions)
 for _,r in ipairs(regions) do
  local off=0
  while off<r.size do
   assert(os.time()-began<180 and bytes<34359738368,'scan budget reached')
   local n=math.min(262144,r.size-off);local chunk=read(r.base+off,n)
   if chunk then
    local pos=1
    while true do
     pos=chunk:find('LDLD\1\0\0\0',pos,true);if not pos then break end
     local at=r.base+off+pos-1
     if not seen[at] then
      seen[at]=true
      local h=read(at,24)
      if h then
       for _,t in ipairs(SPECS) do
        if u32(h,8)==t.hash then
         local ok,p=pcall(resolve,at,t)
         if ok then
          local key=p.name..':'..string.format('%X',p.address)
          if not found[key] then
           found[key]=p;matchedBlocks=matchedBlocks+1
           local aok,why=pcall(apply,p);if not aok then error(why) end
          end
         else note('REJECT '..t.name..' '..tostring(p)) end
        end
       end
      end
     end
     pos=pos+1;checkpoint()
    end
   end
   bytes=bytes+n
   if off+n>=r.size then break end
   off=off+n-23;checkpoint()
  end
 end
 for key,p in pairs(found) do state.plans[key]=p end
 local h,m=0,0
 for _,p in pairs(state.plans) do if p.name=='health' then h=h+1 else m=m+1 end end
 note(string.format('SCAN_RESULT matched_blocks=%d health_tables=%d magazine_tables=%d read_MiB=%.1f',matchedBlocks,h,m,bytes/1048576))
 return h>0 and m>0
end

local loader=rawget(_G,'CowboyBingusModLoader');local previous=rawget(_G,'update')
local ok,why=pcall(function()
 assert(loader and loader.open_log and type(previous)=='function','loader/update unavailable')
 logfile=assert(loader.open_log(NAME..'.log'));backupfile=assert(loader.open_log(NAME..'-backup-'..tostring(os.time())..'.log'))
 proc=k.OpenProcess(0x438,0,k.GetCurrentProcessId());assert(proc~=nil and proc~=ffi.NULL,'process handle unavailable')
end)
if not ok then state.phase='failed';note(why);return end
note('SESSION E/AT-12 health 3000, magazine 300; RPM and fire mode unchanged')
local worker,next_scan,callback
local function start_scan()
 state.phase='working';worker=coroutine.create(function()
  if not state.verified then verify_build(function()coroutine.yield()end);state.verified=true end
  local all=scan(function()if not state.deadline or os.clock()>=state.deadline then coroutine.yield()end end)
  if all then state.phase='watching';state.empty=0 else state.phase='waiting';state.empty=state.empty+1 end
  next_scan=os.time()+math.min(30,2^(state.empty+1))
  if state.empty>=4 then state.phase='gave_up';note('SCAN_STOP four rounds without both target tables') end
 end)
end
local function step()
 state.frame=state.frame+1
 if state.frame<120 or state.phase=='failed' or state.phase=='gave_up' then return end
 if state.phase=='pending' then start_scan() end
 if state.phase=='waiting' and os.time()>=next_scan then start_scan() end
 if state.phase=='working' then
  state.deadline=os.clock()+0.004
  local resumed,err=coroutine.resume(worker)
  if not resumed then
   if tostring(err):find('scan budget reached',1,true) then
    note('SCAN_BUDGET reached; retaining verified writes');state.phase='waiting';state.empty=state.empty+1;next_scan=os.time()+math.min(30,2^(state.empty+1))
    if state.empty>=4 then state.phase='gave_up';note('SCAN_STOP scan budget exhausted') end
   else state.phase='failed';note('FAILED '..tostring(err)) end
  end
 elseif not next_scan or os.time()>=next_scan then
  next_scan=os.time()+15
  for key,p in pairs(state.plans) do
   if not guard_ok(p) then state.plans[key]=nil;note('TABLE_RELOADED '..p.name)
   else local changed=apply(p);if changed then note('REAPPLIED '..p.name) end end
  end
  if next(state.plans)==nil then state.phase='waiting' end
 end
end
callback=function(dt,...)
 local result=previous(dt,...);local ran,err=pcall(step)
 if not ran then state.phase='failed';note('FAILED '..tostring(err)) end
 if (state.phase=='failed' or state.phase=='gave_up') and update==callback then update=previous;if proc then k.CloseHandle(proc);proc=nil end end
 return result
end
update=callback
