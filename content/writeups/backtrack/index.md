---
title: "rev/backtrack - nullcon hackim ctf goa 2025"
date: 2025-01-02
draft: false
description: "write up for the backtrack rev challenge from nullcon goa ctf 2025"
tags: ["ctf", "rev", "malware"]
showtableofcontents: true
---

this was a pretty fun malware challenge from nullcon goa, although i did spend alot of time going through random rabbit holes in the program (but i guess i now know more about how malware might load dlls).


## chal description
while working i found an interesting sample in the wild.\
the sample seems to load other executables but idk how? can you find that out?\
warning: this is an actual malware, do not execute it (the challenge is meant to be solved statically)\
also i overwrote a part of the entry to make the sample not executble (just to be extra safe ;) )\
files can be found in the zip:

- b8ad5cbf8c8a3129582161226e79b6c4b67c8b868592d1618252451c8c2146c8 is the sample
- input_file is the data they used to get the keylogger
- keylogger.bin is the result after the input_file is given to the sample
- data.bin is the challenge file

to solve this task reverse what's in data.bin and look at the output (example: input_file -> keylogger, data.bin -> ???)

files: [`files.zip`](/writeups/backtrack/files.zip)

## solution
the zip contains the 4 files mentioned in the description. the sample `b8ad5cbf8c8a...`, is malware that loads payloads. the idea is that it turns files like `input_file` into a *pe* such as `keylogger.bin`, which it then launches. based on the description, the flag should be in the transformed `data.bin`.
looking at the hex of the two untransformed files (and based on the size of the `keylogger.bin`), we can see that they are compressed, and that `data.bin` should turn into a jpeg.
![input_file](/writeups/backtrack/input_file_hex.png)
![data.bin](/writeups/backtrack/data_hex.png)

with this determined, we can finally start to look at the decompiled code in ghidra.

the main function looks like this (after some analysis, some of the names for things are also dumb):
```c
int main(void)
{
  bool bvar1;
  char cvar2;
  undefined uvar3;
  undefined2 show_window;
  int ivar4;
  int *pivar5;
  undefined4 uvar6;
  int unaff_esi;
  void *exception_list;
  code *some_scramble_func_;
  uint idk_what_this_s;
  undefined4 local_8;
  
  local_8 = 0xfffffffe;
  some_scramble_func_ = lots_of_unwinding;
  exception_list = exceptionlist;
  idk_what_this_s = something_notimportant ^ 0x405bb0;
  exceptionlist = &exception_list;
  cvar2 = init_start(1);
  if (cvar2 == '\0') {
    handle_exceptions(7);
  }
  else {
    bvar1 = false;
    local_8 = 0;
    uvar3 = fun_00402eb0();
    if (dat_00407068 != 1) {
      if (dat_00407068 == 0) {
        dat_00407068 = 1;
                    /* get args to somewhere idk where though */
        ivar4 = call_main_table(&another_table,&dat_00405118);
        if (ivar4 != 0) {
          exceptionlist = exception_list;
          return 0xff;
        }
        _initterm(&ptr_00405100,&dat_00405108);
        dat_00407068 = 2;
      }
      else {
        bvar1 = true;
      }
      ___scrt_release_startup_lock(uvar3);
      pivar5 = (int *)fun_00403110();
      if (*pivar5 != 0) {
        cvar2 = check_entrypoint(pivar5);
        if (cvar2 != '\0') {
          (*(code *)*pivar5)(0,2,0);
        }
      }
      show_window = fun_004032b0();
      uvar6 = fun_00403780();
      unaff_esi = init_all(0x400000,0,uvar6,show_window);  // the function where things happen
      cvar2 = fun_00403300();
      if (cvar2 != '\0') {
        if (!bvar1) {
          _cexit();
        }
        free_all(1,0);
        exceptionlist = exception_list;
        return unaff_esi;
      }
      goto lab_00402c9a;
    }
  }
  handle_exceptions(7);
lab_00402c9a:
                    /* warning: subroutine does not return */
  exit(unaff_esi);
}
```

it looks like there's alot here, but all of the transformations actually happen in the function that get's called (here named `init_all`).
the rest is used to initialize some headers for the *pe* in the program's memory space.

taking a look at that function, we can see it's just a wrapper around another function call (my naming *convention* (i don't have a naming convention) is confusing) 
```c
undefined4 init_all(void)
{
  int ivar1;
  
  ivar1 = init();
  if (ivar1 == 0) {
     try_reinit();
     start_stuff(0);
  }
  return 0;
}
```
the init function loads `shwapi.dll`
```c
{
  loadlibrarya(local_50);
  builtin_memcpy(local_30 + 0xc,"shlwapi.dll",0xc);
  hmodule = loadlibrarya(local_30 + 0xc);
  builtin_memcpy(local_30,"shgetvaluea",0xc);
  shgetvaluea?? = (shgetvaluea *)getprocaddress(hmodule,local_30);
}
```

the try_reinit function seems to just delay the program a little.
```c
  dvar1 = gettickcount();
  uvar5_45000 = 45000;
  uvar4_360000 = 360000;
  do {
     getlocaltime(&local_28);
     uvar3 = (uint)local_28.wsecond;
     dvar2 = gettickcount();
     if ((45000 < dvar2 - dvar1) && (uvar3 == t_second)) break;
     dvar2 = gettickcount();
  } while (dvar2 - dvar1 < 0x57e41);
```

### loading

the function `start_stuff` is where the program actually loads the exe.
```c
void start_stuff(void)
{
  uint ustack_60;
  dword local_50 [2];
  handle thread_handle;
  lpthread_start_routine dllmain_addr;
  undefined4 some_size;
  image_dos_header *registryval;
  context *context;
  char dllmain [28];
  uint local_18;
  undefined *local_14;
  void *local_10;
  undefined *pustack_c;
  undefined4 local_8;
  
  pustack_c = &lab_004041c0;
  local_10 = exceptionlist;
  ustack_60 = something_notimportant ^ (uint)&stack0xfffffffc;
  local_14 = (undefined *)&ustack_60;
  exceptionlist = &local_10;
  local_8 = 0;
  some_size = 0;
  local_18 = ustack_60;
  registryval = (image_dos_header *)hkey_loader_or_something(&some_size);
  context = copy_file_wrapper(registryval,some_size);
  dllmain[0] = '\0';
  dllmain[1] = '\0';
   ...
  dllmain[0x1b] = '\0';
  strcat(dllmain,"dll");
  strcat(dllmain,"ma");
  strcat(dllmain,"in");
  dllmain_addr = (lpthread_start_routine)find_dllmain(context,dllmain);
  thread_handle = (handle)0x0;
  dllmain_addr = (lpthread_start_routine)find_dllmain(context,dllmain);
  thread_handle = createthread((lpsecurity_attributes)0x0,0,dllmain_addr,(lpvoid)0x0,0,local_50);
  waitforsingleobject(thread_handle,0xffffffff);
  exit_free_fn();
  return;
}
```

i did end up figuring out the structs of these values while trying to understand how it works. 
the malware loads some input from the windows registry (hkey_loader), which it interprets as a *pe* header, `copy_file_wrapper` copies the loaded data, into program memory.
the next part finds `dllmain` in the loaded program and runs it in a other thread.

knowing all this, the data would have to be transformed when it first gets loaded, which would be in `hkey_loader_or_something`.

this function looks like this:
```c
void hkey_loader_or_something(size_t *param_1)
{
  lstatus lvar1;
  dword local_48;
  void *dest;
  size_t length;
  dword local_3c;
  astruct_1 *src;
  size_t size_in;
  char buf_a [22];
  void *local_10;
  undefined *pustack_c;
  undefined4 local_8;
  
  pustack_c = &lab_004041f0;
  local_10 = exceptionlist;
  exceptionlist = &local_10;
  local_8 = 0;
  length = 0;
  size_in = 0;
  local_48 = 3;
  local_3c = 4;
  builtin_strncpy(buf_a,"software\\realtek inc.",0x16);
  lvar1 = (*shgetvaluea??)((hkey)0x80000001,buf_a,"cs",&local_48,&size_in,&local_3c);
  if (lvar1 == 0) {
     src = (astruct_1 *)malloc(size_in);
     local_3c = size_in;
     lvar1 = (*shgetvaluea??)((hkey)0x80000001,buf_a,"ch",&local_48,src,&local_3c);
     if (lvar1 == 0) {
       length = size_in << 1;
       dest = malloc(length);
       if (dest != (void *)0x0) {
          copy(src,size_in,dest,&length);
          *param_1 = length;
          if (src != (astruct_1 *)0x0) {
            operator_delete[](src);
            src = (astruct_1 *)0x0;
          }
          fun_004014c1();
          return;
       }
       dest = (void *)0x0;
     }
  }
  exceptionlist = local_10;
  init_dat_00407298_first();
  return;
}
```

it would look for **software\realtek inc.** in the registry, and load the two keys **cs** and **hs**.
the first one is the size of the data, and the second is the data itself.
the program then allocates **2x** the size of the data into a buffer that will store the transformed data.

### transformation

the function `copy` is where the transformations happen. src_buf is where the loaded untransformed data is.
```c
struct astruct_1 {
    undefined4* ptr;
    byte data;
};
char * __cdecl copy(astruct_1 *src_buf,int size_in,byte *dest_buf?,int *length)
{
  byte *next;
  byte *local_20;
  int local_1c;
  int local_14;
  uint base;
  byte *tmp_ptr;
  byte *src_buf_ptr;
  byte c1;
  byte c2;
  
  local_14 = 0;
  src_buf_ptr = &src_buf->data;
  tmp_ptr = dest_buf?;
  if (src_buf->ptr == '\x01') {
     sometypeacopy(&src_buf->data,dest_buf?,size_in + -4);
     *length = size_in + -4;
  }
  else {
     while (src_buf_ptr != (byte *)(&src_buf->ptr + size_in)) {
       if (local_14 == 0) {
          base = (uint)*(ushort *)src_buf_ptr;
          src_buf_ptr = src_buf_ptr + 2;
          local_14 = 0x10;
       }
       if ((base & 1) == 0) {
          *tmp_ptr = *src_buf_ptr;
          tmp_ptr = tmp_ptr + 1;
          src_buf_ptr = src_buf_ptr + 1;
       }
       else {
          c1 = *src_buf_ptr;
          c2 = *src_buf_ptr;
          next = src_buf_ptr + 1;
          src_buf_ptr = src_buf_ptr + 2;
          local_20 = tmp_ptr + -((uint)*next + (c1 & 0xf0) * 0x10);
          local_1c = (c2 & 0xf) + 1;
          while (local_1c != 0) {
            *tmp_ptr = *local_20;
            tmp_ptr = tmp_ptr + 1;
            local_20 = local_20 + 1;
            local_1c = local_1c + -1;
          }
       }
       base = base >> 1;
       local_14 = local_14 + -1;
     }
     *length = (int)tmp_ptr - (int)dest_buf?;
  }
  return (char *)length;
}
```

### flag

this algorithm seems to just be some kind of decompression, which i reimplemented in python.
```py
f = open("data.bin", 'rb')
f.read(4)
data = f.read()
data_size = len(data)
length = data_size << 1
out_buf = [0 for _ in range(length)]
i, block, base, tmp = 0, 0, 0, 0
while i != data_size:
    if block == 0:
        base = int.from_bytes(data[i:i+2][::-1])
        i += 2
        block = 0x10
    if (base & 1) == 0:
        out_buf[tmp] = data[i]
        tmp += 1
        i += 1
    else:
        c = data[i]
        next = data[i + 1]
        i += 2
        x1 = tmp - (next + (c & 0xf0) * 0x10)
        x2 = (c & 0xf) + 1
        while x2 != 0:
            out_buf[tmp] = out_buf[x1]
            tmp += 1
            x1 += 1
            x2 -= 1
    base = base >> 1
    block -= 1
length = tmp
out_buf = bytes(out_buf[:length])
with open("output_file.bin", 'wb') as f:
    f.write(out_buf)
```

running this on `data.bin` gives us this jpeg.
![flag image](/writeups/backtrack/output_file.jpeg)

this also works for the other input file (to get the keylogger).

flag: `eno{m4lw4r3_3nj0y3r5_wh00p!}`

solution script: [`backtrack.py`](/writeups/backtrack/backtrack.py)
