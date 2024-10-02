## How to debug V8?

Here is some notes for debugging the V8:

**1/ Use the `v8/tools/gdbinit`**

V8 provides useful debugging command, e.g., `job`, that helps you print the JS runtime value memeory layout.

```
gef➤  job 0x2f2800045e05
0x2f2800045e05: [JSArray]
 - map: 0x2f280018d429 <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x2f280018ce2d <JSArray[0]>
 - elements: 0x2f2800045df5 <FixedDoubleArray[1]> [PACKED_DOUBLE_ELEMENTS]
 - length: 100
 - properties: 0x2f2800000219 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x2f2800000e31: [String] in ReadOnlySpace: #length: 0x2f2800025af9 <AccessorInfo name= 0x2f2800000e31 <String[6]: #length>, data= 0x2f2800000251 <undefined>> (const accessor descriptor), location: descriptor
 }
 - elements: 0x2f2800045df5 <FixedDoubleArray[1]> {
           0: 1.1
 }
```

Don't forget to add the following lines to your `.gdbinit` file.
```
source ~/.gef-.py
source /your/path/to/v8/tools/gdbinit
```

**2/ Use `%SystemBreak` and `%DebugPrint`**

`%SystemBreak` and `%DebugPrint` help you inspect the memory layout of a JavaScript file during testing.

+ `%SystemBreak`: Allows you to break execution at any point, helping skip irrelevant parts.
+ `%DebugPrint`: Prints the address of JavaScript runtime variables during the break.

To use both commands, start d8 with the following command:

```
gdb --args d8 --allow-natives-syntax /path/to/your/script
```

However, you may find it annoying that the output of `%DebugPrint` gets refreshed if you're using a gdb plugin like `gdb-gef`. To avoid this, we need to separate the stdout of `gdb` and the stdout of `d8`. To achieve this, open another terminal to receive `d8`'s output and set the following line in `gdb` to redirect `d8`'s output:

You should replace the TTY, e.g., `/dev/pts/8`, with output of running the `tty` command in your receving terminal.

```
set inferior-tty /dev/pts/8
```