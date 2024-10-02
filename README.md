## What is the Browser Dojo?

The Browser Dojo is a collection of recent browser-related pwn challenges, including targets like V8, with the description, attachments, exp and writeups.

*TODO: hope we can find another way of classification instead of the challenges. For the how2heap, they use heap exploitation techniques.* <br>
*TODO: I think putting this repo as one of the dojo in the pwn.college could be my envision by the end of year 2024*

## Overview

| Artifact | Version | Writeup | Vuln Description                      | CTF        | Challenge |  Time  | 
| -------- | ------- | ----------- | ------------------------------------- | ---------- | --------- | ----------- |
| V8       | v7.5.0   | [Link](https://github.com/jackfromeast/browser-dojo/blob/main/v8/2019-star-ctf-oob-v8/README.md) | Manually introduced oob vulnerability | \*CTF 2019 | oob-v8    |  2019-Apr-05 |
| V8       | v11.9.99 | [Link](https://github.com/jackfromeast/browser-dojo/blob/main/v8/2024-patriot-ctf-babyxss/README.md) | Manually introduced oob vulnerability | PatriotCTF 2024 | babyxss | 2024-Sep-22|


## Folder Layout

+ `challenge`
  + `attackment`
    + `challenge.tar.gz`: The raw attachment from the ctf challenge
  + `build` 
    + `build.sh`: The build script to fetch & compile the binary from source code with custom `args.gn`.
    + `chall.diff`: The challenge diff file that introduce the vulnerability.
    + `args.gn`: The configuration file for compiling (Optional).
    + `build.Dockerfile`: The Dockerfile to build the binary.
  + `challenge`
    + `d8` and other necessary compiled outputs, e.g. `snapshot_blob.bin`.
  + `solution`
    + `writeup.md`: The writeup from the challenge.
    + `solve.js`: The exp script for the challenge.