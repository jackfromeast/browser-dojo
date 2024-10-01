## What is the Browser Dojo?

The Browser Dojo is a collection of recent browser-related pwn challenges, including targets like V8, with the description, attachments, exp and writeups.

*TODO: hope we can find another way of classification instead of the challenges. For the how2heap, they use heap exploitation techniques.*
*TODO: I think putting this repo as one of the dojo in the pwn.college could be my envision by the end of year 2024*

## Overview

| Artifact | Version | Time        | Vuln Description                      | CTF        | Challenge |
| -------- | ------- | ----------- | ------------------------------------- | ---------- | --------- |
| V8       | b027d36 | 2019-Apr-05 | Manually introduced oob vulnerability | \*CTF 2019 | oob-v8    |
| V8       | b027d36 | 2024-Sep-22 | Manually introduced oob vulnerability | PatriotCTF 2024 | babyxss |


## Deployment

Each challenge comes with a Dockerfile to create a ready-to-go environment for building and debugging. Getting a vulnerable version of a binary from a few years ago isn’t as simple as running a git checkout—you’ll probably run into system and script inconsistencies. By using the provided Dockerfile, you can sidestep these headaches and work in a clean, controlled environment without messing up your main setup.