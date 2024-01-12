## What is the Web-Pwn?

The term 'pwn' typically refers to binary exploitation through memory corruption vulnerabilities in CTF. While, 'web' focuses on exploiting vulnerabilities in the modern web world, such as XSS, CSRF, and SQL injection, which primarily are injection-based vulnerabilities. 'Web-Pwn' is a specialized term that describes the exploitation of memory-related vulnerabilities within essential web components like browsers, JavaScript runtimes, PHP runtimes, and others. These vulnerabilities can be triggered by an attacker through specific web-based operations.

This repository is used to collect a list of ctf challenges of 'Web-Pwn' with the description, attachments, exp and writeups.

*TODO: hope we can find another way of classification instead of the challenges. For the how2heap, they use heap exploitation techniques.*


## Overview

| Artifact | Version | Time        | Vuln Description                      | CTF        | Challenge |
| -------- | ------- | ----------- | ------------------------------------- | ---------- | --------- |
| V8       | b027d36 | 2019-Apr-05 | Manually introduced oob vulnerability | \*CTF 2019 | oob-v8    |


## Deployment

To ensure a smoother deployment process, I will supply Dockerfiles designed to create a self-contained environment, streamlining the building and debugging of the binary. Constructing a vulnerable version of the binary from 3 or 4 years ago involves more than just executing a git checkout command. Challenges often arise due to inconsistencies in your system environment and build scripts, which can lead to unexpected errors. By utilizing the Dockerfile, you can effectively address these issues in a contained environment, avoiding any disruption to your host machine's current configuration.