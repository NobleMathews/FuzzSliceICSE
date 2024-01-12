# FuzzSlice

[![SWH](https://archive.softwareheritage.org/badge/origin/https://github.com/NobleMathews/FuzzSliceICSE/)](https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/NobleMathews/FuzzSliceICSE)

<p align="center">
    <a href="https://archive.softwareheritage.org/swh:1:cnt:72e1b742f8f9e55b01d2fbc3c2bc76ed62699746;origin=https://github.com/NobleMathews/FuzzSliceICSE;visit=swh:1:snp:1d64e508e0712f6f2bdf5bce07b81c45707a227e;anchor=swh:1:rev:2f3287061abe46a436fb6b4422171d171c345567;path=/FuzzSlice_ICSE_2024.pdf">ICSE 2024 Paper PDF</a> •
    <a href="https://archive.softwareheritage.org/swh:1:cnt:b963c46c995105ecc6efed0c7a8dbee7b2372d0e;origin=https://github.com/NobleMathews/FuzzSliceICSE;visit=swh:1:snp:1d64e508e0712f6f2bdf5bce07b81c45707a227e;anchor=swh:1:rev:2f3287061abe46a436fb6b4422171d171c345567;path=/FuzzSlice_Technical_Documentation.pdf">FuzzSlice Technical Documentation</a> •
    <a href="https://archive.softwareheritage.org/browse/origin/directory/?origin_url=https://github.com/NobleMathews/FuzzSliceICSE">Archival Code Repository</a> •
    <a href="https://conf.researchr.org/details/icse-2024/icse-2024-research-track/39/FuzzSlice-Pruning-False-Positives-in-Static-Analysis-Warnings-through-Function-Level">ICSE Publication</a> •
    <a href="https://www.researchgate.net/publication/374114151_FuzzSlice_Pruning_False_Positives_in_Static_Analysis_Warnings_through_Function-Level_Fuzzing#fullTextFileContent">Preprint (ResearchGate)</a> 
</p>

## Purpose

This artifact is a full functional and reusable implementation of the approach and results presented in the paper “FuzzSlice: Pruning False Positives in Static Analysis Warnings through Function-Level Fuzzing. The goal of FuzzSlice is to automatically prune false positives in static analysis warnings. FuzzSlice achieves this by compiling code slices at the function level of each static analysis warning. It then proceeds to fuzz these compiled slices using libfuzzer. 

List of badges applied for:
- Artifact Available
    - [Archival Repository (Software Heritage)](https://archive.softwareheritage.org/browse/origin/directory/?origin_url=https://github.com/NobleMathews/FuzzSliceICSE)
    - [![SWH](https://archive.softwareheritage.org/badge/swh:1:rev:2f3287061abe46a436fb6b4422171d171c345567/)](https://archive.softwareheritage.org/swh:1:rev:2f3287061abe46a436fb6b4422171d171c345567;origin=https://github.com/NobleMathews/FuzzSliceICSE;visit=swh:1:snp:1d64e508e0712f6f2bdf5bce07b81c45707a227e)
    - Identifier: swh:1:rev:2f3287061abe46a436fb6b4422171d171c345567;origin=https://github.com/NobleMathews/FuzzSliceICSE;visit=swh:1:snp:1d64e508e0712f6f2bdf5bce07b81c45707a227e

- Artifact Reusable
    - Dockerfile part of Archival Repository
    - [Technical Documentation](FuzzSlice_Technical_Documentation.pdf)

## Provenance

The package includes the code for artifact and the benchmarks used in the study (Juliet, openssl, openssh-portable and tmux repositories). In this artifact, we have provided a docker file which will automatically setup various modules of our package (therefore docker is the only dependency). The docker can be easily setup on a Linux machine by directly applying the commands on the README of the replication package in order. Therefore, there is no particular technology skills assumed by the reviewer. The expected setup time for the docker is a few minutes. We have already provided sample static analysis warnings to demonstrate FuzzSlice. The expected output is the code coverage of fuzzing and whether a static analysis warning is classified as a possible true bug or false positive. We have also provided a user documentation guide, which will go over the various configuration options of FuzzSlice in detail and explain what they do and what to expect as output.

## Setup

These instructions will guide you through getting a copy of the tool up and running on your local machine.

### Prerequisites

- Docker

### Recommended Option: Using Pre-built Docker Image

For a quick start, you can use a pre-built image available on Docker Hub. This is the recommended method, especially if you are using an amd64 architecture system.

To pull and run the pre-built image, execute the following commands:

```bash
docker pull noblemathews/fuzzslice-icse
docker run -it noblemathews/fuzzslice-icse
```


### Building docker image 

This option is not recommended as it can fail based on system architecture or package deprecation. However, if you would like to build the docker image from scratch, you can follow the instructions below. To verify to some extent that dependencies are working correctly please ensure that the 3 sample targets are classified correctly as true bugs or false positives as shown in the next section.

1A. If you are downloading this repository from archival as a compressed file the git submodules will not be included. Please run the following command from the root directory of the project to download the submodules:
```bash
chmod +x ./init_submodules.sh
./init_submodules.sh
```

1B. Else if you have cloned this repo as a git repository, enter the root directory of the project. Recursively fetch the submodules by running:
```bash
git submodule update --init --recursive
```

You can now build the environment required for the tool from using the Dockerfile included by running the following command:
```bash
docker build --platform linux/x86_64 -t sf . 
```

The build command will both setup the environment and the test repositories. To enter the container invoke:
```bash
docker run -it sf
```

## Usage

### Replicate Results

To replicate the results of the paper, you can run the following command from within in the docker container:

```bash
python3 main.py
```

**Quoting from the paper:**
To evaluate the warnings produced by the static analysis tools, we subject each warning to a fuzzing process lasting `five minutes`. Our fuzzing procedure was conducted on a Headless Server equipped with a powerful hardware configuration consisting of `64 cores of Intel Xeon Gold 6226R processors, operating at a speed of 3.900GHz, and 128GB of RAM on Ubuntu 20.04 LTS`. It is worth noting that certain warning locations may only be compilable on specific operating systems as defined by preprocessor directives.



**Note:** Running FuzzSlice on all repositories and static analysis warnings will take a long time and compute to run (~3-4 days based on the fuzzing budget). We have setup `config.yaml` to run one of the smaller repositories `tmux` on 3 warnings with a reduced time budget for fuzzing (the rest are commented out and can be enabled by editting `info_lib/tmux/targets.txt`).

The expected output with the 3 warnings is as follows:

```bash
| INFO     | fuzz:build_report:526 - Number of possible True positives: 2
| INFO     | fuzz:build_report:528 - ./test_lib/tmux/cmd-send-keys.c:110: error: Buffer Overrun L1 // issue
| INFO     | fuzz:build_report:528 - ./test_lib/tmux/cmd-parse.c:1292: error: Buffer Overrun L2
| INFO     | fuzz:build_report:531 - Number of possible False positives: 1
| INFO     | fuzz:build_report:533 - ./test_lib/tmux/layout-custom.c:66: error: Buffer Overrun L1
```

If you would like to replicate all the results in the paper you can uncomment any warning within any of the projects in `info_lib/<project>/targets.txt` directory. Then in the `config.yaml` file, replace `test_library` attribute with `<project>`. Then run `python3 main.py`. We have reduced the fuzzing time from 5 minutes to 10 seconds in `config.yaml` so that users can see the fuzzing of several warnings at a faster pace (at the cost of accuracy). Even with this reduced configuration building all the projects and covering all warnings in the analysis would take 8 hours of fuzzing and compilation time.

### Running the tool on a custom repo

Now you can clone and setup target repo in testlib. After setting up the repo such that `make` can be run on it. 

The tool also expects a list of targets to work with, though all targets produced from a static analyzer can be used here we have kept this part manual so that the tool is only run on the kind of issues the user wants to check for (say buffer or memory issues). This file should be provided as `infolib/{test_library}/targets.txt`. Each target line should start with `{relative_path}:{line_no}`, this format is used by default in reports generated by tools like `rats` and `infer`. 

You can run the tool on the repo by updating the `config.yaml` file as per your requirements and running the `main.py` script.

The config keys currently supported are detailed below:

```yaml
test_library: Name of the directory within test_lib which has been setup for testing
fuzz_tool: Use 0 for libfuzzer and 1 for AFL [AFL support has currently been paused please retain this as 0]
timeout: The time for which Fuzzer runs
hard_timeout: Max timeout enforced for the entire fuzzing binaries function [For cases that don't terminate as expected]
max_length_fuzz_bytes: Max length of fuzz bytes
parallel_execution: Allow multiprocessing for issues
crash_limit: Maximum number of crashes to check
bug_timeline_targets_run: Performs git blame based tracing of issues [Retain as false for analysis]
log_report: Enable timing each part of the pipeline
```
