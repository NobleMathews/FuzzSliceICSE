# Script to filter Static analysis warnings and retain only those relevant for fuzzing

import os
import subprocess

# Using readlines()
file1 = open("./infer-report.txt", "r")
static_lines = file1.readlines()


with open(
    "/mnt/StaticSlicer/info_lib/binutils-gdb-old/build_logs"
) as myfile:
    build_logs = myfile.read()


count = 0
targets = []
unique = {}

# Strips the newline character
for line in static_lines:
    count += 1
    # print("Line{}: {}".format(count, line.strip()))
    target_name = line.split(":")[0]
    file_name = os.path.basename(target_name)

    if ("Buffer Overrun L2" not in line):
        continue

    if file_name not in build_logs:
        continue

    if target_name.strip() == "":
        continue

    if "build_ss" in line:
        continue

    if line not in unique:
        targets.append(line)
        unique[line] = 1
file3 = open("myfile.txt", "w")
file3.writelines(targets)
file3.close()


print(targets)
