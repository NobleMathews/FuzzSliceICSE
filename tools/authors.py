import os
import shlex
import subprocess


command_base = "git --no-pager log --pretty=short -u -L  "
project = "tmux"

target_file1 = open("./info_lib/" + project + "/infer-classified","r")
target_file2 = open("./info_lib/" + project + "/rats-classified","r")

static_lines = target_file1.readlines()
static_lines += target_file2.readlines()

accept = 0

os.chdir("./test_lib/" + project)

authors = {}

for line in static_lines:
    # print("Line{}: {}".format(count, line.strip()))
    if ":" not in line:
        continue

    if "FP:" in line:
        accept = 1
        continue

    if "TP:" in line:
        accept = 0
        continue

    if "NR:" in line:
        accept = 0
        continue

    if "NC:" in line:
        accept = 0
        continue

    if "Not built" in line:
        accept = 0
        continue

    if accept == 0:
        continue

    line = line.replace("./test_lib/" + project, ".")
    target_name = line.split(":")[0]
    line_no = line.split(":")[1]
    file_name = target_name
    command = command_base + line_no + "," + line_no +":" + file_name
    print(file_name)
    print(line_no)
    print(command)

    p = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True
        )
    # p.wait(10)
    output = p.stdout.decode("utf-8")
    # print(output)
    
    for line in output.split("\n"):
        if "Author: " in line:
            line = line.replace("Author: ","")
            # print(line)
            if line in authors:
                authors[line] += 1
            else:
                authors[line] = 1

print(authors)



