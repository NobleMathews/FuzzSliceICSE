# Put output of python3  mainpy in save_log before executing this file
# python3 main.py > log 2>&1

import os
import re

f = open(f"./info_lib/C/both-tools-classified", "r")
lines = f.readlines()
targets = []

FP = {}
TP = {}

num_files_fuzzed = 0
status = 0
confirmed_TP = 0
confirmed_FP = 0
unconfirmed_TP = 0
unconfirmed_FP = 0

for line in lines:
    if line.strip() == "":
        continue

    if "Number of possible False positives" in line:
        status = 0
        continue
    elif "Number of possible True positives" in line:
        status = 1
        continue
    elif "Number of unreachable issues" in line:
        status = 2
        continue
    elif "Number of files that are not compiled" in line:
        continue

    if status == 2:
        continue
    
    num_files_fuzzed = num_files_fuzzed + 1
    targets += [line]

    file = line.split(":")[0]
    target_line = line.split(":")[1]
    f1 = open(file, "r")
    clines = f1.readlines()

    num_lines = 0

    danger = 0
    check = 0

    # If there is a FIX followed by FLAW then it is false positive
    # If there is two FLAWS in same function then it is true positive
    # We move backward from vulnerability line counting the FIX and FLAW lines and stop when we have 2 ...
    for codeline in reversed(clines[0 : int(target_line) - 1]):
        if "FIX:" in codeline:
            danger = danger + 1
            num_lines = num_lines + 1
            continue
        if "FLAW" in codeline:
            danger = danger - 1
            num_lines = num_lines + 1
            continue

        if codeline.startswith("{"):
            check = 1
            continue

        if check == 1:
            check = 0
            if "Sink" in codeline:
                if status == 0:
                    print(codeline)
                    print(line)
                    unconfirmed_TP = unconfirmed_TP + 1
                elif status == 1:
                    confirmed_TP = confirmed_TP + 1
                TP[line] = 1
            elif "goodG2B" in codeline:
                # print("False positive: "+ line)
                if status == 0:
                    confirmed_FP = confirmed_FP + 1
                elif status == 1:
                    unconfirmed_FP = unconfirmed_FP + 1
                FP[line] = 1
            else:
                # print("True positive: "+ line)
                if status == 0:
                    unconfirmed_TP = unconfirmed_TP + 1
                elif status == 1:
                    confirmed_TP = confirmed_TP + 1
                TP[line] = 1

            # if danger >= 0:
            #     # print("False positive: "+ line)
            #     if status == 0:
            #         confirmed_FP = confirmed_FP + 1
            #     elif status == 1:
            #         unconfirmed_FP = unconfirmed_FP + 1
            #     FP[line] = 1
            # elif danger < 0:
            #     # print("True positive: "+ line)
            #     if status == 0:
            #         print(line)
            #         unconfirmed_TP = unconfirmed_TP + 1
            #     elif status == 1:
            #         confirmed_TP = confirmed_TP + 1
            #     TP[line] = 1
            # else:
            #     print(line)
            #     print(codeline)
            #     print("This case has never happened ... ")
            #     exit()
            break

    


print("Number of binaries fuzzed are: " + str(num_files_fuzzed))
print("The confirmed True positives are: " + str(confirmed_TP) + "/" + str(len(TP)))
print("The confirmed False positives are: " + str(confirmed_FP) + "/" + str(len(FP)))
print("Unconfirmed True positives are: " + str(unconfirmed_TP) + "/" + str(len(TP)))
print("Unconfirmed False positives are: " + str(unconfirmed_FP) + "/" + str(len(FP)))
