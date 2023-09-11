import json
import os
from datetime import datetime
from gitlogparser import get_log
import numpy as np

# git checkout `git rev-list -n 1 --first-parent --before="2020-01-01 00:00" master`
libraries = ["openssh-portable", "openssl", "tmux"]
for test_library in libraries:
    lib_clone_location = f"/mnt/fresh/{test_library}"
    result_targets = {}
    report_location = f"tools/bug_timeline/{test_library}_report.json"
    statistics_location = f"tools/bug_timeline/{test_library}_stats"

    if not os.path.exists(report_location):
        with open(f"tools/bug_timeline/{test_library}_targets", "r", encoding="UTF-8") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            old_format = line.replace("-L","")
            target_func, lineno = old_format.split(":")[0].split(",")
            with open(f"{lib_clone_location}/{old_format.split(':')[1]}", "r", encoding="UTF-8") as f:
                start_lines = f.readlines()[:int(lineno)]
            final_loc = lineno
            for st_line in range(len(start_lines)):
                if target_func in start_lines[st_line]:
                    final_loc = st_line
            result = get_log(lib_clone_location,f"git log -L{final_loc},{lineno}:{old_format.split(':')[1]}")
            result_targets[f"git log -L{final_loc},{lineno}:{old_format.split(':')[1]}"] = json.loads(result)

        with open(report_location, "w", encoding="UTF-8") as f:
            json.dump(result_targets, f, indent=4)

    with open(report_location, "r", encoding="UTF-8") as f:
        result_targets = json.load(f) 

    loldest=[]
    lnewest=[]
    for key,value in result_targets.items():
        start, old_format = key.replace("-L","").split(",")
        lineno, target = old_format.split(":")
        target_key = f"{target}:{lineno}"
        result = sorted(value, key=lambda d: datetime.fromisoformat(d['commit_date']))
        entry = f"{target_key}\t0\t0\n"
        if result:
            oldest = datetime.fromisoformat(result[0]['commit_date'])
            newest = datetime.fromisoformat(result[-1]['commit_date'])
            loldest.append(oldest.timestamp())
            lnewest.append(newest.timestamp())
            entry = f"{target_key}\t{oldest.date()}\t{newest.date()}\t{start.split()[-1]}\n"
        with open(statistics_location, "a+", encoding="UTF-8") as f:
            f.write(entry)

    print(f"Median: {datetime.fromtimestamp(np.median(loldest)).strftime('%Y-%m-%d')} {datetime.fromtimestamp(np.median(lnewest)).strftime('%Y-%m-%d')}")
    print(f"Mean: {datetime.fromtimestamp(np.mean(loldest)).strftime('%Y-%m-%d')} {datetime.fromtimestamp(np.mean(lnewest)).strftime('%Y-%m-%d')}")
