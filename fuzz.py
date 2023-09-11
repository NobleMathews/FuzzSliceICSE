import glob
import linecache
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from multiprocessing import Pool, process
from pathlib import Path
import yaml
import timeout_decorator

import psutil
from loguru import logger

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
# The time for which Fuzzer runs
timeout = config["timeout"]
# Max length of fuzz bytes
max_length_fuzz_bytes = config["max_length_fuzz_bytes"]
# Allow multiprocessing for issues
parallel_execution = config["parallel_execution"]
crash_limit = config["crash_limit"]
hard_timeout = config["hard_timeout"]

# Deprecated - please use libfuzz until this is re-enabled
class Aflfuzz:

    # test case wise timeout in milliseconds
    test_timeout = 1000
    afl_fuzz_path = "afl-fuzz"
    afl_cov_path = "afl-cov"

    @staticmethod
    def construct_fuzz_command(file, inpath, outpath):
        command = (
            "AFL_SKIP_CPUFREQ=1 "
            + Aflfuzz.afl_fuzz_path
            + " -t "
            + str(Aflfuzz.test_timeout)
            + " -i "
            + inpath
            + " -V "
            + str(Fuzzer.TIMEOUT)
            + " -C -o "
            + outpath
            + " "
            + file
        )
        my_env = os.environ
        my_env["AFL_SKIP_CPUFREQ"] = "1"
        cwd = "."
        return [command, my_env, cwd]

    @staticmethod
    def check_crashes(print_lines, file, outpath):
        if not (os.path.isfile(file[:-3] + "cov")):
            print_lines += ["No ASAN compiled binary"]
            print_lines += [
                "===============================CRASH ANALYSIS ENDS================================="
            ]
            return

        dir = os.path.join(outpath, "crashes")
        count = 0
        is_confirmed = 0
        for path in os.listdir(dir):
            # There is a README file which needs to be not counted!
            if path == "README.txt":
                continue
            # check if current path is a file
            crashpath = os.path.join(dir, path)
            if os.path.isfile(crashpath):
                f = open(crashpath, "rb")
                p = subprocess.Popen(
                    [file[:-3] + "cov"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                p.stdin.write(f.read())
                p.stdin.close()
                p.wait()
                asan_output = p.stderr.read().decode("utf-8")
                [print_lines, crash_line] = Fuzzer.identify_crash_line(
                    print_lines, asan_output, file
                )
                [print_lines, ret] = Fuzzer.confirm_crash_warning(
                    print_lines, file, crash_line
                )

                if ret == 1:
                    is_confirmed = 1
                f.close()
                count += 1

        return [print_lines, is_confirmed, count]

    @staticmethod
    def generate_coverage(print_lines, file, outpath):
        print_lines += [
            "===============================COVERAGE ANALYSIS BEGINS================================="
        ]
        coverage_bin = file[:-3] + "cov"

        if not (os.path.isfile(coverage_bin)):
            print_lines += ["No ASAN compiled binary"]
            print_lines += [
                "===============================COVERAGE ANALYSIS ENDS================================="
            ]
            return

        code_dir = os.path.abspath(os.path.join(file, os.pardir))
        command = (
            Aflfuzz.afl_cov_path
            + " -d "
            + outpath
            + ' --code-dir . --enable-branch-coverage --overwrite --coverage-cmd "'
            + coverage_bin
            + ' < AFL_FILE"'
        )
        args = shlex.split(command)
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=code_dir
        )
        p.wait()
        output = p.stdout.read().decode("utf-8")
        if "ERROR" in output:
            print_lines += [
                "Coverage results did not generate. Maybe it is because of stack smashing"
            ]
            print_lines += [args]
            print_lines += [output]
            print_lines += [
                "===============================COVERAGE ANALYSIS ENDS================================="
            ]
            return print_lines
        if "Could not find any" in output:
            print_lines += ["gcov file not present"]
            print_lines += [output]
            print_lines += [
                "===============================COVERAGE ANALYSIS ENDS================================="
            ]
            return print_lines

        print_lines += ["Coverage results generated!"]

        print_lines = Aflfuzz.print_coverage(print_lines, file, outpath)
        print_lines += [
            "===============================COVERAGE ANALYSIS ENDS================================="
        ]

        return print_lines

    @staticmethod
    def print_coverage(print_lines, file, outpath):
        web_report_dir = os.path.join(
            outpath,
            "cov",
            "web",
            "test_files",
            os.path.basename(file)[:-3] + "c.gcov.html",
        )
        f = open(web_report_dir, "rb")
        output = f.read().decode("utf-8")
        lines = output.split("\n")
        results = []
        for line in lines:
            if '<td class="headerCovTableEntry">' in line:
                m = re.findall('<td class="headerCovTableEntry">([\d\/\s]+)<', line)
                if m:
                    results += [m[0]]

        print_lines += ["The Line coverage is : " + results[0] + "/" + results[1]]
        print_lines += ["The Function coverage is : " + results[2] + "/" + results[3]]
        print_lines += ["The Branch coverage is : " + results[4] + "/" + results[5]]

        return print_lines


class Libfuzz:
    too_many_crashes = crash_limit

    @staticmethod
    def construct_fuzz_command(file, inpath, outpath):
        command = (
            file
            + " -fork=2 -ignore_crashes=1 -max_len="
            + str(Fuzzer.max_len)
            + " -detect_leaks=0  -len_control=0 -malloc_limit_mb=204800 -timeout=10 -rss_limit_mb=204800 -max_total_time="
            + str(Fuzzer.TIMEOUT)
            + " "
            + inpath
        )
        cwd = outpath
        my_env = os.environ
        my_env["LD_LIBRARY_PATH"] = os.path.abspath(
            "./test_lib/" + Fuzzer.test_library + "/build_ss"
        )
        return [command, my_env, cwd]

    @staticmethod
    def check_crashes(print_lines, file, outpath):
        dir = outpath
        count = 0
        is_confirmed = 0
        for path in os.listdir(dir):
            if os.path.isfile(os.path.join(dir, path)):
                if path.startswith("crash-"):
                    if count > Libfuzz.too_many_crashes:
                        # Too many crashes! Stop!!
                        break
                    count = count + 1
                    print_lines += ["crashfile: " + path]
                    p = subprocess.run(
                        [file, os.path.join(dir, path)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    asan_output = p.stderr.decode("utf-8")
                    [print_lines, crash_line] = Fuzzer.identify_crash_line(
                        print_lines, asan_output, file
                    )
                    [print_lines, ret] = Fuzzer.confirm_crash_warning(
                        print_lines, file, crash_line
                    )

                    if ret == 1:
                        is_confirmed = 1
        return [print_lines, is_confirmed, count]

    @staticmethod
    def print_coverage(file, print_lines, coverage_output, fuzz_data=None):
        if fuzz_data is None:
            fuzz_data = {}
        file_root = os.path.splitext(os.path.basename(file))[0] + "."
        count = 0
        count_not_covered = 0
        count_impossible_to_cover = 0
        target_line = ""
        # Assume target line is covered until later disproved
        target_line_covered = 1
        lines = coverage_output.split("\n")
        print_lines += ["Coverage for target file : "]
        print_status = 0
        for line in lines:
            # Print only lines from coverage within target file or else stdout is cluttered!
            if (file_root in line) or print_status:
                if "Unexecuted instantiation" not in line:
                    print_lines += [line]
                    print_status = 1

            if line.strip() == "":
                print_status = 0

            match_all_lines = re.search("\d\|.*\|", line)
            if match_all_lines:
                count = count + 1

            match_zero_lines = re.search("\d\|      0\|", line)
            if match_zero_lines:
                count_not_covered = count_not_covered + 1

            match_cannot_cover_lines = re.search("\d\|       \|", line)
            if match_cannot_cover_lines:
                count_impossible_to_cover = count_impossible_to_cover + 1

            if "/*target_line*/" in line:
                target_line = line
                if match_zero_lines:
                    target_line_covered = 0
                    fuzz_data["target_line_hit"] = 0
                else:
                    fuzz_data["target_line_hit"] = line.split("|")[1].strip()

        print_lines += ["The target line is: " + str(target_line)]

        if target_line_covered:
            print_lines += ["Target is covered"]
        else:
            print_lines += ["Target is not covered"]

        coverage_ratio = (count - count_not_covered - count_impossible_to_cover) / (count - count_impossible_to_cover)
        fuzz_data["coverage_ratio"] = coverage_ratio
        
        print_lines += [
            "The Line coverage is : "
            + str(count - count_not_covered - count_impossible_to_cover)
            + "/"
            + str(count - count_impossible_to_cover)
            + " = "
            + str(coverage_ratio)
        ]
        return [target_line_covered, print_lines]

    @staticmethod
    def generate_coverage(print_lines, file, outpath, fuzz_data=None):
        target_line_covered = 0
        print_lines += [
            "===============================COVERAGE ANALYSIS BEGINS================================="
        ]
        # logger.info("PLEASE")
        # command1 = file + " " + outpath + "/*"
        # p = subprocess.Popen(command1, shell = True,  stdout = subprocess.PIPE, stderr=subprocess.PIPE, cwd= outpath)
        # p.wait()

        command2 = "llvm-profdata merge -sparse default.profraw -o default.profdata"
        p = subprocess.run(
            shlex.split(command2),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=outpath,
        )
        output = p.stderr.decode("utf-8")

        # logger.info(output)
        if output.strip() != "":
            print_lines += ["Could not find profdata!"]
            print_lines += [output]
            print_lines += [
                "===============================COVERAGE ANALYSIS ENDS================================="
            ]
            return target_line_covered, print_lines

        command3 = "llvm-cov show " + file + " -instr-profile=default.profdata"
        p = subprocess.run(
            shlex.split(command3),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=outpath,
        )

        output = p.stderr.decode("utf-8")
        if output.strip() != "":
            print_lines += ["Could not generate LLVM coverage"]
            print_lines += [output]
            print_lines += [
                "===============================COVERAGE ANALYSIS ENDS================================="
            ]
            return target_line_covered, print_lines

        coverage_output = p.stdout.decode("utf-8")
        # logger.info(coverage_output)
        print_lines += ["Coverage results generated!"]
        target_line_covered, print_lines = Libfuzz.print_coverage(
            file, print_lines, coverage_output, fuzz_data
        )
        print_lines += [
            "===============================COVERAGE ANALYSIS ENDS================================="
        ]
        return target_line_covered, print_lines


class Fuzzer:
    test_library = ""
    # Static analysis targets to compare
    targets = []
    # The time for which Fuzzer runs
    TIMEOUT = timeout
    # Max length of fuzz bytes
    max_len = max_length_fuzz_bytes
    # Allow multiprocessing for issues
    set_parallel_execution = parallel_execution
    # Lock for writing to stdout
    lock = threading.Lock()
    # False positives
    FP = []
    # True positives
    TP = []
    # Not reachable
    NR = []

    @staticmethod
    def print_info(print_lines):
        Fuzzer.lock.acquire()
        for line in print_lines:
            logger.info(line)
        Fuzzer.lock.release()

    @staticmethod
    def print_crashes(print_lines, file, outpath, fuzzer):
        print_lines += [
            "===============================CRASH ANALYSIS BEGINS================================="
        ]

        if fuzzer == 1:
            print_lines, is_confirmed, count = Aflfuzz.check_crashes(
                print_lines, file, outpath
            )
        else:
            print_lines, is_confirmed, count = Libfuzz.check_crashes(
                print_lines, file, outpath
            )

        print_lines += ["Found number of crashes: " + str(count)]
        if is_confirmed:
            print_lines += ["Crash aligns with detected site"]
        else:
            print_lines += ["Crash does not align with detected site"]

        print_lines += [
            "===============================CRASH ANALYSIS ENDS================================="
        ]
        return is_confirmed, print_lines

    @staticmethod
    def identify_crash_line(print_lines, asan_output, file):
        lines = asan_output.split("\n")
        file_root = os.path.splitext(os.path.basename(file))[0]
        issue = ""
        crash_detected = 0
        for line in lines:
            m = re.findall("==ERROR: AddressSanitizer: ([\w-]+)", line)
            if m:
                issue = m[0]
                crash_detected = 1
                print_lines += ["Crash reason: " + issue]

            if ("#" in line) and ((file_root + ".c") in line) and (crash_detected == 1):
                print_lines += ["Crash at: " + line.split(" ")[-1]]
                return [print_lines, line.split(" ")[-1]]
        return [print_lines, ""]

    @staticmethod
    def confirm_crash_warning(print_lines, file, crash_line):
        if crash_line.strip() == "":
            return [print_lines, 0]

        if ":" not in crash_line:
            return [print_lines, 0]

        crash_line_no = int(crash_line.split(":")[1])
        crash_string = linecache.getline(file[:-3] + "c", crash_line_no)

        print_lines += ["The crash happens at this point  -> " + crash_string]

        if "/*target_line*/" in crash_string.strip():
            return [print_lines, 1]

        return [print_lines, 0]

    @staticmethod
    def approximate_fuzz_byte_len(file):
        source_file = file[:-3] + "c"
        file = open(source_file, "r")
        lines = file.readlines()
        fixed_size = 0
        dyn_size = 0
        for line in lines:
            if "// Buff size :" in line:
                m = re.search("Buff size : ([\d]*) ", line)
                if m:
                    fixed_size = int(m.group(1))
                m = re.search("Dyn size : ([\d]*)", line)
                if m:
                    dyn_size = int(m.group(1))
        # Max 1000 bytes per fixed object and 10000 bytes for dynamic objects
        approx_bytes = fixed_size * 1000 + dyn_size * 10000
        Fuzzer.max_len = approx_bytes
        # Please note that this could be wrong but is generally not so
        # Smaller fuzz bytes help to faster reach vulnerability
        logger.info("The fuzz bytes chosen for this issue is : " + str(approx_bytes))

    @staticmethod
    def fuzz_binary(print_lines, file, inpath, outpath, fuzzer):
        print_lines += ["File name to be fuzzed.... : " + file]
        Fuzzer.approximate_fuzz_byte_len(file)
        if fuzzer == 1:
            command, my_env, cwd = Aflfuzz.construct_fuzz_command(file, inpath, outpath)
        else:
            command, my_env, cwd = Libfuzz.construct_fuzz_command(file, inpath, outpath)
        print_lines += [command]

        # os.chdir(cwd)
        # os.system(command)
        subp = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, shell=True, env=my_env
        )

        print_lines += ["Done fuzzing file: " + file]
        return print_lines

    @staticmethod
    def flush_fuzz_dir(test_library):
        dir = os.path.join("./fuzz", test_library)
        if os.path.exists(dir):
            shutil.rmtree(dir)
        os.makedirs(dir)

    @staticmethod
    def prepare_directories(test_library, filename):
        path = os.path.join("./fuzz/", test_library, filename)
        os.mkdir(path)
        inpath = os.path.abspath(os.path.join("./fuzz/", test_library, filename, "in"))
        os.mkdir(inpath)
        outpath = os.path.abspath(
            os.path.join("./fuzz/", test_library, filename, "out")
        )
        os.mkdir(outpath)

        with open(os.path.join(inpath, "seed"), "w") as f:
            f.write("A" * 1000)
        f.close()

        return [inpath, outpath]

    @staticmethod
    def find_files(test_library, extension):
        filenames = []
        for filename in glob.glob(
            os.path.join("./workspace", test_library, "test_files", "*" + extension)
        ):
            filenames += [filename]
        return filenames

    @staticmethod
    def build_report(sourcefiles, binaries):
        logger.info(
            "===============================FUZZ REPORT================================="
        )
        logger.info("Number of possible True positives: " + str(len(Fuzzer.TP)))
        for issue in Fuzzer.TP:
            logger.info(issue)

        logger.info("\n")
        logger.info("Number of possible False positives: " + str(len(Fuzzer.FP)))
        for issue in Fuzzer.FP:
            logger.info(issue)

        logger.info("\n")
        logger.info("Number of unreachable issues: " + str(len(Fuzzer.NR)))
        for issue in Fuzzer.NR:
            logger.info(issue)

        logger.info("\n")
        logger.info(
            "Number of files that are not compiled :"
            + str(len(sourcefiles) - len(binaries))
        )

        for file in sourcefiles:
            root_name = os.path.basename(file).split(".")[0]
            found = 0
            for bin in binaries:
                if root_name in bin:
                    found = 1
                    break
            if not (found):
                logger.info(file)

        logger.info(
            "===============================FUZZ REPORT END================================="
        )

    @staticmethod
    def process_issue(file, test_library, fuzzer, count_file, fuzz_data=None):
        if fuzz_data is None:
            fuzz_data = {}
        file = os.path.abspath(file)
        print_lines = ["Fuzzing issue: " + str(count_file)]
        filename = os.path.basename(file)
        inpath, outpath = Fuzzer.prepare_directories(test_library, filename)
        print_lines = Fuzzer.fuzz_binary(print_lines, file, inpath, outpath, fuzzer)

        if fuzzer == 1:
            print_lines = Aflfuzz.generate_coverage(print_lines, file, outpath)
        else:
            target_line_covered, print_lines = Libfuzz.generate_coverage(
                print_lines, file, outpath, fuzz_data
            )

        # Has to happen after generating coverage so that coverage information is not spoilt!!
        target_crashes, print_lines = Fuzzer.print_crashes(
            print_lines, file, outpath, fuzzer
        )

        word_root = filename.split(".")[-2]
        warning_no = filename.split(".")[0]
        for static_warning in Fuzzer.targets:
            if static_warning.strip() == "":
                continue
            static_warning_no = static_warning.split(":")[1]
            if (word_root in static_warning) and (warning_no == static_warning_no):
                filename = static_warning
                break

        if target_crashes:
            fuzz_data["type"] = "TP"
            print_lines += ["This may be a True positive : " + filename]
            Fuzzer.TP += [filename]
        elif not (target_crashes) and target_line_covered:
            fuzz_data["type"] = "FP"
            print_lines += ["This is false positive : " + filename]
            Fuzzer.FP += [filename]
        else:
            fuzz_data["type"] = "NR"
            print_lines += ["Vulnerability cannot be reached :" + filename]
            Fuzzer.NR += [filename]

        return print_lines

    @staticmethod
    @timeout_decorator.timeout(hard_timeout)
    def fuzz_binaries(test_library, fuzzer):
        fuzz_data = {}
        logger.info(
            "===============================FUZZING STARTS================================="
        )
        files = Fuzzer.find_files(test_library, ".out")
        sourcefiles = Fuzzer.find_files(test_library, ".c")
        logger.info("Total number of source files : " + str(len(sourcefiles)))
        logger.info("The number of binaries to be fuzzed: " + str(len(files)))

        f = open(f"./info_lib/{test_library}/targets.txt", "r")
        lines = f.readlines()
        targets = []

        for line in lines:
            targets += [line]

        Fuzzer.test_library = test_library
        Fuzzer.targets = targets

        Fuzzer.flush_fuzz_dir(test_library)

        if Fuzzer.set_parallel_execution:
            pool = Pool()

        results = []
        count_file = 0
        for file in files:
            if not Fuzzer.set_parallel_execution:
                print_lines = Fuzzer.process_issue(
                    file, test_library, fuzzer, count_file, fuzz_data
                )
                Fuzzer.print_info(print_lines)
                count_file = count_file + 1
            else:
                result = pool.apply_async(
                    Fuzzer.process_issue, [file, test_library, fuzzer, count_file]
                )
                results += [result]
                count_file = count_file + 1

        if Fuzzer.set_parallel_execution:
            for result in results:
                Fuzzer.print_info(result.get())
            pool.close()
            pool.join()

        Fuzzer.build_report(sourcefiles, files)
        logger.info(
            "===============================FUZZING ENDS================================="
        )
        return fuzz_data
