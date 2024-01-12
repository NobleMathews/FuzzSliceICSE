from glob import glob
import json
import os
import pathlib
import pickle
import re
import shlex
import shutil
import subprocess
from collections import defaultdict
import sys
import time
import yaml
import timeout_decorator

from loguru import logger
from lxml import etree

from build_log_parser import BuildLog

from fuzz import Fuzzer
from fuzz_gen import Generator
from srcml import Srcml, get_name

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
test_library = config["test_library"]
# Use 0 for libfuzzer and 1 for AFL
fuzz_tool = config["fuzz_tool"]
bug_timeline_targets_run = config["bug_timeline_targets_run"]
log_report = config["log_report"]


# cc = "gcc -g -O0 -w -fprofile-generate"
primary_cc = "afl-clang-fast -g -O0 -w -fprofile-instr-generate -fcoverage-mapping"
cc = primary_cc
# cxx = "clang++"
logs: BuildLog

# TODO this needs to be constructed dynamically
includes_locations = (
    os.path.abspath(f"./test_lib/{test_library}/include"),
    os.path.abspath(f"./test_lib/{test_library}"),
    os.path.abspath(f"./test_lib/{test_library}/apps"),
    os.path.abspath(f"./test_lib/{test_library}/apps/include"),
    os.path.abspath(f"./test_lib/{test_library}/testcasesupport"),
)

lib_clone_location = f"./test_lib/{test_library}"
lib_info_location = f"./info_lib/{test_library}"
temp_loc = os.path.abspath(os.path.join(lib_clone_location, "build_ss"))
test_location = f"./workspace/{test_library}/test_files"
rats_log = f"./info_lib/{test_library}/rats_logs"
pickle_name = test_library.replace("/", "_")
pickler = f"./info_lib/{test_library}/{pickle_name}"
unrefined_targets = f"./info_lib/{test_library}/targets-unrefined.txt"
targets = f"./info_lib/{test_library}/targets.txt"
build_log = f"./info_lib/{test_library}/build_logs_fixed"
xml_location = f"./info_lib/{test_library}/srcml.xml"
out_location = f"./info_lib/{test_library}/out"
std_out_location = f"./info_lib/{test_library}/out.txt"
log_location = f"./info_lib/{test_library}_log.txt"

delim = ".@."


class Issue:
    subissue_filemap = {}
    subissue_dir = {}

    def __init__(self, test_loc, file_tloc, line=None, functions=None):
        if functions is None:
            functions = []
        file_loc = file_tloc.replace("./", "")
        test_file_path = os.path.abspath(
            os.path.join(test_loc, test_name(file_loc, line))
        )
        test_file_xml = os.path.abspath(
            os.path.join(
                test_loc,
                test_name(file_loc, line).rsplit(".", 1)[0] + ".xml",
            )
        )
        self.true_location = get_orig_location(os.path.abspath(file_loc))
        # if not os.path.isfile(test_file_path):
        #     shutil.copy(
        #         file_loc,
        #         test_file_path
        #     )
        p = pathlib.Path(file_tloc)
        ref_loc = str(p.relative_to(*p.parts[:2]))
        self.id = file_tloc
        self.testname = test_name(file_loc, line)
        self.ref_loc = ref_loc
        self.orig_line = line
        self.test_file_path = test_file_path
        self.test_file_xml = test_file_xml
        self.location = get_preproc_location(self.true_location)
        self.line = get_preproc_line(self.location, line)
        self.functions = functions
        self.commands = {}
        self.target_line = None
        self.subissue_filemap = {}
        self.subissue_dir = {}

    def remove_subissue_dir(self, loc):
        if os.path.exists(loc):
            shutil.rmtree(loc)

    def subissue(self, sub_file, sub_funcs):
        test_loc = self.test_file_path.rsplit(".", 1)[0]
        assert isinstance(test_loc, str)
        # If we concatenate all missing functions as subdirectory name it can
        # exceed UNIX max name length. Hence just using first missing function as
        # subdir name
        test_loc = os.path.join(test_loc, sub_funcs[0])

        if os.path.basename(sub_file) == os.path.basename(self.id):
            # Prevent main issue references minimized twice
            # We will reminimize the main issue file with updated functions
            os.remove(self.test_file_path)
            self.subissue_filemap[sub_file] = set(self.functions) | set(sub_funcs)
            sub_funcs = list(self.subissue_filemap[sub_file])
            self.functions = sub_funcs
            return self
        elif sub_file not in self.subissue_filemap:
            self.subissue_filemap[sub_file] = set()
            self.subissue_filemap[sub_file] |= set(sub_funcs)
            self.subissue_dir[sub_file] = test_loc
        else:
            # If this file has been minimized before we add the functions required,
            # deleting the subissue directory, and minimize the file again without repeating
            # the file multiple time
            self.remove_subissue_dir(self.subissue_dir[sub_file])
            self.subissue_filemap[sub_file] |= set(sub_funcs)
            sub_funcs = list(self.subissue_filemap[sub_file])
            test_loc = self.subissue_dir[sub_file]
        logger.info("Creating sub issue at {}", test_loc)
        file_tloc = sub_file
        return Issue(test_loc, file_tloc, functions=sub_funcs)

    def add_final_data(self, commands, target_line):
        self.commands = commands
        self.target_line = target_line


def get_preproc_location(file_loc):
    if temp_loc not in file_loc:
        return file_loc.replace(os.path.abspath(lib_clone_location), temp_loc)
    return file_loc


def get_orig_location(file_loc):
    if temp_loc in file_loc:
        return file_loc.replace(temp_loc, os.path.abspath(lib_clone_location))
    return file_loc


# The line number corresponds to original file
# We shall get corresponding line number in preprocessed file
def get_preproc_line(file_loc, line):
    if line == None:
        return None
    line = int(line)

    if not os.path.exists(file_loc):
        return None

    file1 = open(file_loc, "r")
    lines = file1.readlines()
    cur_line = 0
    match_line = 0
    for i, l in enumerate(lines):

        cur_line = cur_line + 1

        if cur_line > line + 3:
            break

        if l.startswith("// "):
            toks = l.split(" ")
            cur_line = int(toks[1]) - 1

        elif cur_line == line:
            match_line = i + 1
    return str(match_line)


def test_name(file_name, lineno):
    if not lineno:
        lineno = ""
    # return lineno + delim + file_name.replace("/", delim)+".c"
    return lineno + delim + file_name.split("/")[-1]


def change_include(f, filename):
    lines = []
    defaults = ["stdio.h", "stddef.h", "string.h", "stdint.h"]
    for i in defaults:
        lines.append("#include <" + i + ">\n")
    with open(f, "r", encoding="UTF-8") as c:
        for line in c.readlines():
            if line.strip().startswith("#") and "include" in line:
                if any(ext in line for ext in defaults):
                    continue
                include_info = line.replace("<", '"').replace(">", '"').split('"')
                # file_location = info_dict[filename].get("location").rsplit("/", 1)[0]
                file_location = os.path.abspath(filename.rsplit("/", 1)[0])
                if len(include_info) >= 2:
                    include_req = include_info[1]
                    new_locs = [os.path.join(file_location, include_req)] + [
                        os.path.join(includes_location, include_req)
                        for includes_location in includes_locations
                    ]
                    for new_loc in new_locs:
                        if os.path.exists(new_loc):
                            new_line = f'#include "{new_loc}"'
                            break
                        else:
                            new_line = line
                else:
                    new_line = line
                    logger.error(f"Unable to fix {include_info}")
            else:
                new_line = line
            lines.append(new_line.strip())
    with open(f, "w", encoding="UTF-8") as c:
        c.write("\n".join(lines))


def run_srcml(target, out, lib_src=None):
    logger.info("Running SrcML on {}", target)
    path_output = pathlib.Path(out)
    pathlib.Path(*path_output.parts[:-1]).mkdir(parents=True, exist_ok=True)
    if lib_src is None:
        if path_output.is_file():
            return
        result = subprocess.run(
            ["srcml", target, "--position", "-o", out], stderr=subprocess.PIPE
        )
        if result.stderr:
            logger.error(result.stderr.decode())
    else:
        # p = pathlib.Path(target)
        # ref_loc = str(p.relative_to(os.path.abspath(".")))
        result = lib_src.nxml(f"./src:unit[@filename='{target}']")
        if result:
            with open(out, "wb") as c:
                c.write(b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n')
                c.write(etree.tostring(result[0]))
        else:
            logger.error("Lib analysis missing file {}", target)


# def genrate_joern():
#     subprocess.run(shlex.split(f"joern-parse {lib_clone_location}"))
#     subprocess.run(shlex.split(f"joern-export --repr cfg --out {out_location}"))


def get_final(target, out):
    if os.path.exists(out):
        return
    result = subprocess.run(["srcml", target, "-o", out], stderr=subprocess.PIPE)
    if result.stderr:
        logger.error(result.stderr.decode())


def add_main(issue, func, concat_locations):
    f = issue.test_file_path
    main_gen = Generator(target_type=fuzz_tool)
    if func["func_name"].startswith("_"):
        func["func_name"] = func["func_name"][1:]

    # Remove main if it already exists
    with open(f, "r+") as fd:
        d = fd.readlines()
        fd.seek(0)
        for i in d:
            fd.write(i)
            if i.strip() == "// Fuzzing wrapper body":
                break
        fd.truncate()

    main_gen.reset_globals(func, issue.commands["compile"], issue.commands["link"], f)
    lines = main_gen.gen_target_function(func, 0)

    # Insert new main
    if lines is None:
        logger.error("Failed to generate runner main for {}", func["func_name"])
        lines = ["int main(){", "return 0;", "}"]
    with open(f, "r+") as f:
        d = f.readlines()
        f.seek(0)
        for i in d:
            f.write(i)
            if i.strip() == "// Fuzzing wrapper body":
                break
        f.truncate()
        f.writelines("\n" + s for s in lines)
    linker_checks(issue, concat_locations, final=True)


def add_temp_main(issue, func):
    f = issue.test_file_path
    main_gen = Generator(target_type=fuzz_tool)
    if func["func_name"].startswith("_"):
        func["func_name"] = func["func_name"][1:]

    # Remove main if it already exists
    with open(f, "r+") as fd:
        d = fd.readlines()
        fd.seek(0)
        for i in d:
            if i.strip() == "// Fuzzing wrapper body":
                break
            fd.write(i)
        fd.truncate()

    main_gen.reset_globals(func, [], [], f)
    lines = main_gen.gen_target_function(func, 0)
    if lines is None:
        logger.error("Failed to generate runner main for {}", func["func_name"])
        lines = ["int main(){", "return 0;", "}"]
    with open(f, "r+") as f:
        d = f.readlines()
        f.seek(0)
        for i in d:
            f.write(i)
        f.truncate()
        f.write("\n// Fuzzing wrapper body\n")
        f.writelines("\n" + s for s in lines)


def find_defs(missing_file_defs, all_defs, concat_locations):
    linker_locs = set()
    for loc, loc_info in concat_locations.items():
        linker_locs = linker_locs.union(loc_info["linker_locs"])
    get_inf = defaultdict(list)
    retrieved = set()
    concerned_files = [
        str(pathlib.Path(get_preproc_location(file))) for file in linker_locs
    ]
    concerned_files_with_s_to_c = []
    for concerned_file in concerned_files:
        if concerned_file.endswith(".s"):
            concerned_files_with_s_to_c.append(concerned_file[:-2] + ".c")
        else:
            concerned_files_with_s_to_c.append(concerned_file)
    concerned_defs = {
        k: v for k, v in all_defs.items() if k in concerned_files_with_s_to_c
    }
    for file, info in concerned_defs.items():
        for missing_file in missing_file_defs:
            calls_in_file = []
            for path in concat_locations:
                if path.endswith(missing_file):
                    # .c specific will not work for cpp files - need to change extension logic throughout
                    test_srcml = Srcml(path[:-2] + ".xml")
                    calls_in_file.extend(
                        [get_name(node) for node in test_srcml.nxml(".//src:call")]
                    )
            for req in missing_file_defs[missing_file]:
                if req not in retrieved:
                    if info.get("_" + req):
                        # Not optimised - choose best match - REMOVE not in retrieved
                        get_inf[file].append("_" + req)
                        logger.debug("Found {} in {}", "_" + req, file)
                        retrieved.add(req)
                    elif info.get("macro " + req):
                        get_inf[file].append("macro " + req)
                        logger.debug("Found {} in {}", "macro " + req, file)
                        retrieved.add(req)
                    elif info.get("struct " + req):
                        get_inf[file].append("struct " + req)
                        logger.debug("Found {} in {}", "struct " + req, file)
                        retrieved.add(req)
                    # The check prevents function declarations from being picked as well
                    # fails if reassigned like ctx->func.emit = poly1305_emit
                    elif req not in calls_in_file and info.get(req):
                        # Not optimised - choose best match - REMOVE not in retrieved
                        get_inf[file].append(req)
                        logger.debug("Found {} in {}", req, file)
                        retrieved.add(req)
    missing_defs = set.union(*missing_file_defs.values())
    if len(retrieved) == len(missing_defs):
        return get_inf
    else:
        logger.error(
            "Failed to fully resolve, could not find: {}", missing_defs - retrieved
        )
        raise FileNotFoundError
        return None


# def construct_concat_locations(issue):
#     default_out = issue.test_file_path[:-2] + ".o"

#     #default_cc = f"afl-clang-fast  -g -O0 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping  -c {issue.test_file_path} -o {default_out}"
#     if "gcc" in cc:
#         default_cc = f"{cc}  -g -O0 -w -fprofile-generate  -c {issue.test_file_path} -o {default_out}"
#     else:
#         default_cc = f"{cc}  -g -O0 -w -fprofile-instr-generate  -c {issue.test_file_path} -o {default_out}"

#     concat_locations = {}
#     compile_command, linker_locs, additional_linker = logs.get_compile_dependencies(
#         issue.location
#     )
#     if not compile_command:
#         compile_command = default_cc
#     concat_locations[issue.test_file_path] = {
#         "compile_command": compile_command,
#         "linker_locs": linker_locs,
#         "additional_keys": additional_linker,
#     }
#     return concat_locations


def minimize_target(lib_src, issue):
    concat_locations = {}
    if issue.line:
        line = int(issue.line)
    else:
        line = None
    run_srcml(issue.location, issue.test_file_xml, lib_src)
    file_src = issue.test_file_xml

    if not os.path.exists(file_src):
        logger.error("Entire file not built: {}", file_src)
        return None, None

    unit_srcml = Srcml(file_src)

    loc_name = issue.location
    defined_funcs = set(lib_src.decl_info[loc_name].keys())
    func = {}
    # func = {
    #        "params": [
    #           {
    #               "param_name":
    #               "param_type":
    #               "generator_type":
    #               "array_size":
    #               "parent_type":
    #               "parent_gen":
    #               "param_usage":
    #           }
    #        ],
    #        "return_type":,
    #        "func_name":
    # }
    if line:
        unit_srcml.mark(line)
        function = lib_src.get_enclosing_function(loc_name, line, defined_funcs)
        if function is None:
            logger.error("Enclosing Function does not exist")
            return None, None

        func["func_name"] = function.name
        func["return_type"] = function.type
        func["params"] = function.params(function.parameter)
        req_functions = [function.name]
        if issue.functions:
            req_functions = req_functions + issue.functions
    else:
        req_functions = issue.functions

    if req_functions == []:
        logger.error(
            "Function within file not built. Failed to find enclosing function for file: {}",
            file_src,
        )
        return None, None

    retain_set = set()
    used_types = set()
    new_function_refs = set(req_functions)

    while new_function_refs:
        for target_func in new_function_refs:
            retain_set = retain_set.union([target_func])
            retain_set = retain_set.union(
                lib_src.get_calls_recursively(
                    loc_name,
                    target_func,
                )
            )
            used_types = used_types.union(
                lib_src.get_used_types(loc_name, target_func, used_types, line)
            )

        # for used in list(used_types):
        #     target_func = "_"+used
        #       need not be defined in the file itself
        #     if target_func in defined_funcs:
        #         retain_set = retain_set.union(lib_src.get_calls_recursively(
        #             loc_name, target_func,
        #         ))
        #         used_types = used_types.union(lib_src.get_used_types(loc_name, target_func, line))

        for f_str in retain_set.union(used_types):
            used_types = used_types.union(
                lib_src.get_used_types(loc_name, f_str, used_types)
            )

        # These are function pointers needed to be preserved
        new_function_refs = (
            lib_src.internal_function_references(loc_name, used_types, line)
            - retain_set
            - used_types
        )
    drop_set = defined_funcs - retain_set - used_types
    # USED TYPES not completely removed due to partial definition
    for struct_def in defined_funcs:
        if struct_def.startswith("struct ") and struct_def in drop_set:
            drop_set.remove(struct_def)
    if "_original_main" not in req_functions:
        drop_set.add("_main")
    for target_func in req_functions:
        function_info = lib_src.decl_info[loc_name].get(target_func)
        drop_set.discard(target_func)
        drop_set.discard(function_info.type)

    unit_srcml.drop(drop_set, used_types)

    unit_srcml.trim(req_functions[0], line)

    unit_srcml.save(file_src)
    get_final(file_src, issue.test_file_path)
    change_include(issue.test_file_path, loc_name)
    if line:
        # fix_ifdefs(issue.test_file_path, func["func_name"])
        add_temp_main(issue, func)
        concat_locations = handle_missing_links(issue, lib_src)
    return func, concat_locations


def build_compile_command(
    compiler, compile_opts, compile_target, compile_out, link=False
):
    ignore_opts = ("-O",)
    opts = " ".join(
        [req_opts for req_opts in compile_opts if not req_opts.startswith(ignore_opts)]
    )

    if not link:
        return (
            f"{compiler} {opts} -O0 -w -c {' '.join(compile_target)} -o {compile_out}"
        )
    else:
        return f"{compiler} {opts} -w {' '.join(compile_target)} -o {compile_out}"


def handle_missing_links(issue, lib_src, concat_locations=None):
    # if "gcc" in cc:
    #     additional_opts = ["-g", "-O0", "-w", "-fprofile-generate"]
    # #     default_cc = f"{cc}  -g -O0 -w -fprofile-generate  -c {issue.test_file_path} -o {default_out}"
    # else:
    #     additional_opts = ["-g", "-O0", "-w", "-fprofile-instr-generate"]
    # #     default_cc = f"{cc}  -g -O0 -w -fprofile-instr-generate  -c {issue.test_file_path} -o {default_out}"
    if concat_locations is None:
        concat_locations = {}
        # wrong issue location sent here
        compile_command, linker_locs, additional_linker = logs.get_compile_dependencies(
            issue.location
        )
        # if not compile_command:
        #     compile_command = default_cc
        compile_opts = compile_command
        # + additional_opts
        # compile_command = build_compile_command(compiler=cc, compile_opts=compile_opts, compile_target=issue.test_file_path, compile_out=(issue.test_file_path[:-2] + ".o"))
        concat_locations[issue.test_file_path] = {
            "compile_command": compile_opts,
            "linker_locs": linker_locs,
            "additional_keys": additional_linker,
        }
    missing_defs = linker_checks(issue, concat_locations, link=True)
    # TODO Review
    # if "gcc" in cc:
    #     default_cc = f"{cc}  -g -O0 -w -fprofile-generate  -c {issue.test_file_path} -o {default_out}"
    # else:
    #     default_cc = f"{cc}  -g -O0 -w -fprofile-instr-generate  -c {issue.test_file_path} -o {default_out}"
    #
    # if not(concat_locations):
    #     concat_locations = construct_concat_locations(issue)
    # missing_defs = linker_checks(concat_locations)
    if missing_defs and len(missing_defs) != 0:
        logger.info("Missing defs: {}", missing_defs)
        file_dict_targets = find_defs(missing_defs, lib_src.decl_info, concat_locations)
        if file_dict_targets:
            logger.info("Missing defs obtained across {} files", len(file_dict_targets))
            for sub_file, sub_funcs in file_dict_targets.items():
                new_issue = issue.subissue(sub_file, sub_funcs)
                succeeded, _ = minimize_target(lib_src, new_issue)
                if succeeded is None:
                    return concat_locations
                (
                    compile_command,
                    linker_locs,
                    additional_linker,
                ) = logs.get_compile_dependencies(new_issue.location)
                # if not compile_command:
                # compile_command = default_cc
                concat_locations[new_issue.test_file_path] = {
                    "compile_command": compile_command,
                    "linker_locs": linker_locs,
                    "additional_keys": additional_linker,
                }
        else:
            return None
        handle_missing_links(issue, lib_src, concat_locations=concat_locations)
    return concat_locations


def remove_binary(issue):
    file_root = (issue.testname).split(".")[0]
    object_file = file_root + ".o"
    binary_file = file_root + ".out"
    if os.path.isfile(object_file):
        os.remove(object_file)
    if os.path.isfile(binary_file):
        os.remove(binary_file)


def ignore_extended_attributes(func, filename, exc_info):
    is_meta_file = os.path.basename(filename).startswith("._")
    if not (func is os.unlink and is_meta_file):
        raise


def analyze(srcml: Srcml, issues):
    global cc
    logger.success("Library analysis complete")
    if os.path.exists(test_location):
        shutil.rmtree(test_location, onerror=ignore_extended_attributes)
    os.makedirs(test_location)
    if bug_timeline_targets_run:
        bug_timeline_targets = []
        for issue in issues:
            if issue.line:
                defined_funcs = set(srcml.decl_info[issue.location].keys())
                function = srcml.get_enclosing_function(issue.location, int(issue.line), defined_funcs)
                if function is not None:
                    bug_timeline_targets.append(f"-L{function.name[1:]},{issue.orig_line}:{issue.ref_loc}")
        with open(f"tools/bug_timeline/{test_library}_targets", "w", encoding="UTF-8") as c:
            c.write("\n".join(bug_timeline_targets))
        sys.exit(0)
    for issue in issues:
        try:
            logger.info("")
            logger.info("")
            logger.info(
                "================================New Issue================================"
            )
            logger.info("Testing :" + issue.test_file_path)

            if fuzz_tool == 1:
                cc = "gcc -fprofile-arcs -ftest-coverage"
                func, concat_locations = minimize_target(srcml, issue)
                if func is None:
                    continue
                logger.info(
                    "================================Compiling copy with coverage instrumentation================================"
                )
                # Switch the compiler to afl-clang
                # cc = "gcc -fsanitize=address,undefined -fprofile-arcs -ftest-coverage"
                # concat_locations = construct_concat_locations(issue)
                add_main(issue, func, concat_locations)

                if os.path.exists(issue.test_file_path[:-2] + ".out"):
                    os.rename(
                        issue.test_file_path[:-2] + ".out",
                        issue.test_file_path[:-2] + ".cov",
                    )
                if os.path.exists(
                    os.path.basename(issue.test_file_path[:-2] + ".gcno")
                ):
                    os.rename(
                        os.path.basename(issue.test_file_path[:-2] + ".gcno"),
                        issue.test_file_path[:-2] + ".gcno",
                    )

                logger.info(
                    " ================================Now compiling with AFL body ==============================================="
                )
                # Switch the compiler to afl-clang
                cc = "afl-clang-fast -g -O0 -w -fprofile-instr-generate -fcoverage-mapping"
                # concat_locations = construct_concat_locations(issue)
                add_main(issue, func, concat_locations)
            else:
                # Compile with libclang
                cc = "clang -fsanitize=fuzzer,address -fsanitize-recover=address -fprofile-instr-generate -fcoverage-mapping -g"
                func, concat_locations = minimize_target(srcml, issue)
                if func is None:
                    continue
                remove_binary(issue)
                # concat_locations = construct_concat_locations(issue)
                add_main(issue, func, concat_locations)

            # concat_locs.append(issue.test_file_path)
            # compile_command, linker_locs, additional_linker = process_compile_command(issue.ref_loc)
            # with open(issue.test_file_path[:-2] + "_final.c", 'wb') as wfd:
            #     for f in concat_locs:
            #         with open(f, 'rb') as fd:
            #             shutil.copyfileobj(fd, wfd)
            #             wfd.write(b"\n")
            # linker_checks(compile_command, final=True)
        except FileNotFoundError:
            continue


def run_rats():
    logger.info("Running Rats")
    with open(rats_log + "_status", "wb") as e:
        with open(rats_log, "wb") as c:
            subprocess.run(
                ["rats", "-l", "c"]
                + glob(lib_clone_location + "/**/*.c", recursive=True),
                stdout=c,
                stderr=e,
            )


def run_clang_format():
    logger.info("Running Formatter")
    subprocess.run(
        ["./clang-format-all", "./workspace"],
        # stdout=subprocess.DEVNULL,
        # stderr=subprocess.DEVNULL,
    )


def linker_checks(issue, concat_locations, link=True, final=False):
    out_locations = []
    commands_used = {"compile": [], "link": []}

    # add_loc_keys = set()
    # if len(concat_locations) == 1:
    #     loc = list(concat_locations)[0]
    #     out_loc = loc[:-2] + ".o"
    #     out_locations.append(out_loc)
    # else:
    target_line = None
    with open(issue.test_file_path, "r+") as f:
        d = f.readlines()
        for line, i in enumerate(d, 1):
            if "//target_line" in i:
                target_line = line
                break
    if concat_locations is None:
        issue.add_final_data(commands_used, target_line)
        return {}
    for loc, loc_info in concat_locations.items():
        if loc_info["compile_command"]:
            out_loc = loc[:-2] + ".o"
            out_locations.append(out_loc)
        if os.path.exists(out_loc):
            logger.warning("Overwriting compile target {}", out_loc)
            # continue
        # if loc_info["additional_keys"]:
        # add_loc_keys = add_loc_keys.union(loc_info["additional_keys"])
        # add_loc_keys = loc_info["additional_keys"]
        command = build_compile_command(cc, loc_info["compile_command"], [loc], out_loc)
        # else:
        #     command = loc_info["compile_command"] + f" -w -c {loc} -o {out_loc}"
        logger.debug(command)
        commands_used["compile"].append(command)
        result = subprocess.run(shlex.split(command), stderr=subprocess.PIPE)
        # if result.stderr:
        #     decoded_error = result.stderr.decode()
        #     logger.error(decoded_error)
        #     issue.add_final_data(commands_used, target_line)
        #     return {}
    if not link:
        issue.add_final_data(commands_used, target_line)
        return {}

    command = build_compile_command(
        # +" -fuse-ld=lld -Wl,--no-demangle"
        cc,
        loc_info["compile_command"] + loc_info["additional_keys"],
        out_locations,
        f"{out_locations[0][:-2]}.out",
        True,
    )
    # #command = f"{cc}  -g -O0 -fprofile-instr-generate -fcoverage-mapping  {' '.join(add_loc_keys)} -o {out_locations[0][:-2]}.out {' '.join(out_locations)}"
    logger.info(command)
    commands_used["link"].append(command)
    result = subprocess.run(shlex.split(command), stderr=subprocess.PIPE)
    issue.add_final_data(commands_used, target_line)
    if result.stderr:
        decoded_error = result.stderr.decode()
        dct = defaultdict(set)
        for line in decoded_error.splitlines():
            if not final and "Undefined symbols" in line:
                failed_symbol = re.compile('"([^"]+)", referenced from')
                matched = failed_symbol.findall(line)[0]
                filename_matched = line.rsplit(" in ")[-1]
                dct[filename_matched.strip()].add(matched)
            if not final and "undefined reference to" in line:
                failed_symbol = re.compile("undefined reference to `([^`']+)'")
                matched = failed_symbol.findall(line)[0]
                if line.split(":")[0].endswith("ld"):
                    filename_matched = line.split(":")[1]
                else:
                    filename_matched = line.split(":")[0]
                dct[filename_matched.strip()].add(matched)
        if dct:
            return dct
        else:
            logger.error(decoded_error)
            return {}
    else:
        logger.success(
            "Completed processing with final file at {}", f"{out_locations[0][:-2]}.out"
        )
        return {}


def create_build_log(raw_log):
    logger.info("Started build")
    os.makedirs(raw_log.rsplit("/", 1)[0], exist_ok=True)
    #     child_make = os.path.join(lib_clone_location, "child.mk")
    #     if not os.path.exists(child_make):
    #         with open(child_make, "w") as e:
    #             x = """\
    # include Makefile

    # CC = gcc -save-temps
    # CXX = g++ -save-temps
    # """
    #             e.write(x)
    # with open(raw_log + "_error", "w", encoding="UTF-8") as e:
    # with open(raw_log, "w", encoding="UTF-8") as c:
    # my_env = os.environ.copy()
    # -temp-dir for llvm only?
    # my_env["CC"] = f"gcc -save-temps"
    # my_env["CXX"] = f"g++ -save-temps"
    if not os.path.exists(temp_loc):
        os.makedirs(temp_loc)
    # make clean removed since it no longer handles all the files in this dir without mod
    subprocess.run(
        'CC="clang -save-temps" CXX="clang++ -save-temps" ../configure',
        # env=my_env,
        cwd=temp_loc,
        # stdout=devnull,
        # stderr=e,
        shell=True,
    )

    subprocess.run(
        f"bear make all > {os.path.abspath(raw_log)} 2>&1",
        # env=my_env,
        cwd=temp_loc,
        # stdout=c,
        # stderr=e,
        shell=True,
        errors="ignore",
    )

    logger.info("Build Log created")


def fix_build_log():
    raw_log = build_log.replace("_fixed", "")
    if not os.path.exists(raw_log):
        create_build_log(raw_log)
    # DOES NOT WORK PROPERLY COMPARED TO BEAR
    # subprocess.run(
    #     f"compiledb --parse build_logs",
    #     # env=my_env,
    #     cwd=lib_info_location,
    #     # stdout=c,
    #     # stderr=e,
    #     shell=True,
    #     errors='ignore'
    # )
    with open(raw_log, "r", encoding="utf-8", errors="ignore") as fp:
        data = fp.read()
        lines = data.replace("\\\n", "").splitlines()
        lines = [x + "\n" for x in lines]
    with open(build_log, "w", encoding="utf-8") as fp:
        fp.writelines(lines)
    logger.info("Build Log fixed")


# __attribute__ macros are misparsed by srcml. this function fixes that
def fix_attribute_srcml_parse(s):
    if "__attribute__" in s:
        ret = ""
        skip = 0
        find_pattern = 0
        seq_found = 0
        for i in range(len(s)):
            c = s[i]
            if i + 13 < len(s) and s[i : i + 13] == "__attribute__":
                find_pattern = 1
                seq_found = 0
            if find_pattern == 1:
                if c == "(":
                    skip += 1
                    seq_found = 1
                    continue
                elif c == ")" and skip > 0:
                    skip -= 1
                    continue
                elif skip == 0 and seq_found == 1:
                    find_pattern = 0
                else:
                    continue
            ret = ret + c
        return ret
    return s


# Some lines with """ in them are misparsed by srcml. This function rectifies that.
def fix_quote_srcml_parse(line):
    matches = re.search(r'"[^"]*"[\s]*"', line)
    result = line
    if matches:
        # Final string that is result of operation
        result = ""
        # Number of " marks that we've encountered after an opening " mark was seen
        count = 0
        # If it is set it means that we have seen an opening " mark and need to close it
        close = 0
        # Number of newlines between adjoining " marks
        newlines = 0
        # if there is '"' then " must be ignored. when set this enables that
        ignore = 0
        i = 0
        while i < len(line):
            c = line[i]
            if c == "'":
                if ignore == 0:
                    # Concatenate " marks together
                    if count > 0:
                        if count % 2 == 0:
                            result = result + ""
                        else:
                            result = result + '"'
                            close = 0
                    count = 0
                    ignore = 1
                else:
                    ignore = 0

            if ignore == 1:
                result = result + c
                i = i + 1
                continue

            if c == '"':
                if close == 1:
                    count = count + 1
                elif close == 0:
                    close = 1
                    result = result + '"'
            elif c == " ":
                if count == 0:
                    result = result + c
            elif c == "\n":
                if count == 0:
                    result = result + c
                else:
                    newlines = newlines + 1
            elif c == "\t":
                if count == 0:
                    result = result + c
            # In presence of backslash ignore effect of next character
            elif c == "\\":
                result = result + c
                c = line[i + 1]
                result = result + c
                i = i + 1
            else:
                # Concatenate " marks together
                if count > 0:
                    if count % 2 == 0:
                        result = result + ""
                    else:
                        result = result + '"'
                        close = 0
                count = 0
                result = result + c
            i = i + 1

        # End
        if count > 0:
            if count % 2 == 0:
                result = result + ""
            else:
                result = result + '"'
                close = 0
        for j in range(newlines):
            result = result + "\n"

    return result


# Split file into parts ending with ; and comments to correct later
def identify_break_points(whole):
    char_to_close = ""
    breaks = []
    ignore = 0

    i = 0
    while i < len(whole):
        c = whole[i]
        if ignore == 1 and c == char_to_close:
            ignore = 0
        elif ignore == 0 and c == "'":
            ignore = 1
            char_to_close = "'"
        elif ignore == 0 and c == '"':
            ignore = 1
            char_to_close = '"'
        elif c == "\\":
            i = i + 2
            continue

        if ignore == 1:
            i = i + 1
            continue

        if c == ";":
            breaks.append(i)
        elif c == "#":
            while whole[i] != "\n":
                i = i + 1
            breaks.append(i - 1)
        elif c == "/":
            i = i + 1
            if whole[i] == "/":
                while whole[i] != "\n":
                    i = i + 1
                breaks.append(i - 1)
            if whole[i] == "*":
                while (whole[i] != "/") or (whole[i - 1] != "*"):
                    i = i + 1
                while whole[i] != "\n":
                    i = i + 1
                breaks.append(i - 1)

        i = i + 1

    parts = []
    start = 0
    end = -1
    for i in breaks:
        end = i + 1
        parts.append(whole[start:end])
        start = end
    parts.append(whole[end : len(whole) - 1])
    return parts


def fix_srcml_bugs(lines):
    whole = "".join(lines)
    output = []

    # Ensure not splitting by quotation within '' through lookahead
    parts = identify_break_points(whole)
    for line in parts:
        # Do not handle single quotes ' can still have the same issue
        result = fix_quote_srcml_parse(line)
        result = fix_attribute_srcml_parse(result)
        if ".__sigaction_handler" in result:
            result = result.replace(".__sigaction_handler", "")
        output.append(result)
    whole = "".join(output)
    return whole


def prep_preprocessed_output(location):
    # .ii in cxx?
    # prune included stuff and
    for p in pathlib.Path(location).rglob("*.i"):
        path = str(p)
        if os.path.basename(path).startswith("._"):
            continue
        lines = []
        local_headers = {}
        src_name = ""
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            data = fp.read()
            not_skip = True
            for l in data.splitlines():
                if l.startswith("# "):
                    toks = l.strip().split(" ")
                    _linenum = toks[1]
                    filename = toks[2]
                    filename = filename.strip('"')
                    filename = re.sub(r"(../)\1+", r"\1", filename)
                    # Headers with inc extension should be added as is
                    if filename.endswith(".inc") or filename.endswith(".y"):
                        not_skip = True
                        continue
                    if len(toks) >= 4:
                        status = toks[3]
                        if status == "1":
                            basename = os.path.basename(filename)
                            value = os.path.abspath(os.path.join(temp_loc, filename))
                            if basename in local_headers:
                                # This is a local header
                                if os.path.abspath(lib_clone_location) in value:
                                    for i, includeline in enumerate(
                                        local_headers[basename]
                                    ):
                                        search = includeline
                                        search = search.replace("<", '"')
                                        search = search.replace(">", '"')
                                        result = re.search('"(.*)"', search)
                                        if result.group(1):
                                            headerfile = os.path.normpath(result.group(1)).replace("../","")
                                            if headerfile in value:
                                                lines.append(f'#include "{value}"\n')
                                                local_headers[basename].pop(i)
                                                break
                                # This is stdlib
                                else:
                                    for includeline in local_headers[basename]:
                                        lines.append(includeline + "\n")
                                    local_headers.pop(basename, None)

                    if not src_name:
                        src_name = filename
                        # If make is moving into another directory and executing it will cause issues
                        # ../ replace ensures this doesnt cause issues
                        append_name = src_name.replace("../", "")
                        if os.path.isfile(
                            os.path.join(lib_clone_location, append_name)
                        ):
                            orig_file = open(
                                os.path.join(lib_clone_location, append_name), "r"
                            )
                        elif os.path.isfile(
                            os.path.join(lib_clone_location, "build_ss", append_name)
                        ):
                            orig_file = open(
                                os.path.join(
                                    lib_clone_location, "build_ss", append_name
                                )
                            )
                        else:
                            continue
                        src_lines = orig_file.readlines()
                        for line in src_lines:
                            line = line.strip()
                            if line.startswith("#") and ("include" in line):
                                search = line
                                search = search.replace("<", '"')
                                search = search.replace(">", '"')
                                result = re.search('"(.*)"', search)
                                if result.group(1):
                                    headerfile = os.path.basename(result.group(1))
                                    if headerfile in local_headers:
                                        if line not in local_headers[headerfile]:
                                            local_headers[headerfile].append(line)
                                    elif headerfile not in local_headers:
                                        local_headers[headerfile] = [line]
                    _flags = toks[3:]
                    not_skip = src_name == filename
                if not_skip:
                    if l.startswith("# "):
                        lines.append(l.replace("# ", "// ") + "\n")
                    else:
                        lines.append(l + "\n")

        src_name = src_name.replace("../", "")

        fixed_lines = fix_srcml_bugs(lines)
        with open(os.path.join(temp_loc, src_name), "w") as fp:
            fp.write(fixed_lines)
        files = [path.rsplit(".", 1)[0] + ext for ext in (".i", ".s", ".d")]
        for f in files:
            if os.path.exists(f):
                os.rename(f, f + "preprocessed")


def remove_linemarkers(inputFileName):

    with open(inputFileName, "r") as fp:
        lines = fp.readlines()

    with open(inputFileName, "w") as fp:
        for line in lines:
            if not line.lstrip().startswith("// "):
                fp.write(line)


if __name__ == "__main__":
    os.makedirs(lib_info_location, exist_ok=True)
    if not os.path.exists(build_log):
        fix_build_log()
    # if not os.path.exists(rats_log):
    #     run_rats()
    logs = BuildLog(build_log, temp_loc, lib_info_location)
    prep_preprocessed_output(temp_loc)
    run_srcml(temp_loc, xml_location)
    logger.success("Beginning analysis for Srcml library file")
    lib_srcml = None
    if not os.path.exists(pickler):
        lib_srcml = Srcml(xml_location)
        logger.success("Proceeding to fix srcML output")
        lib_srcml.fix_srcml(xml_location)
        lib_srcml.get_all_defined_functions_and_range()
        logger.success("Picking data")
        with open(pickler, "wb") as pickle_f:
            pickle.dump(lib_srcml, pickle_f)
    if lib_srcml is None:
        with open(pickler, "rb") as pickle_f:
            lib_srcml = pickle.load(pickle_f)
    issues = []
    with open(targets, "r", encoding="UTF-8") as f:
        for line in f.readlines():
            if line.startswith("#") or not line.startswith("./"):
                continue
            location_info = line.split(" ")[0]
            file_tloc, lineno, *_ = location_info.split(":")
            if not file_tloc.endswith(".c"):
                continue
            issues.append(Issue(test_location, file_tloc, lineno))
    if not log_report:
        analyze(lib_srcml, issues)
        try:
            Fuzzer.fuzz_binaries(test_library, fuzz_tool)
        except timeout_decorator.TimeoutError:
            logger.error("Fuzzing timed out")
    else:
        for issue in issues:
            start = time.time()
            analyze(lib_srcml, [issue])
            compilable_slice = time.time()
            try:
                fuzz_data = Fuzzer.fuzz_binaries(test_library, fuzz_tool)
            except timeout_decorator.TimeoutError:
                fuzz_data = {"timed_out":True}
            fuzzing_ends = time.time()
            fuzz_data["time_compile"] = compilable_slice - start
            fuzz_data["time_fuzz"] = fuzzing_ends - compilable_slice
            fuzz_data["time_total"] = fuzzing_ends - start
            fuzz_data["issue"] = issue.id + ":" + str(issue.orig_line)
            with open(log_location, "a") as fp:
                fp.write(json.dumps(fuzz_data)+"\n")
    # for filename in iglob(test_location+'/**/*.c*',
    #                        recursive = True):
    #     remove_linemarkers(filename)
    # run_clang_format()
