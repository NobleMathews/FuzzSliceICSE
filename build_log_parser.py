import glob
import json
import os
import re
import shlex
import yaml

# from code import compile_command
# from compileall import compile_file

import numpy as np
from loguru import logger

keep_gcc_include_fixed = False
keep_gcc_intrin = False

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
test_library = config["test_library"]

def get_language_map(extension):
    # TODO: There are even more in the man page of gcc.
    mapping = {
        ".c": "c",
        ".cp": "c++",
        ".cpp": "c++",
        ".cxx": "c++",
        ".txx": "c++",
        ".cc": "c++",
        ".C": "c++",
        ".ii": "c++",
        ".m": "objective-c",
        ".mm": "objective-c++",
    }
    return mapping.get(extension)


def is_not_include_fixed(dirname):
    """
    This function returns True in case the given dirname is NOT a GCC-specific
    include-fixed directory containing standard headers.
    """
    return os.path.basename(os.path.normpath(dirname)) != "include-fixed"


def contains_no_intrinsic_headers(dirname):
    """
    Returns True if the given directory doesn't contain any intrinsic headers.
    """
    if not os.path.exists(dirname):
        return True
    if glob.glob(os.path.join(dirname, "*intrin.h")):
        return False
    return True


class BuildAction:
    """
    The objects of this class hold information which is the input of the
    analyzer engines.
    """

    __slots__ = [
        "analyzer_options",
        "compiler_includes",
        "compiler_standard",
        "analyzer_type",
        "original_command",
        "directory",
        "output",
        "lang",
        "target",
        "source",
        "arch",
        "action_type",
    ]

    LINK = 0
    COMPILE = 1
    PREPROCESS = 2
    INFO = 3

    def __init__(self, **kwargs):
        # Filtered list of options.
        for slot in BuildAction.__slots__:
            super(BuildAction, self).__setattr__(slot, kwargs[slot])

    def __str__(self):
        # For debugging.
        return (
            "\nOriginal command: {0},\n"
            "Analyzer type: {1},\n Analyzer options: {2},\n"
            "Directory: {3},\nOutput: {4},\nLang: {5},\nTarget: {6},\n"
            "Source: {7}"
        ).format(
            self.original_command,
            self.analyzer_type,
            self.analyzer_options,
            self.directory,
            self.output,
            self.lang,
            self.target,
            self.source,
        )

    def __setattr__(self, attr, value):
        if hasattr(self, attr) and getattr(self, attr) != value:
            raise AttributeError("BuildAction is immutable")
        super(BuildAction, self).__setattr__(attr, value)

    def __eq__(self, other):
        return other.original_command == self.original_command

    def to_dict(self):
        """Reverting to original compilation database
        record for JSON conversion.
        """
        return {
            "command": self.original_command,
            "directory": self.directory,
            "file": self.source,
        }

    def __hash__(self):
        """
        If the compilation database contains the same compilation action
        multiple times it should be checked only once.
        Use this key to compare compilation commands for the analysis.
        """
        hash_content = []
        hash_content.extend(self.analyzer_options)
        hash_content.append(str(self.analyzer_type))
        hash_content.append(self.target)
        hash_content.append(self.source)
        return hash("".join(hash_content))

    def with_attr(self, attr, value):
        details = {key: getattr(self, key) for key in BuildAction.__slots__}
        details[attr] = value
        return BuildAction(**details)


SOURCE_EXTENSIONS = {".c", ".cc", ".cp", ".cpp", ".cxx", ".c++", ".o", ".so", ".a"}

# Replace gcc/g++ build target options with values accepted by Clang.
REPLACE_OPTIONS_MAP = {
    "-mips32": ["-target", "mips", "-mips32"],
    "-mips64": ["-target", "mips64", "-mips64"],
    "-mpowerpc": ["-target", "powerpc"],
    "-mpowerpc64": ["-target", "powerpc64"],
}

# The compilation flags of which the prefix is any of these regular expressions
# will not be included in the output Clang command.
# These flags should be ignored only in case the original compiler is clang.
IGNORED_OPTIONS_CLANG = [
    # Clang gives different warnings than GCC. Thus if these flags are kept,
    # '-Werror', '-pedantic-errors' the analysis with Clang can fail even
    # if the compilation passes with GCC.
    "-save-temps",
    "-Werror",
    "-pedantic-errors",
    # Remove '-w' the option supressing the warnings.
    # This suppressing mechanism is independent of
    # checker enabling/disabling (-W, -W-no), and
    # cannot be overridden by those.
    # '-w'
]

# The compilation flags of which the prefix is any of these regular expressions
# will not be included in the output Clang command.
# These flags should be ignored only in case the original compiler is gcc.
IGNORED_OPTIONS_GCC = [
    # --- UNKNOWN BY CLANG --- #
    "-fallow-fetchr-insn",
    "-fcall-saved-",
    "-fcond-mismatch",
    "-fconserve-stack",
    "-fcrossjumping",
    "-fcse-follow-jumps",
    "-fcse-skip-blocks",
    "-fcx-limited-range$",
    "-fext-.*-literals",
    "-ffixed-r2",
    "-ffp$",
    "-mfp16-format",
    "-fgcse-lm",
    "-fhoist-adjacent-loads",
    "-findirect-inlining",
    "-finline-limit",
    "-finline-local-initialisers",
    "-fipa-sra",
    "-fmacro-prefix-map",
    "-fno-aggressive-loop-optimizations",
    "-fno-canonical-system-headers",
    "-fno-delete-null-pointer-checks",
    "-fno-defer-pop",
    "-fno-extended-identifiers",
    "-fno-jump-table",
    "-fno-keep-static-consts",
    "-f(no-)?reorder-functions",
    "-fno-strength-reduce",
    "-fno-toplevel-reorder",
    "-fno-unit-at-a-time",
    "-fno-var-tracking-assignments",
    "-fobjc-link-runtime",
    "-fpartial-inlining",
    "-fpeephole2",
    "-fr$",
    "-fregmove",
    "-frename-registers",
    "-frerun-cse-after-loop",
    "-fs$",
    "-fsched-spec",
    "-fstack-usage",
    "-fstack-reuse",
    "-fthread-jumps",
    "-ftree-pre",
    "-ftree-switch-conversion",
    "-ftree-tail-merge",
    "-m(no-)?abm",
    "-m(no-)?sdata",
    "-m(no-)?spe",
    "-m(no-)?string$",
    "-m(no-)?dsbt",
    "-m(no-)?fixed-ssp",
    "-m(no-)?pointers-to-nested-functions",
    "-mno-fp-ret-in-387",
    "-mpreferred-stack-boundary",
    "-mpcrel-func-addr",
    "-mrecord-mcount$",
    "-maccumulate-outgoing-args",
    "-mcall-aixdesc",
    "-mppa3-addr-bug",
    "-mtraceback=",
    "-mtext=",
    "-misa=",
    "-mfunction-return=",
    "-mindirect-branch-register",
    "-mindirect-branch=",
    "-mfix-cortex-m3-ldrd$",
    "-mmultiple$",
    "-msahf$",
    "-mskip-rax-setup$",
    "-mthumb-interwork$",
    "-mupdate$",
    # Deprecated ARM specific option
    # to Generate a stack frame that is compliant
    # with the ARM Procedure Call Standard.
    "-mapcs",
    "-fno-merge-const-bfstores$",
    "-fno-ipa-sra$",
    "-mno-thumb-interwork$",
    # ARM specific option.
    # Prevent the reordering of
    # instructions in the function prologue.
    "-mno-sched-prolog",
    # This is not unknown but we want to preserve asserts to improve the
    # quality of analysis.
    "-DNDEBUG$",
    # --- IGNORED --- #
    "-save-temps",
    # Clang gives different warnings than GCC. Thus if these flags are kept,
    # '-Werror', '-pedantic-errors' the analysis with Clang can fail even
    # if the compilation passes with GCC.
    "-Werror",
    "-pedantic-errors",
    # Remove the option disabling the warnings.
    # '-w',
    "-g(.+)?$",
    # Link Time Optimization:
    "-flto",
    # MicroBlaze Options:
    "-mxl",
    # PowerPC SPE Options:
    "-mfloat-gprs",
    "-mabi",
]

IGNORED_OPTIONS_GCC = re.compile("|".join(IGNORED_OPTIONS_GCC))
IGNORED_OPTIONS_CLANG = re.compile("|".join(IGNORED_OPTIONS_CLANG))

# The compilation flags of which the prefix is any of these regular expressions
# will not be included in the output Clang command. These flags have further
# parameters which are also omitted. The number of parameters is indicated in
# this dictionary.
IGNORED_PARAM_OPTIONS = {
    re.compile("-install_name"): 1,
    re.compile("-exported_symbols_list"): 1,
    re.compile("-current_version"): 1,
    re.compile("-compatibility_version"): 1,
    re.compile("-init$"): 1,
    re.compile("-e$"): 1,
    re.compile("-seg1addr"): 1,
    re.compile("-bundle_loader"): 1,
    re.compile("-multiply_defined"): 1,
    re.compile("-sectorder"): 3,
    re.compile("--param$"): 1,
    re.compile("-u$"): 1,
    re.compile("--serialize-diagnostics"): 1,
    re.compile("-framework"): 1,
    # Darwin linker can be given a file with lists the sources for linking.
    re.compile("-filelist"): 1,
}


COMPILE_OPTIONS = [
    "-nostdinc",
    r"-nostdinc\+\+",
    "-pedantic",
    "-O[1-3]",
    "-Os",
    "-std=",
    "-stdlib=",
    "-f",
    "-m",
    "-Wno-",
    "--sysroot=",
    "-sdkroot",
    "--gcc-toolchain=",
]

COMPILE_OPTIONS = re.compile("|".join(COMPILE_OPTIONS))

COMPILE_OPTIONS_MERGED = [
    "--sysroot",
    "-sdkroot",
    "--include",
    "-include",
    "-iquote",
    "-[DIUF]",
    "-idirafter",
    "-isystem",
    "-imacros",
    "-isysroot",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
]

INCLUDE_OPTIONS_MERGED = [
    "-iquote",
    "-[IF]",
    "-isystem",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
]

XCLANG_FLAGS_TO_SKIP = [
    "-module-file-info",
    "-S",
    "-emit-llvm",
    "-emit-llvm-bc",
    "-emit-llvm-only",
    "-emit-llvm-uselists",
    "-rewrite-objc",
]

COMPILE_OPTIONS_MERGED = re.compile("(" + "|".join(COMPILE_OPTIONS_MERGED) + ")")

INCLUDE_OPTIONS_MERGED = re.compile("(" + "|".join(INCLUDE_OPTIONS_MERGED) + ")")


PRECOMPILATION_OPTION = re.compile("-(E|M[G|T|Q|F|J|P|V|M]*)$")

# Match for all of the compiler flags.
CLANG_OPTIONS = re.compile(".*")


def del_list_numpy(list_main, id_to_del):
    arr = np.array(list_main)
    return list(np.delete(arr, id_to_del))


def is_not_include_fixed(dirname):
    """
    This function returns True in case the given dirname is NOT a GCC-specific
    include-fixed directory containing standard headers.
    """
    return os.path.basename(os.path.normpath(dirname)) != "include-fixed"


def contains_no_intrinsic_headers(dirname):
    """
    Returns True if the given directory doesn't contain any intrinsic headers.
    """
    if not os.path.exists(dirname):
        return True
    if glob.glob(os.path.join(dirname, "*intrin.h")):
        return False
    return True


def collect_clang_compile_opts(flag_iterator, details):
    """Collect all the options for clang do not filter anything."""
    if CLANG_OPTIONS.match(flag_iterator.item):
        details["analyzer_options"].append(flag_iterator.item)
        return True


def collect_transform_xclang_opts(flag_iterator, details):
    """Some specific -Xclang constucts need to be filtered out.
    To generate the proper plist reports and not LLVM IR or
    ASCII text as an output the flags need to be removed.
    """
    if flag_iterator.item == "-Xclang":
        next(flag_iterator)
        next_flag = flag_iterator.item
        if next_flag in XCLANG_FLAGS_TO_SKIP:
            return True

        details["analyzer_options"].extend(["-Xclang", next_flag])
        return True

    return False


def collect_transform_include_opts(flag_iterator, details):
    """
    This function collects the compilation (i.e. not linker or preprocessor)
    flags to the buildaction.
    """

    m = COMPILE_OPTIONS_MERGED.match(flag_iterator.item)

    if not m:
        return False

    flag = m.group(0)
    together = len(flag) != len(flag_iterator.item)

    if together:
        param = flag_iterator.item[len(flag) :]
    else:
        next(flag_iterator)
        param = flag_iterator.item

    # The .plist file contains a section with a list of files. For some
    # further actions these need to be given with an absolute path. Clang
    # prints them with absolute path if the original compiler invocation
    # was given absolute paths.
    # TODO: If Clang will be extended with an extra analyzer option in
    # order to print these absolute paths natively, this conversion will
    # not be necessary.
    flags_with_path = [
        "-I",
        "-idirafter",
        "-iquote",
        "-isysroot",
        "-isystem",
        "-sysroot",
        "--sysroot",
    ]
    if flag in flags_with_path and ("sysroot" in flag or param[0] != "="):
        # --sysroot format can be --sysroot=/path/to/include in this case
        # before the normalization the '=' sign must be removed.
        # We put back the original
        # --sysroot=/path/to/include as
        # --sysroot /path/to/include
        # which is a valid format too.
        if param[0] == "=":
            param = param[1:]
            together = False
        param = os.path.normpath(os.path.join(details["directory"], param))

    details["analyzer_options"].extend([flag + param] if together else [flag, param])

    return True


def collect_compile_opts(flag_iterator, details):
    """
    This function collects the compilation (i.e. not linker or preprocessor)
    flags to the buildaction.
    """
    if COMPILE_OPTIONS.match(flag_iterator.item):
        details["analyzer_options"].append(flag_iterator.item)
        return True

    return False


def skip_sources(flag_iterator, _):
    """
    This function skips the compiled source file names (i.e. the arguments
    which don't start with a dash character).
    """
    if flag_iterator.item[0] != "-":
        return True

    return False


def determine_action_type(flag_iterator, details):
    """
    This function determines whether this is a preprocessing, compilation or
    linking action and sets it in the buildaction object. If the action type is
    set to COMPILE earlier then we don't set it to anything else.
    """
    if flag_iterator.item == "-c":
        details["action_type"] = BuildAction.COMPILE
        return True
    elif flag_iterator.item.startswith("-print-prog-name"):
        if details["action_type"] != BuildAction.COMPILE:
            details["action_type"] = BuildAction.INFO
        return True
    elif PRECOMPILATION_OPTION.match(flag_iterator.item):
        if details["action_type"] != BuildAction.COMPILE:
            details["action_type"] = BuildAction.PREPROCESS
        return True

    return False


def get_arch(flag_iterator, details):
    """
    This function consumes -arch flag which is followed by the target
    architecture. This is then collected to the buildaction object.
    """
    # TODO: Is this really a target architecture? Have we seen this flag being
    # used in a real project? This -arch flag is not really documented among
    # GCC flags.
    # Where do we use this architecture during analysis and why?
    if flag_iterator.item == "-arch":
        next(flag_iterator)
        details["arch"] = flag_iterator.item
        return True

    return False


def get_target(flag_iterator, details):
    """
    This function consumes --target or -target flag which is followed by the
    compilation target architecture.
    This target might be different from the default compilation target
    collected from the compiler if cross compilation is done for
    another target.
    This is then collected to the buildaction object.
    """
    if flag_iterator.item in ["--target", "-target"]:
        next(flag_iterator)
        details["compilation_target"] = flag_iterator.item
        return True

    return False


def get_language(flag_iterator, details):
    """
    This function consumes -x flag which is followed by the language. This
    language is then collected to the buildaction object.
    """
    # TODO: Known issue: a -x flag may precede all source files in the build
    # command with different languages.
    if flag_iterator.item.startswith("-x"):
        if flag_iterator.item == "-x":
            next(flag_iterator)
            details["lang"] = flag_iterator.item
        else:
            details["lang"] = flag_iterator.item[2:]  # 2 == len('-x')
        return True
    return False


def get_output(flag_iterator, details):
    """
    This function consumes -o flag which is followed by the output file of the
    action. This file is then collected to the buildaction object.
    """
    if flag_iterator.item == "-o":
        next(flag_iterator)
        details["output"] = flag_iterator.item
        return True

    return False


def replace(flag_iterator, details):
    """
    This function extends the analyzer options list with the corresponding
    replacement based on REPLACE_OPTIONS_MAP if the flag_iterator is currently
    pointing to a flag to replace.
    """
    value = REPLACE_OPTIONS_MAP.get(flag_iterator.item)

    if value:
        details["analyzer_options"].extend(value)

    return bool(value)


def skip_clang(flag_iterator, _):
    """
    This function skips the flag pointed by the given flag_iterator with its
    parameters if any.
    """
    if IGNORED_OPTIONS_CLANG.match(flag_iterator.item):
        return True

    return False


def skip_gcc(flag_iterator, _):
    """
    This function skips the flag pointed by the given flag_iterator with its
    parameters if any.
    """
    if IGNORED_OPTIONS_GCC.match(flag_iterator.item):
        return True

    for pattern, arg_num in IGNORED_PARAM_OPTIONS.items():
        if pattern.match(flag_iterator.item):
            for _ in range(arg_num):
                next(flag_iterator)
            return True

    return False


class OptionIterator:
    def __init__(self, args):
        self._item = None
        self._it = iter(args)

    def __next__(self):
        self._item = next(self._it)
        return self

    next = __next__

    def __iter__(self):
        return self

    @property
    def item(self):
        return self._item


class BuildLog:
    def __init__(self, build_log, temp_loc, lib_clone_location) -> None:
        self.raw_data = ""
        self.compile_commands = {}
        self.processed_commands = []
        with open(build_log, "r", encoding="UTF-8") as f:
            self.raw_data = f.read()
        # with open(
        #     lib_clone_location + "/compile_commands.json", "r", encoding="UTF-8"
        # ) as f:
        #     self.compile_commands = json.load(f)
        # if not self.compile_commands:
        with open(temp_loc + "/compile_commands.json", "r", encoding="UTF-8") as f:
            self.compile_commands = json.load(f)
        self.process_compile_commands()

    def get_links_from_raw_logs(self, source_file_name, output_object_name):
        additional_linker = []
        all_object_files = set()
        compile_locs = set()
        for line in self.raw_data.split("\n"):
            if " -c " not in line:
                entries = line.split()
                for i in range(len(entries)):
                    fentry = entries[i]
                    if fentry == "-o":
                        i = i + 1
                    if not fentry.startswith("-"):
                        all_object_files.add(os.path.basename(fentry))
                    elif fentry.startswith("-l"):
                        additional_linker.append(fentry)
                    elif fentry.startswith("-L"):
                        location = fentry[2:]
                        modfentry = os.path.normpath(
                            os.path.join(
                                os.path.abspath(f"./test_lib/{test_library}/build_ss"),
                                location,
                            )
                        )
                        if not os.path.exists(modfentry):
                            logger.error(
                                "Unable to resolve library location {}", location
                            )
                        additional_linker.append("-L" + modfentry)
        for detail in self.processed_commands:
            if detail["output"] in all_object_files:
                compile_locs.add(
                    os.path.normpath(
                        os.path.join(detail["directory"], detail["source"])
                    )
                )
        return compile_locs, additional_linker

    def get_compile_dependencies(self, file_loc):
        link_dependencies = set()
        all_compiles_encountered = []
        # TODO too many repetitions as set will loose meaning of paired arguments
        for detail in self.processed_commands:
            if file_loc and os.path.normpath(
                os.path.join(detail["directory"], detail["source"])
            ).replace("/build_ss/", "/") == file_loc.replace("/build_ss/", "/"):
                link_set, additional_linker = self.get_links_from_raw_logs(
                    detail["source"], detail["output"]
                )
                link_dependencies = link_dependencies.union(link_set)
                for opt in detail["analyzer_options"]:
                    # TODO should i check for -l and -L only?
                    additional_linker.append(opt)
                all_compiles_encountered.append(detail)
        compile_detail = all_compiles_encountered[0]
        # compile_command = ["gcc"] + compile_detail["analyzer_options"] + ["-o", "/dev/null"]
        return (
            compile_detail["analyzer_options"],
            link_dependencies,
            list(dict.fromkeys(additional_linker)),
        )

    # , file_loc=None, target_loc=None
    def process_compile_commands(self):
        # _, link_commands = self.get_links_from_raw_logs(file_loc)
        relevant_commands = []
        clang_flag_collectors = [
            skip_sources,
            skip_clang,
            collect_transform_xclang_opts,
            get_output,
            determine_action_type,
            get_arch,
            get_target,
            get_language,
            collect_transform_include_opts,
            collect_clang_compile_opts,
        ]

        gcc_flag_transformers = [
            skip_gcc,
            replace,
            collect_transform_include_opts,
            collect_compile_opts,
            determine_action_type,
            skip_sources,
            get_arch,
            get_target,
            get_language,
            get_output,
        ]

        for compilation_db_entry in self.compile_commands:
            # if file_loc and compilation_db_entry["file"] == file_loc or target_loc and compilation_db_entry["compilation_target"]==target_loc:
            details = {
                "analyzer_options": [],
                "compiler_includes": [],
                "compiler_standard": "",
                "compilation_target": "",  # Compilation target in the compilation cmd.
                "analyzer_type": -1,
                "original_command": "",
                "directory": "",
                "output": "",
                "lang": None,
                "arch": "",  # Target in the compile command set by -arch.
                "target": "",
                "source": "",
            }
            if "arguments" in compilation_db_entry:
                gcc_command = compilation_db_entry["arguments"]
                details["original_command"] = " ".join(
                    [shlex.quote(x) for x in gcc_command]
                )
            elif "command" in compilation_db_entry:
                details["original_command"] = compilation_db_entry["command"]
                gcc_command = shlex.split(compilation_db_entry["command"])
            else:
                logger.warning("No valid 'command' or 'arguments' entry found!")
                return details
            details["directory"] = compilation_db_entry["directory"]
            details["action_type"] = None
            details["compiler"] = (
                gcc_command[1] if gcc_command[0].endswith("ccache") else gcc_command[0]
            )
            if "++" in os.path.basename(details["compiler"]):
                details["lang"] = "c++"
            relevant_commands.append(details)
            if "clang" in details["compiler"]:
                flag_processors = clang_flag_collectors
            else:
                flag_processors = gcc_flag_transformers
            for it in OptionIterator(gcc_command[1:]):
                for flag_processor in flag_processors:
                    if flag_processor(it, details):
                        break
                else:
                    pass
            if details["action_type"] is None:
                details["action_type"] = BuildAction.COMPILE
            # TODO CHECK IF THINGS FAIL
            # if "build_ss" in compilation_db_entry["file"]:
            #     hope_target = compilation_db_entry["file"].replace(
            #         details["directory"], ""
            #     )
            # else:
            hope_target = (
                compilation_db_entry["file"]
                .replace("/build_ss/", "/")
                .replace(details["directory"].rsplit("/", 1)[0] + "/", "")
            )
            details["source"] = hope_target
            # Required when -o option not used
            if details["output"].strip() == "":
                pre, ext = os.path.splitext(details["source"])
                details["output"] = pre + ".o"
            details["output"] = os.path.basename(details["output"])

            # In case the file attribute in the entry is empty.
            if details["source"] == ".":
                details["source"] = ""

            lang = get_language_map(os.path.splitext(details["source"])[1])
            if lang:
                if details["lang"] is None:
                    details["lang"] = lang
            else:
                details["action_type"] = BuildAction.LINK

            # Option parser detects target architecture but does not know about the
            # language during parsing. Set the collected compilation target for the
            # language detected language.
            details["target"] = details["compilation_target"]

            # With gcc-toolchain a non default compiler toolchain can be set. Clang
            # will search for include paths and libraries based on the gcc-toolchain
            # parameter. Detecting extra include paths from the host compiler could
            # conflict with this.

            # For example if the compiler in the compile command is clang and
            # gcc-toolchain is set we will get the include paths for clang and not for
            # the compiler set in gcc-toolchain. This can cause missing headers during
            # the analysis.

            if not keep_gcc_include_fixed:
                details["compiler_includes"] = list(
                    filter(is_not_include_fixed, details["compiler_includes"])
                )

            if not keep_gcc_intrin:
                details["compiler_includes"] = list(
                    filter(contains_no_intrinsic_headers, details["compiler_includes"])
                )

                # filter out intrin directories
                aop_without_intrin = []
                analyzer_options = iter(details["analyzer_options"])

                for aopt in analyzer_options:
                    m = INCLUDE_OPTIONS_MERGED.match(aopt)
                    if m:
                        flag = m.group(0)
                        together = len(flag) != len(aopt)

                        if together:
                            value = aopt[len(flag) :]
                        else:
                            flag = aopt
                            value = next(analyzer_options)
                        if (
                            os.path.isdir(value)
                            and contains_no_intrinsic_headers(value)
                            or not os.path.isdir(value)
                        ):
                            if together:
                                aop_without_intrin.append(aopt)
                            else:
                                aop_without_intrin.append(flag)
                                aop_without_intrin.append(value)
                    else:
                        # no match
                        aop_without_intrin.append(aopt)
                details["analyzer_options"] = aop_without_intrin
                # details['linker_locs'] = self.get_links_from_raw_logs(details["output"])
            self.processed_commands.append(details)
        # return self._process_compile_command(file_loc)

    # def _process_compile_command(self, file_loc):
    #     data = self.raw_data
    #     match_lines = [
    #         line for line in data.split("\n") if file_loc in line and "-c" in line
    #     ]
    #     if not match_lines:
    #         logger.warning("File at {} not used in logs", file_loc)
    #         return None, None, None
    #     linker_locs = set()
    #     new_commands = set()
    #     additions_command_keys = set()
    #     for matches in match_lines:
    #         new_command = shlex.split(matches)
    #         id_to_del = []
    #         for i, element in enumerate(new_command):
    #             if element == "-o":
    #                 out_loc = new_command[i + 1]
    #                 new_command[i + 1] = "/dev/null"
    #                 match_lines = [
    #                     line
    #                     for line in data.split("\n")
    #                     if out_loc in line and " -c " not in line
    #                 ]
    #                 for matcher in match_lines:
    #                     for loc in matcher.split():
    #                         if loc.startswith("-L"):
    #                             possible_replacement = os.path.join(
    #                                 self.lib_clone_location, loc[2:]
    #                             )
    #                             if os.path.exists(possible_replacement):
    #                                 loc = "-L" + os.path.abspath(possible_replacement)
    #                             additions_command_keys.add(loc)
    #                         elif loc.startswith("-l"):
    #                             additions_command_keys.add(loc)
    #                         elif loc.endswith(".o"):
    #                             match_sub_line = [
    #                                 line for line in data.split("\n") if loc in line
    #                             ][0]
    #                             linker_locs.add(match_sub_line.split()[-1].strip())
    #             elif element.startswith("-I"):
    #                 possible_replacement = os.path.join(self.lib_clone_location, element[2:])
    #                 if os.path.exists(possible_replacement):
    #                     new_command[i] = "-I" + os.path.abspath(possible_replacement)
    #             elif element.startswith("-L"):
    #                 possible_replacement = os.path.join(self.lib_clone_location, element[2:])
    #                 if os.path.exists(possible_replacement):
    #                     new_command[i] = "-L" + os.path.abspath(possible_replacement)
    #             elif element in ("-MF", "-MT"):
    #                 # possible_replacement = os.path.join(self.lib_clone_location, new_command[i + 1])
    #                 # if os.path.exists(possible_replacement):
    #                 #     new_command[i + 1] = os.path.abspath(possible_replacement)
    #                 # else:
    #                 id_to_del.extend([i, i + 1])
    #             elif element in ("-MMD", "-c"):
    #                 id_to_del.append(i)
    #             elif (
    #                 not element.startswith("-")
    #                 and i > 0
    #                 and not new_command[i - 1].startswith("-")
    #             ):
    #                 id_to_del.append(i)
    #         new_command_string = shlex.join(del_list_numpy(new_command, id_to_del))
    #         new_commands.add(new_command_string)
    #     return new_commands, linker_locs, additions_command_keys
