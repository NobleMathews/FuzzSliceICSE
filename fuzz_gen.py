from loguru import logger

from expand_var import expand_struct, reset_param_globals, register_initial_paramnames

# compiler_flags_libFuzzer = "-ferror-limit=1 -g -O0 -fsanitize=address,undefined,fuzzer -fprofile-instr-generate -fcoverage-mapping"
# compiler_flags_aflplusplus = "-ferror-limit=1 -g -O0 -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping"
# import copy

LIBFUZZER = 0
AFLPLUSPLUS = 1

# Constants for generator
GEN_BUILTIN = 0
GEN_STRING = 1
GEN_ENUM = 2
GEN_ARRAY = 3
GEN_VOID = 4
GEN_QUALIFIER = 5
GEN_POINTER = 6
GEN_STRUCT = 7
GEN_INCOMPLETE = 8
GEN_FUNCTION = 9
GEN_INPUT_FILE = 10
GEN_OUTPUT_FILE = 11
GEN_UNKNOWN = 12

compile_command = []
link_command = []
file_path = ""


class Generator:
    def __init__(self, target_type: int = AFLPLUSPLUS):
        self.gen_func_params = []
        self.gen_free = []
        self.gen_this_function = True
        self.buf_size_arr = []
        self.dyn_size = 0
        self.curr_gen_string = -1
        self.target_type = target_type
        self.var_function = 0
        self.var_files = 0

    # def gen_header(self):
    #     defaults = ["stdio.h", "stddef.h", "stdlib.h", "string.h", "stdint.h"]
    #     include_lines = []
    #     for i in defaults:
    #         include_lines.append("#include <" + i + ">\n")

    #     return include_lines

    def gen_builtin(self, type_name, var_name):

        return {
            "gen_lines": [
                "//GEN_BUILTIN\n",
                type_name + " " + var_name + ";\n",
                "memcpy(&" + var_name + ", pos, sizeof(" + type_name + "));\n",
                "pos += sizeof(" + type_name + ");\n",
            ],
            "gen_free": [],
        }

    def gen_size(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_SIZE\n",
                type_name + " " + var_name + " = (" + type_name + ") dyn_size;\n",
            ],
            "gen_free": [],
        }

    def gen_string(self, type_name, var_name, parent_type):
        if len(parent_type) > 0:
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    parent_type
                    + " r"
                    + var_name
                    + " = ("
                    + parent_type
                    + ") "
                    + "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(r" + var_name + ", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(r" + var_name + ", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    type_name + " " + var_name + "= r" + var_name + ";\n",
                ],
                "gen_free": [
                    # "if (dyn_size > 0 && strlen(r" + var_name + \
                    # ") > 0) {\n",
                    "if (dyn_size > 0) {\n",
                    "    free(r" + var_name + ");\n",
                    "}\n",
                ],
            }
        return {
            "gen_lines": [
                "//GEN_STRING\n",
                type_name
                + " "
                + var_name
                + " = ("
                + type_name
                + ") "
                + "malloc(sizeof(char) * dyn_size + 1);\n",
                "memset(" + var_name + ", 0, sizeof(char) * dyn_size + 1);\n",
                "memcpy(" + var_name + ", pos, sizeof(char) * dyn_size );\n",
                "pos += sizeof(char) * dyn_size ;\n",
            ],
            "gen_free": [
                # "if (dyn_size > 0 && strlen(" + var_name + \
                # ") > 0) {\n",
                "if (dyn_size > 0 ) {\n",
                "    free(" + var_name + ");\n",
                "}\n",
            ],
        }

    def gen_enum(self, type_name, var_name):
        return {"gen_lines": ["//GEN_ENUM\n"], "gen_free": []}

    def gen_array(self, type_name, var_name):
        return {
            "gen_lines": [
                "//GEN_STRING\n",
                type_name
                + "* "
                + var_name
                + " = ("
                + type_name
                + "*)"
                + f"calloc(dyn_size + 1,sizeof({type_name}));\n",
            ],
            "gen_free": [],
        }

    def gen_void(self, var_name):
        return self.gen_string("void *", var_name, "char *")
        # return {"gen_lines": ["//GEN_VOID\n"], "gen_free": []}

    def gen_qualifier(self, type_name, var_name, parent_type, parent_gen):

        if parent_type in ["const char *", "const unsigned char *"]:
            self.dyn_size += 1
            temp_type = parent_type[6:]
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    temp_type
                    + " s"
                    + var_name
                    + " = ("
                    + temp_type
                    + ") "
                    + "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(s" + var_name + ", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(s" + var_name + ", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    parent_type + " u" + var_name + "= s" + var_name + ";\n",
                    "//GEN_QUALIFIED\n",
                    type_name + " " + var_name + " = u" + var_name + ";\n",
                ],
                "gen_free": [
                    "if (s" + var_name + ") {\n",
                    "    free(s" + var_name + ");\n",
                    "    s" + var_name + " = NULL;\n",
                    "}\n",
                ],
                "buf_size": "sizeof(char)",
            }
        if parent_type in ["char *", "unsigned char *"]:
            self.dyn_size += 1
            return {
                "gen_lines": [
                    "//GEN_STRING\n",
                    parent_type
                    + " s"
                    + var_name
                    + " = ("
                    + parent_type
                    + ") "
                    + "malloc(sizeof(char) * dyn_size + 1);\n",
                    "memset(s" + var_name + ", 0, sizeof(char) * dyn_size + 1);\n",
                    "memcpy(s" + var_name + ", pos, sizeof(char) * dyn_size );\n",
                    "pos += sizeof(char) * dyn_size ;\n",
                    "//GEN_QUALIFIED\n",
                    type_name + " " + var_name + " = s" + var_name + ";\n",
                ],
                "gen_free": [
                    "if (s" + var_name + " ) {\n",
                    "    free(s" + var_name + ");\n",
                    "    s" + var_name + " = NULL;\n",
                    "}\n",
                ],
                "buf_size": "sizeof(char)",
            }
        return {
            "gen_lines": [
                "//GEN_QUALIFIED\n",
                parent_type + " u" + var_name + ";\n",
                "memcpy(&u" + var_name + ", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " " + var_name + " = u" + var_name + ";\n",
            ],
            "gen_free": [],
            "buf_size": "",
        }

    def gen_pointer(self, type_name, var_name, parent_type):
        return {
            "gen_lines": [
                "//GEN_POINTER\n",
                parent_type + " r" + var_name + ";\n",
                "memcpy(&r" + var_name + ", pos, sizeof(" + parent_type + "));\n",
                "pos += sizeof(" + parent_type + ");\n",
                type_name + " " + var_name + "= &r" + var_name + ";\n",
            ],
            "gen_free": [],
        }

    def gen_struct(self, parameter):
        global compile_command
        global link_command
        global file_path
        try:
            return expand_struct(file_path, [parameter], compile_command, link_command)
        except:
            logger.error("Struct generation took too long - Skipping for now")
            return 0, [], {"gen_lines": ["//GEN_STRUCT\n"], "gen_free": []}

    def gen_input_file(self, var_name):
        cur_gen_free = ["    " + x for x in self.gen_free]
        gen_lines = (
            [
                "//GEN_INPUT_FILE\n",
                "const char* " + var_name + ' = "generator_input_file";\n',
                "FILE *fp" + str(self.var_files) + " = fopen(" + var_name + ',"w");\n',
                "if (fp" + str(self.var_files) + "  == NULL) {\n",
            ]
            + cur_gen_free
            + [
                "    return 0;\n",
                "}\n",
                "fwrite(pos, 1, dyn_size, fp" + str(self.var_files) + ");\n",
                "fclose(fp" + str(self.var_files) + ");\n",
                "pos += dyn_size;\n",
            ]
        )
        return {"gen_lines": gen_lines, "gen_free": []}

    # def check_gen_function(self, function):
    #     """ Check if we can initialize argument as function call """
    #     return True

    def gen_var_function(self, parent_func, func, var_name):
        """Initialize for argument of function call"""
        curr_gen_func_params = []
        curr_gen_free = []
        curr_buf_size_arr = []
        curr_dyn_size = 0
        param_list = []
        param_id = 0
        curr_gen_string = -1
        for arg in func["params"]:
            param_list.append("f" + str(self.var_function) + "_" + arg["param_name"])
            if arg["generator_type"].value == GEN_BUILTIN:
                if arg["param_type"].split(" ")[0] in ["volatile", "const"]:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        if curr_gen_string >= 0:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_SIZE\n",
                                    arg["param_type"].split(" ")[1]
                                    + " uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = ("
                                    + arg["param_type"].split(" ")[1]
                                    + ") dyn_size;\n",
                                    arg["param_type"]
                                    + " f"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                ],
                            }
                        else:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_BUILTIN\n",
                                    arg["param_type"].split(" ")[1]
                                    + " uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                    "memcpy(&u"
                                    + arg["param_name"]
                                    + ", pos, sizeof("
                                    + arg["param_type"].split(" ")[1]
                                    + "));\n",
                                    "pos += sizeof("
                                    + arg["param_type"].split(" ")[1]
                                    + ");\n",
                                    arg["param_type"]
                                    + " f"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                ],
                            }
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"].split(" ")[1] + ")"
                            )
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_SIZE\n",
                                    arg["param_type"].split(" ")[1]
                                    + " uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = ("
                                    + arg["param_type"].split(" ")[1]
                                    + ") dyn_size;\n",
                                    arg["param_type"]
                                    + " f"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                ],
                            }
                        else:
                            var_curr_gen = {
                                "gen_lines": [
                                    "//GEN_BUILTIN var\n",
                                    arg["param_type"].split(" ")[1]
                                    + " uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                    "memcpy(&u"
                                    + arg["param_name"]
                                    + ", pos, sizeof("
                                    + arg["param_type"].split(" ")[1]
                                    + "));\n",
                                    "pos += sizeof("
                                    + arg["param_type"].split(" ")[1]
                                    + ");\n",
                                    arg["param_type"]
                                    + " f"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + " = uf"
                                    + str(self.var_function)
                                    + "_"
                                    + arg["param_name"]
                                    + ";\n",
                                ],
                            }
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"].split(" ")[1] + ")"
                            )
                else:
                    if arg["param_usage"] == "SIZE_FIELD" and len(func["params"]) > 1:
                        if curr_gen_string >= 0:
                            var_curr_gen = self.gen_size(
                                arg["param_type"],
                                "f" + str(self.var_function) + "_" + arg["param_name"],
                            )
                        else:
                            var_curr_gen = self.gen_builtin(
                                arg["param_type"],
                                "f" + str(self.var_function) + "_" + arg["param_name"],
                            )
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"] + ")"
                            )
                    else:
                        if curr_gen_string == param_id - 1 and curr_gen_string >= 0:
                            var_curr_gen = self.gen_size(
                                arg["param_type"],
                                "f" + str(self.var_function) + "_" + arg["param_name"],
                            )
                        else:
                            var_curr_gen = self.gen_builtin(
                                arg["param_type"],
                                "f" + str(self.var_function) + "_" + arg["param_name"],
                            )
                            curr_buf_size_arr.append(
                                "sizeof(" + arg["param_type"] + ")"
                            )
                curr_gen_func_params += var_curr_gen["gen_lines"]

            if arg["generator_type"].value == GEN_STRING:
                if (
                    arg["param_usage"] == "FILE_PATH"
                    or arg["param_usage"] == "FILE_PATH_READ"
                    or arg["param_usage"] == "FILE_PATH_WRITE"
                    or arg["param_usage"] == "FILE_PATH_RW"
                ):
                    var_curr_gen = self.gen_input_file(
                        "f" + str(self.var_function) + "_" + arg["param_name"]
                    )
                    self.var_files += 1
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None

                    curr_gen_func_params += var_curr_gen["gen_lines"]

                else:
                    var_curr_gen = self.gen_string(
                        arg["param_type"],
                        "f" + str(self.var_function) + "_" + arg["param_name"],
                        arg["parent_type"],
                    )
                    curr_dyn_size += 1
                    if not var_curr_gen:
                        return None
                    curr_gen_func_params += var_curr_gen["gen_lines"]
                    curr_gen_free += var_curr_gen["gen_free"]
                    curr_gen_string = param_id
            param_id += 1

        function_call = (
            "//GEN_VAR_FUNCTION\n    "
            + func["return_type"]
            + " "
            + var_name
            + " = "
            + func["func_name"]
            + "("
            + ",".join(param_list)
            + ");\n"
        )

        # !attempting free on address which was not malloc()-ed
        #
        # if func["return_type_pointer"]:
        #     if func["return_type"].split(" ")[0] != "const" and not parent_func["return_type_pointer"]:
        #         curr_gen_free += ["if(" + var_name+ ") free("+var_name+");\n"]

        curr_gen_func_params.append(function_call)
        return {
            "gen_lines": curr_gen_func_params,
            "gen_free": curr_gen_free,
            "dyn_size": curr_dyn_size,
            "buf_size_arr": curr_buf_size_arr,
        }

    def reset_globals(self, func, compile=[], link=[], file=""):
        global compile_command
        global link_command
        global file_path

        compile_command = compile
        link_command = link
        file_path = file
        reset_param_globals()
        param_list = []
        for arg in func["params"]:
            param_list.append(arg["parameter"])
        register_initial_paramnames(file, param_list)

    def gen_target_function(self, func, param_id) -> list:

        malloc_free = [
            "unsigned char *",
            "char *",
        ]
        param_list = []
        for arg in func["params"]:
            param_list.append(arg["parameter"])
        logger.info(
            "Attempting to handle param #{} in {}", param_id, ", ".join(param_list)
        )
        if param_id == len(func["params"]):

            # if not self.gen_this_function:
            #     return ["int main(){", "return 0;", "}"]
            # # If there is no buffer - return!
            # if not self.buf_size_arr:
            #     return ["int main(){", "return 0;", "}"]

            f = []
            # for line in self.gen_header():
            #     f.append(line)
            f.append("\n")
            if self.target_type == LIBFUZZER:
                f.append(""" #include <math.h> """)
                f.append(
                    "int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size)\n"
                )
                f.append("{\n")

                if self.dyn_size > 0:
                    f.append(
                        "    // Buff size : "
                        + str(len(self.buf_size_arr))
                        + " Dyn size : "
                        + str(self.dyn_size)
                        + "\n"
                    )
                    f.append("    if (Fuzz_Size < (" + str(self.dyn_size))
                    if self.buf_size_arr:
                        f.append(" + " + "+".join(self.buf_size_arr))
                    f.append(")) {return 0;}\n")
                    f.append(
                        "    size_t dyn_size = (int) ((Fuzz_Size - ("
                        + str(self.dyn_size)
                    )
                    if self.buf_size_arr:
                        f.append(" + " + "+".join(self.buf_size_arr))
                    f.append("))/" + str(self.dyn_size) + ");\n")
                    # f.append(
                    #     "    if (dyn_size < 5) { return 0; }\n"
                    # )
                else:
                    if len(self.buf_size_arr) > 0:
                        f.append("    if (Fuzz_Size < ")
                        f.append("+".join(self.buf_size_arr))
                        f.append(") return 0;\n")

                f.append("    uint8_t * pos = Fuzz_Data;\n")
                for line in self.gen_func_params:
                    f.append("    " + line)

                f.append("    //FUNCTION_CALL\n")
                if func["return_type"] in malloc_free:
                    f.append(
                        "    "
                        + func["return_type"]
                        + " generator_target = "
                        + func["func_name"]
                        + "("
                    )
                else:
                    f.append("    " + func["func_name"] + "(")

                param_list = []
                for arg in func["params"]:
                    if arg["param_name"].strip() == "void":
                        arg["param_name"] = ""
                    param_list.append(arg["param_name"] + " ")
                f.append(",".join(param_list))
                f.append(");\n")

                # !attempting free on address which was not malloc()-ed

                if func["return_type"] in malloc_free:
                    f.append("    if(generator_target){\n")
                    f.append("        free(generator_target);\n")
                    f.append("        generator_target = NULL;\n")
                    f.append("    }\n")

                f.append("    //FREE\n")
                for line in self.gen_free:
                    f.append("    " + line)

                f.append("    return 0;\n")
                f.append("}")
            else:

                f.append(
                    """ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x) \
    ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
                """
                )

                f.append(
                    """__AFL_FUZZ_INIT();
main() {
// anything else here, e.g. command line arguments, initialization, etc.
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
unsigned char *Fuzz_Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT and before __AFL_LOOP!
while (__AFL_LOOP(10000)) {
    int Fuzz_Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!

    // check for a required/useful minimum input length\n"""
                )
                if self.dyn_size > 0:
                    f.append("    if (Fuzz_Size < " + str(self.dyn_size))
                    if self.buf_size_arr:
                        f.append(" + " + "+".join(self.buf_size_arr))
                    f.append(") continue;\n")
                    f.append(
                        "    size_t dyn_size = (int) ((Fuzz_Size - ("
                        + str(self.dyn_size)
                    )
                    if self.buf_size_arr:
                        f.append(" + " + "+".join(self.buf_size_arr))
                    f.append("))/" + str(self.dyn_size) + ");\n")
                else:
                    if len(self.buf_size_arr) > 0:
                        f.append("    if (Fuzz_Size < ")
                        f.append("+".join(self.buf_size_arr))
                        f.append(") continue;\n")

                f.append("    uint8_t * pos = Fuzz_Data;\n")
                for line in self.gen_func_params:
                    f.append("    " + line)
                f.append("    //Call function to be fuzzed, e.g.:\n")
                if func["return_type"] in malloc_free:
                    f.append(
                        "    "
                        + func["return_type"]
                        + " generator_target = "
                        + func["func_name"]
                        + "("
                    )
                else:
                    f.append("    " + func["func_name"] + "(")

                param_list = []
                for arg in func["params"]:
                    if arg["param_name"].strip() == "void":
                        arg["param_name"] = ""
                    param_list.append(arg["param_name"] + " ")
                f.append(",".join(param_list))
                f.append(");\n")

                # !attempting free on address which was not malloc()-ed

                if func["return_type"] in malloc_free:
                    f.append("    if(generator_target){\n")
                    f.append("        free(generator_target);\n")
                    f.append("        generator_target = NULL;\n")
                    f.append("    }\n")

                f.append("    //FREE\n")
                for line in self.gen_free:
                    f.append("    " + line)

                f.append(
                    """
  }
  return 0;
}"""
                )
            return f

        curr_param = func["params"][param_id]

        # Assign function pointers to NULL
        if curr_param["function_ptr"] == 1:
            func["params"][param_id]["param_name"] = "NULL"
            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_BUILTIN:
            if curr_param["param_type"].split(" ")[0] in ["volatile", "const"]:
                if (
                    curr_param["param_usage"] == "SIZE_FIELD"
                    and len(func["params"]) > 1
                ):
                    if self.curr_gen_string >= 0:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[1]
                                + " u"
                                + curr_param["param_name"]
                                + " = ("
                                + curr_param["param_type"].split(" ")[1]
                                + ") dyn_size;\n",
                                curr_param["param_type"]
                                + " "
                                + curr_param["param_name"]
                                + " = u"
                                + curr_param["param_name"]
                                + ";\n",
                            ],
                            "gen_free": [],
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(" ")[1]
                                + " u"
                                + curr_param["param_name"]
                                + ";\n",
                                "memcpy(&u"
                                + curr_param["param_name"]
                                + ", pos, sizeof("
                                + curr_param["param_type"].split(" ")[1]
                                + "));\n",
                                "pos += sizeof("
                                + curr_param["param_type"].split(" ")[1]
                                + ");\n",
                                curr_param["param_type"]
                                + " "
                                + curr_param["param_name"]
                                + " = u"
                                + curr_param["param_name"]
                                + ";\n",
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": [],
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1] + ")"
                        )
                else:
                    if (
                        self.curr_gen_string == param_id - 1
                        and self.curr_gen_string >= 0
                    ):
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_SIZE\n",
                                curr_param["param_type"].split(" ")[1]
                                + " u"
                                + curr_param["param_name"]
                                + " = ("
                                + curr_param["param_type"].split(" ")[1]
                                + ") dyn_size;\n",
                                curr_param["param_type"]
                                + " "
                                + curr_param["param_name"]
                                + " = u"
                                + curr_param["param_name"]
                                + ";\n",
                            ],
                            "gen_free": [],
                        }
                    else:
                        curr_gen = {
                            "gen_lines": [
                                "//GEN_BUILTIN\n",
                                curr_param["param_type"].split(" ")[1]
                                + " u"
                                + curr_param["param_name"]
                                + ";\n",
                                "memcpy(&u"
                                + curr_param["param_name"]
                                + ", pos, sizeof("
                                + curr_param["param_type"].split(" ")[1]
                                + "));\n",
                                "pos += sizeof("
                                + curr_param["param_type"].split(" ")[1]
                                + ");\n",
                                curr_param["param_type"]
                                + " "
                                + curr_param["param_name"]
                                + " = u"
                                + curr_param["param_name"]
                                + ";\n",
                            ],
                            # "gen_free":["free(u" + curr_param["param_name"] + ");\n"]
                            "gen_free": [],
                        }
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"].split(" ")[1] + ")"
                        )
            else:
                if (
                    curr_param["param_usage"] == "SIZE_FIELD"
                    and len(func["params"]) > 1
                ):
                    if self.curr_gen_string >= 0:
                        curr_gen = self.gen_size(
                            curr_param["param_type"], curr_param["param_name"]
                        )
                    else:
                        curr_gen = self.gen_builtin(
                            curr_param["param_type"], curr_param["param_name"]
                        )
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"] + ")"
                        )
                else:
                    if (
                        self.curr_gen_string == param_id - 1
                        and self.curr_gen_string >= 0
                    ):
                        curr_gen = self.gen_size(
                            curr_param["param_type"], curr_param["param_name"]
                        )
                    else:
                        curr_gen = self.gen_builtin(
                            curr_param["param_type"], curr_param["param_name"]
                        )
                        self.buf_size_arr.append(
                            "sizeof(" + curr_param["param_type"] + ")"
                        )
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_STRING:
            if (
                curr_param["param_usage"] == "FILE_PATH"
                or curr_param["param_usage"] == "FILE_PATH_READ"
                or curr_param["param_usage"] == "FILE_PATH_WRITE"
                or curr_param["param_usage"] == "FILE_PATH_RW"
                or curr_param["param_name"] == "filename"
            ):
                curr_gen = self.gen_input_file(curr_param["param_name"])
                self.var_files += 1
                self.dyn_size += 1
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
            else:
                curr_gen = self.gen_string(
                    curr_param["param_type"],
                    curr_param["param_name"],
                    curr_param["parent_type"],
                )
                self.dyn_size += 1
                if len(curr_param["parent_type"]) > 0:
                    self.buf_size_arr.append(
                        "sizeof(" + curr_param["parent_type"] + ")"
                    )
                else:
                    self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")")
                if not curr_gen:
                    self.gen_this_function = False

                self.gen_func_params += curr_gen["gen_lines"]
                self.gen_free += curr_gen["gen_free"]
                self.curr_gen_string = param_id

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_ENUM:  # GEN_ENUM
            self.gen_this_function = False
            curr_gen = self.gen_enum(curr_param["param_type"], curr_param["param_name"])
            if not curr_gen:
                self.gen_this_function = False
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")")

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_ARRAY:  # GEN_ARRAY
            self.gen_this_function = False
            curr_gen = self.gen_array(
                curr_param["param_name"], curr_param["param_name"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")")

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_VOID:
            self.gen_this_function = False
            # curr_gen = self.gen_void(curr_param["param_name"])
            add_dyn_size, add_buf_size, curr_gen = self.gen_struct(
                "char** " + curr_param["param_name"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.dyn_size += add_dyn_size
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            # self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")*2")
            self.buf_size_arr = self.buf_size_arr + add_buf_size

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_QUALIFIER:
            curr_gen = self.gen_qualifier(
                curr_param["param_type"],
                curr_param["param_name"],
                curr_param["parent_type"],
                curr_param["parent_gen"],
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            if curr_gen["buf_size"]:
                self.buf_size_arr.append(curr_gen["buf_size"])

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_STRUCT:
            curr_gen = self.gen_struct(
                curr_param["param_name"] + " " + curr_param["param_type"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")")

            param_id += 1
            return self.gen_target_function(func, param_id)

        # if curr_param["generator_type"].value == GEN_INCOMPLETE:
        #     # iterate all possible variants for generating
        #     old_func_params = copy.copy(self.gen_func_params)
        #     old_gen_free = copy.copy(self.gen_free)
        #     old_dyn_size = copy.copy(self.dyn_size)
        #     old_buf_size_arr = copy.copy(self.buf_size_arr)
        #     old_var_function = copy.copy(self.var_function)
        #     curr_gen = False
        #     for f in self.target_library['functions']:
        #         if f["return_type"] == curr_param["param_type"] and f["func_name"] != func["func_name"]:
        #             # check for function call with simple data type!!!
        #             check_params = True
        #             for arg in f["params"]:
        #                 if arg["generator_type"].value not in [GEN_BUILTIN, GEN_STRING]:
        #                     check_params = False
        #                     break
        #             if not check_params:
        #                 continue
        #
        #             curr_gen = self.gen_var_function(func,
        #                                              f, curr_param["param_name"])
        #             self.var_function += 1
        #             self.gen_func_params += curr_gen["gen_lines"]
        #             self.gen_free += curr_gen["gen_free"]
        #             self.dyn_size += curr_gen["dyn_size"]
        #             self.buf_size_arr += curr_gen["buf_size_arr"]
        #             param_id += 1
        #             return self.gen_target_function(func, param_id)
        #
        #             param_id -= 1
        #
        #             self.gen_func_params = copy.copy(old_func_params)
        #             self.gen_free = copy.copy(old_gen_free)
        #             self.dyn_size = copy.copy(old_dyn_size)
        #             self.buf_size_arr = copy.copy(old_buf_size_arr)
        #             self.var_function = copy.copy(old_var_function)
        #
        #     # curr_gen = self.gen_incomplete(curr_param["param_name"])
        #     if not curr_gen:
        #         self.gen_this_function = False

        # if curr_param["generator_type"].value == GEN_FUNCTION:
        #     self.gen_this_function = False
        #     # return null pointer to function?
        #     curr_gen = self.gen_function(curr_param["param_name"])
        #     if not curr_gen:
        #         self.gen_this_function = False
        #
        #     self.gen_func_params += curr_gen["gen_lines"]
        #     self.gen_free += curr_gen["gen_free"]
        #     self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")")
        #
        #     param_id += 1
        #     return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_UNKNOWN:  # GEN_UNKNOWN
            add_dyn_size, add_buf_size, curr_gen = self.gen_struct(
                curr_param["parameter"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.dyn_size += add_dyn_size
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            # self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")*2")
            self.buf_size_arr = self.buf_size_arr + add_buf_size

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_INCOMPLETE:  # GEN_INCOMPLETE
            add_dyn_size, add_buf_size, curr_gen = self.gen_struct(
                curr_param["parameter"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.dyn_size += add_dyn_size
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            # self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")*2")
            self.buf_size_arr = self.buf_size_arr + add_buf_size

            param_id += 1
            return self.gen_target_function(func, param_id)

        if curr_param["generator_type"].value == GEN_POINTER:
            add_dyn_size, add_buf_size, curr_gen = self.gen_struct(
                curr_param["parameter"]
            )
            if not curr_gen:
                self.gen_this_function = False

            self.dyn_size += add_dyn_size
            self.gen_func_params += curr_gen["gen_lines"]
            self.gen_free += curr_gen["gen_free"]
            # self.buf_size_arr.append("sizeof(" + curr_param["param_type"] + ")*2")
            self.buf_size_arr = self.buf_size_arr + add_buf_size

            param_id += 1
            return self.gen_target_function(func, param_id)
