import os
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
import numpy as np

from lxml import etree

primitives = ["int", "float", "double", "char", "bool", "enum"]
disallowed_names = ["size_t"]
parent_child_map = {}
var_map = {}
is_pointer = {}
literals = {}
type_vars = {}
incomplete_types = {}
do_not_fuzz = {}
declared = set()
tmp_dir = ""
# Change this to change the maximum length of initialized array
default_index_limits = "dyn_size"

# Allocate memory for each array depending on total memory allocated
def var_size(type, power=1):
    if power == 1:
        return "(1 + (" + str(default_index_limits) + "/sizeof(" + type + ")))"
    return (
        "(1 + (int)(floor(pow("
        + str(default_index_limits)
        + ", 1./"
        + str(power)
        + "))/sizeof("
        + type
        + ")))"
    )


# This routine brings the variables of given types in context within main so that they can be queried by gdb
def modifymain(file, types, vars):
    global tmp_dir
    text = open(file).read()
    text = text + "\nint main() { \n"

    for i, v in enumerate(vars):
        text = text + "\n \t" + types[i] + " "
        num_pointers = is_pointer[vars[i]]
        for j in range(num_pointers):
            text = text + "*"
        text = text + vars[i] + ";\n"
        if vars[i] not in incomplete_types:
            text = text + "\n \t sizeof("
            for j in range(num_pointers):
                text = text + "*"
            text = text + vars[i] + ");\n"

    text = text + "\n \t return 0;\n }"

    with open(tmp_dir + "/temp.c", "w") as f:
        f.write(text)


# This routine just adds parameters in main without expanding them
def add_dummy_parameter(vars, types):
    lines = []
    dyn_size = 0
    buf_size = []

    for i, v in enumerate(vars):
        line = "\n \t" + types[i] + " "
        num_pointers = is_pointer[vars[i]]
        for j in range(num_pointers):
            line = line + "*"
        line = line + vars[i] + ";"
        lines += [line]

    return dyn_size, buf_size, lines


# This routine shows the full declaration and allocation of memory for variables
def add_assignment(file, parameters, vars, types):
    lines = []
    dyn_size = 0
    buf_size = []
    free_line = []
    # text = open( file ).read()

    # text = text + "\nint main() { \n"

    for i, v in enumerate(vars):
        line = "\n \t" + types[i] + " "
        num_pointers = is_pointer[vars[i]]
        for j in range(num_pointers):
            line = line + "*"
        line = line + vars[i] + ";"
        # text = text + line
        lines += [line]

    for i, p in enumerate(parameters):
        parentvar = vars[i]
        declared.add(parentvar)
        if parentvar in do_not_fuzz:
            continue
        sizetype = types[i].replace("*", "")
        num_modifiers = is_pointer[parentvar]
        saved_mod_string = ""
        index_var = "a"
        index_limits_array = literals[parentvar]

        if parentvar in incomplete_types:
            sizetype = "char"

        if sizetype.strip() == "void":
            sizetype = "char"

        if num_modifiers > 1:
            free_line_part1 = []
            free_line_part2 = []
            for i in range(0, num_modifiers - 1, 1):
                # These are pointer of pointers - **  or even triple pointers...
                index_limits = index_limits_array[i]
                if index_limits == -1:
                    index_limits = var_size("int*", num_modifiers)
                    dyn_size += 1
                    buf_size.append("sizeof(int*)")
                else:
                    buf_size.append("sizeof(int*)*" + str(index_limits))

                # text = text + "\n \t" + parentvar + saved_mod_string + " = malloc(sizeof(int*)*" + str(index_limits) + ");\n"
                lines += [
                    "\n \t"
                    + parentvar
                    + saved_mod_string
                    + " = malloc(sizeof(int*)*"
                    + str(index_limits)
                    + ");"
                ]
                free_line_part2.insert(
                    0, "\n \tfree(" + parentvar + saved_mod_string + ");"
                )
                free_line_part2.insert(0, "\n \t}")

                new_index_var = "index_" + chr(ord(index_var) + i)

                lines += [
                    "\n \tmemset("
                    + parentvar
                    + ",0, sizeof(int*) * "
                    + str(index_limits)
                    + ");"
                ]
                # text = text + "\n \t" + "for ( int " + new_index_var + "= 0; " + new_index_var + " < " + str(index_limits) + "; " + new_index_var + "++ )\n \t{\n"
                lines += [
                    "\n \t"
                    + "for ( int "
                    + new_index_var
                    + "= 0; "
                    + new_index_var
                    + " < "
                    + str(index_limits)
                    + " - 1; "
                    + new_index_var
                    + "++ )\n \t{\n"
                ]
                free_line_part1 += [
                    "\n \t"
                    + "for ( int "
                    + new_index_var
                    + "= 0; "
                    + new_index_var
                    + " < "
                    + str(index_limits)
                    + " - 1; "
                    + new_index_var
                    + "++ )\n \t{\n"
                ]
                saved_mod_string = saved_mod_string + "[" + new_index_var + "]"

            if len(index_limits_array) > num_modifiers - 1:
                index_limits = index_limits_array[num_modifiers - 1]
                if index_limits == -1:
                    index_limits = var_size(sizetype, num_modifiers)
                    dyn_size += 1
                    buf_size.append("sizeof(" + sizetype + ")")
                else:
                    buf_size.append("sizeof(" + sizetype + ")*" + str(index_limits))

            # text = text + "\n \t" + parentvar + saved_mod_string + "= malloc(sizeof("+sizetype+")*"+ str(index_limits) + ");\n"
            lines += [
                "\n\t"
                + parentvar
                + saved_mod_string
                + "= malloc(sizeof("
                + sizetype
                + ")*"
                + str(index_limits)
                + ");"
            ]
            free_line_part2.insert(0, "\n\tfree(" + parentvar + saved_mod_string + ");")

            lines += [
                "\n\tmemcpy("
                + parentvar
                + saved_mod_string
                + ", pos, sizeof("
                + sizetype
                + ")*"
                + str(index_limits)
                + ");"
            ]
            lines += ["\n\tpos += sizeof(" + sizetype + ")*" + str(index_limits) + ";"]

            for i in range(0, num_modifiers - 1, 1):
                # text = text + "\n \t" + "}\n"
                lines += ["\n \t" + "}"]

            free_line = free_line + free_line_part1 + free_line_part2

        if num_modifiers == 1:
            # These are single pointers
            if len(index_limits_array) > num_modifiers - 1:
                index_limits = index_limits_array[num_modifiers - 1]
                if index_limits == -1:
                    index_limits = var_size(sizetype)
                    dyn_size += 1
                    buf_size.append("sizeof(" + sizetype + ")")
                else:
                    buf_size.append("sizeof(" + sizetype + ")*" + str(index_limits))
            lines += [
                "\n\t"
                + parentvar
                + "= malloc(sizeof("
                + sizetype
                + ")*"
                + str(index_limits)
                + ");"
            ]
            free_line += ["\n\tfree(" + parentvar + ");"]
            lines += [
                "\n \tmemset("
                + parentvar
                + ",0, sizeof("
                + sizetype
                + ") * "
                + str(index_limits)
                + ");"
            ]
            lines += [
                "\n\tmemcpy("
                + parentvar
                + ", pos, sizeof("
                + sizetype
                + ")* ("
                + str(index_limits)
                + " - 1));"
            ]
            lines += [
                "\n\tpos += sizeof(" + sizetype + ")* (" + str(index_limits) + " - 1);"
            ]

        if num_modifiers == 0:
            # These are normal variables like BIGNUM
            lines += ["\n\tmemcpy(&" + parentvar + ", pos, sizeof(" + sizetype + "));"]
            lines += ["\n\tpos += sizeof(" + sizetype + ");"]
            buf_size.append("sizeof(" + sizetype + ")")

    # Very, very important: Iterate assignment tree from leaf to root
    for key, value in reversed(parent_child_map.items()):
        parentvar = key
        sizetype = type_vars[parentvar]
        num_modifiers = is_pointer[parentvar]
        index_var = "a"
        index_limits_array = literals[parentvar]
        saved_mod_string = ""

        if parentvar in incomplete_types:
            sizetype = "char"
            continue

        if sizetype.strip() == "void":
            sizetype = "char"

        if "va_list" in sizetype.strip():
            continue

        for i in range(0, num_modifiers, 1):
            index_limits = index_limits_array[i]
            if index_limits == -1:
                if i == num_modifiers - 1:
                    index_limits = var_size(sizetype, num_modifiers)
                else:
                    index_limits = var_size("int*", num_modifiers)

            new_index_var = "index_" + chr(ord(index_var) + i)
            # text = text + "\n \t" + "for ( int " + new_index_var + "= 0; " + new_index_var + " < " + str(index_limits) + "; " + new_index_var + "++ )\n \t{\n"
            lines += [
                "\n \t"
                + "for ( int "
                + new_index_var
                + "= 0; "
                + new_index_var
                + " < "
                + str(index_limits)
                + " - 1; "
                + new_index_var
                + "++ )\n \t{"
            ]
            saved_mod_string = saved_mod_string + "[" + new_index_var + "]"

        for v in value:
            childvar = var_map[v]
            if childvar in declared:
                subfield = re.sub("_*$", "", childvar)
                # Compiler complains on assigning arrays like this (I dunno why)
                if "[" not in v:
                    # text = text + "\n \t" + parentvar + saved_mod_string+"."+subfield+" = "+childvar+";\n"
                    lines += [
                        "\n \t"
                        + parentvar
                        + saved_mod_string
                        + "."
                        + subfield
                        + " = "
                        + childvar
                        + ";"
                    ]

                # else:
                #    text = text + "\n \t" + parentvar +"."+subfield+" = "+childvar+";\n"
        for i in range(0, num_modifiers, 1):
            # text = text + "\n \t" + "}\n"
            lines += ["\n \t" + "}"]

    # text = text + "\n \t return 0;\n }"
    # with open("temp.c", "w") as f:
    #    f.write(text)
    return dyn_size, buf_size, lines, free_line


def parseXML(xmlfile, function):
    # create element tree object
    tree = etree.parse(xmlfile)

    # get root element
    root = tree.getroot()
    watch = 0
    parameters = []
    for node in tree.iter():
        if watch == 1 and node.tag == "{http://www.srcML.org/srcML/src}argument_list":
            for arg in node.findall("{http://www.srcML.org/srcML/src}argument"):
                var = "".join(arg.itertext())
                if var:
                    var = re.sub("const ", "", var)
                    parameters += [var]
            watch = 0

        if watch == 1 and node.tag == "{http://www.srcML.org/srcML/src}parameter_list":
            for parameter in node.findall(
                ".//{http://www.srcML.org/srcML/src}parameter"
            ):
                p = "".join(parameter.itertext())
                item = re.sub("const ", "", p)
                parameters += [item]
            watch = 0

        if (
            node.tag == "{http://www.srcML.org/srcML/src}function"
            or node.tag == "{http://www.srcML.org/srcML/src}macro"
        ):
            for namenode in node.findall("{http://www.srcML.org/srcML/src}name"):
                name = "".join(namenode.itertext())
                if name == function:
                    watch = 1

    if parameters == []:
        print("Couldn't find function")
        exit()

    return parameters


def identify_names(xmlfile, reg=0):
    # create element tree object
    tree = etree.parse(xmlfile)

    types = []
    vars = []
    pointer_list = []
    count = 0
    for node in tree.iter():
        if node.tag == "{http://www.srcML.org/srcML/src}decl_stmt":
            decl = node
            type = ""
            var = ""
            pointers = 0
            literal_value = []
            for typenode in decl.findall(".//{http://www.srcML.org/srcML/src}type"):
                for namenode in typenode.findall(
                    ".//{http://www.srcML.org/srcML/src}name"
                ):
                    type = "".join(namenode.itertext()) + " "
                    break
            for varnode in decl.findall(".//{http://www.srcML.org/srcML/src}name"):
                var = "".join(varnode.itertext())
            for modifiernode in decl.findall(
                ".//{http://www.srcML.org/srcML/src}modifier"
            ):
                pointers = pointers + 1
                literal_value.append(-1)
            for indexnode in decl.findall(".//{http://www.srcML.org/srcML/src}index"):
                pointers = pointers + 1
                literalnodes = indexnode.findall(
                    ".//{http://www.srcML.org/srcML/src}literal"
                )
                for literal in literalnodes:
                    literal_value.append("".join(literal.itertext()))
                if not (literalnodes):
                    literal_value.append(-1)

            if reg == 0:
                is_pointer[var] = pointers
                literals[var] = literal_value
                type_vars[var] = type
                var_map["".join(decl.itertext())[:-1]] = var

            types += [type]
            vars += [var]
            pointer_list += [pointers]
            count = count + 1

    return [types, vars, pointer_list]


def get_name(parameters, reg=0):
    global tmp_dir
    text = ""
    for parameter in parameters:
        text = text + parameter + ";\n"
    args = ("srcml", "-l", "C", "--text=" + text, "-o", tmp_dir + "/var.xml")
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    types, vars, pointers = identify_names(tmp_dir + "/var.xml", reg)
    return [types, vars, pointers]


def Isprimitive(type):
    matches = re.finditer("{", type)
    m = None
    for m in matches:
        break

    end = len(type)
    if m:
        end = min(end, m.start())

    for primitive in primitives:
        if primitive in type[0:end]:
            return 1
    return 0


def Isfunctionptr(type):
    args = ("srcml", "-l", "C", "--text=" + type + ";\n", "-o", tmp_dir + "/var.xml")
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    # print(output)
    tree = etree.parse(tmp_dir + "/var.xml")

    if tree.find("./{http://www.srcML.org/srcML/src}function_decl") is not None:
        return 1
    if (
        tree.find(
            "./{http://www.srcML.org/srcML/src}struct/{http://www.srcML.org/srcML/src}decl/{http://www.srcML.org/srcML/src}argument_list"
        )
        is not None
    ):
        return 1
    return 0


def executesrcml(file):
    args = ("srcml", file, "-o", "output.xml")
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    output = popen.stdout.read()
    return output


def compilebinary(file, compile_command, link_command):
    # args = ("gcc", file, "-w", "-g", "-I", "../openssl/include", "-I", "../openssl/ssl", "-I", "../openssl/", "-I", "../openssl/apps/include", "-o", "./a.out")
    global tmp_dir
    my_env = os.environ
    repository = re.search('workspace/(.+?)/test_files', file).group(1)
    my_env["LD_LIBRARY_PATH"] = os.path.abspath(
             "./test_lib/" + repository + "/build_ss"
    )
    for c in compile_command:
        args = shlex.split(c, posix=False)
        for i, arg in enumerate(args):
            if file in arg:
                args[i] = tmp_dir + "/temp.c"
            if "fsanitize" in arg:
                args[i] = ""
        args = list(filter(None, args))
        cmd = " ".join(args)
        popen = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=my_env
        )
        popen.wait()
        output = popen.stderr.read().decode("utf-8")
        if "error" in output:
            lines = output.split("\n")
            uncompiled_vars = []
            for i, line in enumerate(lines):
                if "incomplete type" in line:
                    if "sizeof(" in lines[i + 1]:
                        # This means that the base type is incomplete type even if its pointer is valid
                        var = (
                            lines[i + 1]
                            .replace("sizeof(", "")
                            .replace(");", "")
                            .replace("*", "")
                            .strip()
                        )
                        incomplete_types[var] = 1
                        return 1, []
                    else:
                        type, var, pointers = get_name([lines[i + 1].strip()], 1)
                        uncompiled_vars.append(var[0])
            if uncompiled_vars != []:
                return 1, uncompiled_vars
            print("Compilation failed: \n")
            print(output)
            return 0, []

    if link_command:
        args = shlex.split(link_command[0], posix=False)
        for i, arg in enumerate(args):
            if arg.endswith(".out"):
                args[i] = tmp_dir + "/a.out"
            if "fsanitize" in arg:
                args[i] = ""
        args = list(filter(None, args))
        cmd = " ".join(args)

        popen = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        popen.wait()
        output = popen.stderr.read().decode("utf-8")
        if "error" in output:
            print("Link failed: \n")
            print(cmd)
            print("\n")
            print(output)
            return 0, []

    return 0, []


def numlines(file):
    num_lines = sum(1 for line in open(file))
    return num_lines


def get_content_between_paranthesis(text):
    start = -1
    end = -1
    paranthesis = 0
    for i, char in enumerate(text):
        if start == -1 and char == "{":
            start = i + 1
        if char == "{":
            paranthesis += 1
        if char == "}":
            paranthesis -= 1
        if start != -1 and paranthesis == 0:
            end = i - 1
            break
    if start == -1:
        return ""
    return text[start:end]


def executegdb(num_lines, vars, parameters):
    global tmp_dir
    args = ("gdb", tmp_dir + "/a.out")
    popen = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    # process = subprocess.Popen( args, shell=False, universal_newlines=True,
    # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE )

    popen.stdin.write(("b " + str(num_lines - 1) + "\n").encode(encoding="UTF-8"))
    popen.stdin.write(("r\n y \n").encode(encoding="UTF-8"))

    for var in vars:
        popen.stdin.write(("ptype " + var + "\n").encode(encoding="UTF-8"))

    popen.stdin.close()
    output = popen.stdout.read()

    subvars = []
    collected = 0
    for i, line in enumerate(str(output).split("(gdb)")):
        if i <= 3 or collected == len(vars):
            continue
        # Remove the gdb extra characters
        type = line[8:]
        # print(vars[i-4] + " -> "+ type)
        if "incomplete type" in type:
            # print("Incomplete type: "+type+"\n")
            incomplete_types[vars[i - 4]] = 1
            collected = collected + 1
            continue

        if Isfunctionptr(type):
            collected = collected + 1
            do_not_fuzz[vars[i - 4]] = 1
            continue

        between = get_content_between_paranthesis(type)
        subtypes = [x.replace("\\n", "").strip() for x in re.split(r";", between) if x]
        j = 0
        while j < len(subtypes):
            innerstruct = subtypes[j]

            # Disallow inner struct parsing for now
            if innerstruct.count("{") > innerstruct.count("}"):
                paranthesis_counter = innerstruct.count("{") - innerstruct.count("}")
                while paranthesis_counter != 0:
                    j = j + 1
                    if "{" in subtypes[j]:
                        paranthesis_counter += 1
                    if "}" in subtypes[j]:
                        paranthesis_counter -= 1
                j = j + 1
                continue
            elif ("{" in innerstruct) and ("}" in innerstruct):
                # This is for enums
                j = j + 1
                continue

            if not (Isfunctionptr(innerstruct)):
                inner_struct_type, inner_struct_name, pointers = get_name(
                    [innerstruct], 1
                )

                if len(inner_struct_name) == 0:
                    j = j + 1
                    continue
                new_name = inner_struct_name[0]

                if new_name in disallowed_names:
                    j = j + 1
                    continue

                # Replace only the variable name with the new name. For this we find
                # last matching instance of name so as to be careful not to mutate type string
                while new_name in type_vars:
                    # print(new_name +" -> "+inner_struct_type[0]+ "   "+ type_vars[new_name])
                    if (
                        inner_struct_type[0] == type_vars[new_name]
                        and pointers[0] == is_pointer[new_name]
                    ):
                        break
                    new_name = new_name + "_"
                pos = innerstruct.rfind(inner_struct_name[0])
                innerstruct = (
                    innerstruct[:pos]
                    + new_name
                    + innerstruct[pos + len(inner_struct_name[0]) :]
                )

                if new_name not in type_vars:
                    subvars += [innerstruct]

                get_name([innerstruct], 0)
                # print(vars[i-4] + " --> "+innerstruct)
                if vars[i - 4] not in parent_child_map:
                    parent_child_map[vars[i - 4]] = [innerstruct]
                else:
                    parent_child_map[vars[i - 4]] += [innerstruct]
            j = j + 1

        collected = collected + 1
    return subvars


def prepare_directory(file):
    global tmp_dir
    parent_dir = os.path.abspath(os.path.join(file, os.pardir))
    dir = os.path.join(parent_dir, "tmp")
    if os.path.exists(dir):
        shutil.rmtree(dir)
    os.makedirs(dir)
    tmp_dir = dir
    return dir


def reset_param_globals():
    global parent_child_map
    global is_pointer
    global literals
    global type_vars
    global incomplete_types
    global tmp_dir
    global do_not_fuzz
    global var_map
    global declared

    parent_child_map = {}
    is_pointer = {}
    literals = {}
    type_vars = {}
    incomplete_types = {}
    do_not_fuzz = {}
    var_map = {}
    declared = set()
    tmp_dir = ""


def del_list_numpy(list_main, id_to_del):
    arr = np.array(list_main)
    return list(np.delete(arr, id_to_del))


def remove_vars(types, vars, parameters, match_vars):
    indices = []
    for i, var in enumerate(vars):
        if var in match_vars:
            indices.append(i)

    vars = del_list_numpy(vars, indices)
    types = del_list_numpy(types, indices)
    parameters = del_list_numpy(parameters, indices)

    return types, vars, parameters


# Register names of initial params so that they are not taken up by inner struct members later
# Also set up the temp directories
def register_initial_paramnames(file, initial_params):
    tmp_dir = prepare_directory(file)
    get_name(initial_params)


def expand_struct(file, parameters, compile_command, link_command):
    if parameters[0].strip() == "void":
        return (
            0,
            [],
            {
                "gen_lines": [],
                "gen_free": [],
            },
        )
    new_params = parameters
    counting = 0
    if compile_command == [] and link_command == []:
        new_params = []
        types, vars, pointers = get_name(parameters)
        dyn_size, buf_size, lines = add_dummy_parameter(vars, types)
        curr_gen = {
            "gen_lines": ["//GEN_STRUCT\n"] + lines,
            "gen_free": [],
        }
        return dyn_size, buf_size, curr_gen

    while new_params:
        # print(new_params)
        types, vars, pointers = get_name(parameters)

        # Compile till all incomplete types removed
        while True:
            modifymain(file, types, vars)
            ret, uncompiled_vars = compilebinary(file, compile_command, link_command)
            if ret == 0:
                break
            else:
                types, vars, parameters = remove_vars(
                    types, vars, parameters, uncompiled_vars
                )
        num_lines = numlines(tmp_dir + "/temp.c")
        new_params = executegdb(num_lines, vars[-len(new_params) :], parameters)
        parameters = parameters + new_params
        counting = counting + 1

    dyn_size, buf_size, lines, free_line = add_assignment(file, parameters, vars, types)
    curr_gen = {
        "gen_lines": ["//GEN_STRUCT\n"] + lines,
        "gen_free": free_line,
    }
    return dyn_size, buf_size, curr_gen
