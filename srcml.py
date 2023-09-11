import enum
import os
from collections import defaultdict
import typing
from functools import total_ordering
from typing import Set

import clang.cindex
from loguru import logger
from lxml import etree as et
from lxml.etree import Element

ns = {"src": "http://www.srcML.org/srcML/src", "cpp": "http://www.srcML.org/srcML/cpp"}
# './src:macro' broken - SSL_CTX_get_verify_mode due to (*SSL_get_verify_callback(...
test_nodes = (
    "./src:function",
    "./src:struct",
    "./src:macro",
    "./src:define/src:macro",
    "./src:decl",
    # These are srcml parsing issues
    # "./src:enum/src:decl",
    "./src:struct/src:decl",
    "./src:decl_stmt/src:decl",
    "./src:typedef",
    "./src:function_decl",
    "./src:typedef/src:function_decl",
)


def get_pos_row_col(element: et.Element, event: str):
    """Returns [row,col] from srcML position start attribute or [-1,-1] if the
    attribute is not present"""

    row_num = -1
    col_num = -1
    if (
        event == "start"
        and "{http://www.srcML.org/srcML/position}start" in element.attrib
    ):
        srcml_pos = element.attrib["{http://www.srcML.org/srcML/position}start"].split(
            ":"
        )
        row_num = int(srcml_pos[0])
        col_num = int(srcml_pos[1])
    elif (
        event == "end" and "{http://www.srcML.org/srcML/position}end" in element.attrib
    ):
        srcml_pos = element.attrib["{http://www.srcML.org/srcML/position}end"].split(
            ":"
        )
        row_num = int(srcml_pos[0])
        col_num = int(srcml_pos[1])

    return [row_num, col_num]


def get_xml_line(element: et.Element, event: str):
    """Returns line number within the xml stream where 'element' starts or ends"""
    line_num = -1
    if event == "start":
        # Subtract one because first xml line in the srcml is the XML declaration
        line_num = element.sourceline - 1
    elif event == "end":
        # Based on https://stackoverflow.com/a/47903639, by RomanPerekhrest
        line_num = element.sourceline - 1
        content = et.tostring(element, method="text", with_tail=False)
        if content:
            # Using split("\n") because splitlines() will drop the last newline character
            line_num += len(content.decode("utf8").split("\n")) - 1

    return line_num


def get_name(node, simple=False):
    names = node.xpath("./src:name", namespaces=ns)
    build_name = []
    if names is None:
        logger.info(
            f"Failed to get node name for node in xml at line {node.sourceline}"
        )
        return None
    for name in names:
        if name.text is None:
            return get_name(name)
        else:
            build_name.append(name.text)
    if simple:
        return build_name
    return " ".join(build_name)


def get_type(node, func_name):
    names = node.find("{http://www.srcML.org/srcML/src}type")
    build_type = ""
    if names is None:
        if func_name.startswith("_"):
            # Old syntax resolution
            return "int"
        logger.info(
            f"Failed to get node type for node in xml at line {node.sourceline}"
        )
        return None
    for name in names:
        if name.text is None:
            return get_name(name)
        else:
            if build_type:
                build_type = build_type + " "
            build_type = build_type + name.text
    return build_type


def get_instances(s_node, t_path, simple=False) -> Set[str]:
    names = set()
    if s_node.tag in ("{http://www.srcML.org/srcML/src}macro",):
        next_block = s_node.getnext()
        if next_block is not None:
            s_node = next_block
    if simple:
        return {
            a.text + ";" + str(get_pos_row_col(a, "start")[0])
            for a in s_node.xpath(t_path, namespaces=ns)
            if a.text
        }
    for node in s_node.xpath(t_path, namespaces=ns):
        name_mult = get_name(node)
        name_mult = [name_mult]
        for name in name_mult:
            names.add(name + ";" + str(get_pos_row_col(node, "start")[0]))
    return names


def get_parameters(s_node):
    parameters = []
    for param_node in s_node.xpath("./src:parameter_list/src:parameter", namespaces=ns):
        # Get all parameters in same format with the modifier *
        num_pointers = 0
        parameter_type = ""
        parameter_name = ""
        is_function = 0
        for node in param_node.xpath("./src:decl", namespaces=ns):
            # Name of variable
            for namenode in node.xpath(".//src:name", namespaces=ns):
                parameter_name = "".join(namenode.itertext())
            # Type of parameter
            for nametype in node.xpath("./src:type/src:name", namespaces=ns):
                parameter_type = "".join(nametype.itertext())
            # Number of pointers
            for modifiernode in node.xpath(".//src:modifier", namespaces=ns):
                num_pointers += 1
            for modifiernode in node.xpath(".//src:index", namespaces=ns):
                num_pointers += 1

        for node in param_node.xpath("./src:function_decl", namespaces=ns):
            is_function = 1

        for j in range(num_pointers):
            parameter_type = parameter_type + "*"

        parameter = "".join(node.itertext())
        parameters.append(
            {
                "parameter": parameter + ";" + str(get_pos_row_col(node, "start")[0]),
                "param_name": parameter_name,
                "param_type": parameter_type,
                "function_ptr": is_function,
            }
        )
    return parameters


class DataTypeDetail:
    def __init__(self):
        self.generator_type = DataType.UNKNOWN
        self.is_pointer: bool = False
        self.array_size: int = 0  # for saving the size of array, for example int[30]
        self.type_name: str = ""
        self.parent_type: str = ""
        self.parent_gen: str = (
            ""  # save the function name for generating if generator_type == GEN_STRUCT
        )


@total_ordering
class DataType(enum.Enum):
    BUILTIN = 0  # All basic types: int, float, double, ...
    STRING = 1  # char *, const char *
    ENUM = 2
    ARRAY = 3
    VOIDP = 4
    QUALIFIER = 5  # const, volatile, and restrict qualifiers
    POINTER = 6
    STRUCT = 7
    INCOMPLETE = 8
    FUNCTION = 9
    INPUTFILE = 10
    OUTPUTFILE = 11
    UNKNOWN = 12

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


def getDataTypeDetail(typ: clang.cindex.Type) -> DataTypeDetail:
    qual_type_detail = DataTypeDetail()
    qual_type_detail.array_size = 1
    qual_type_detail.type_name = typ.spelling
    qual_type_detail.generator_type = DataType.UNKNOWN
    canonical_type = typ.get_canonical()

    if canonical_type.spelling == "void *" or canonical_type.spelling == "const void *":
        qual_type_detail.generator_type = DataType.VOIDP
        return qual_type_detail
    if (
        canonical_type.spelling == "char *"
        or canonical_type.spelling == "const char *"
        or canonical_type.spelling == "const unsigned char *"
        or canonical_type.spelling == "unsigned char *"
    ):
        qual_type_detail.parent_type = ""
        qual_type_detail.generator_type = DataType.STRING
        if canonical_type.spelling == "const char *":
            qual_type_detail.parent_type = "char *"
        if canonical_type.spelling == "const unsigned char *":
            qual_type_detail.parent_type = "unsigned char *"
        return qual_type_detail

    if (
        typ.is_const_qualified()
        or typ.is_volatile_qualified()
        or typ.is_restrict_qualified()
    ):
        qual_type_detail.generator_type = DataType.UNKNOWN
        qual_type_detail.parent_type = typ.spelling
        if (
            qual_type_detail.parent_type == "const char *"
            or qual_type_detail.parent_type == "const unsigned char *"
        ):
            qual_type_detail.parent_gen = "string"
            return qual_type_detail
        if typ.kind.value == 0:
            qual_type_detail.parent_gen = "incomplete"
            return qual_type_detail
        return qual_type_detail

    if typ.kind.value == 0:
        qual_type_detail.generator_type = DataType.INCOMPLETE
        return qual_type_detail

    if 3 <= typ.kind.value <= 23:
        qual_type_detail.generator_type = DataType.BUILTIN
        return qual_type_detail

    if typ.kind.value == 106:
        qual_type_detail.generator_type = DataType.ENUM
        return qual_type_detail

    if typ.kind.value == 111:
        qual_type_detail.generator_type = DataType.FUNCTION
        return qual_type_detail

    if typ.kind.value == 101:
        pointee_typ = typ.get_pointee()
        if pointee_typ.kind.value == 0:
            qual_type_detail.generator_type = DataType.INCOMPLETE
            return qual_type_detail
        else:
            if 3 <= pointee_typ.kind.value <= 23:
                qual_type_detail.generator_type = DataType.POINTER
                qual_type_detail.is_pointer = True
                qual_type_detail.parent_type = pointee_typ.spelling
                return qual_type_detail
            else:
                type_split = qual_type_detail.type_name.split()
                if "struct" in type_split:
                    qual_type_detail.generator_type = DataType.INCOMPLETE
                    return qual_type_detail
            qual_type_detail.generator_type = DataType.UNKNOWN
            return qual_type_detail

    if typ.kind.value == 112:
        qual_type_detail.type_name = typ.get_array_element_type().spelling
        qual_type_detail.generator_type = DataType.ARRAY
        qual_type_detail.array_size = typ.get_array_size()
        return qual_type_detail

    type_split = qual_type_detail.type_name.split()
    if "struct" in type_split:
        qual_type_detail.generator_type = DataType.STRUCT
        return qual_type_detail
    return qual_type_detail


def filter_node_list_by_node_kind(
    nodes: typing.Iterable[clang.cindex.Cursor],
    kinds: list,
    name: typing.Optional[str] = None,
) -> typing.Iterable[clang.cindex.Cursor]:
    result = []
    for i in nodes:
        if i.kind in kinds:
            if name is not None:
                if "_" + i.spelling != name:
                    continue
            result.append(i)
    return result


def construct_params(name, file_name, srcmlparams):
    parameters = []
    if name == "_original_main":
        name = "_main"
    # for param in node.xpath("./src:parameter_list/src:parameter/src:decl", namespaces=ns):
    #     params.append({
    #         "param_name": get_name(param),
    #         "param_type": get_type(param, ""),
    #         # "generator_type":
    #         # "array_size":
    #         # "parent_type":
    #         # "parent_gen":
    #         # "param_usage":
    #     })

    for i, param in enumerate(srcmlparams):
        # Do not allow variable argument to be counted as argument
        if srcmlparams[i]["parameter"].split(";")[0] == "...":
            continue
        parameters.append(
            {
                "parameter": srcmlparams[i]["parameter"].split(";")[0],
                "param_name": srcmlparams[i]["param_name"],
                "param_type": srcmlparams[i]["param_type"],
                "function_ptr": srcmlparams[i]["function_ptr"],
                "generator_type": DataType.UNKNOWN,
                "param_usage": "UNKNOWN",
            }
        )
    return parameters


class Function:
    def __init__(
        self,
        node: Element,
        name: str,
        file_name: str,
        ftype: str,
        start: list,
        end: list,
        is_function: bool,
    ):
        self.name = name
        self.file_name = file_name
        self.type = ftype
        self.start = start
        self.end = end
        self.labels = get_instances(node, ".//src:label")
        self.calls = get_instances(node, ".//src:call")
        self.types_used = get_instances(node, ".//src:type")
        self.parameter = get_parameters(node)
        # gets all name tags used
        self.expr_used = get_instances(node, ".//src:name", True)
        # self.call_argument = get_call_argument(self.expr_used)
        self.is_function = is_function
        self.call_arguments = []

    def params(self, srcmlparams):
        if self.is_function:
            return construct_params(self.name, self.file_name, srcmlparams)
        else:
            return []

    def encloses(self, line: int) -> bool:
        # Ignores column numbers
        if self.start[0] <= line <= self.end[0]:
            return True
        else:
            return False


def recover_nodes_in_order(child, scopeless_nodes, recover_order=None):
    if recover_order is None:
        recover_order = []
    for n_child in child:
        if n_child.tag in scopeless_nodes:
            recover_order.append(n_child)
        else:
            recover_nodes_in_order(n_child, scopeless_nodes, recover_order)
    return recover_order


def validate_removal(lineno, block, is_parent=False):
    # req_labels = []
    # if is_parent:
    #     for goto in block.xpath(".//src:goto", namespaces=ns):
    #         goto[0].text
    for child in block:
        if get_pos_row_col(child, "start")[0] > lineno:
            scopeless_nodes = (
                "{http://www.srcML.org/srcML/cpp}if",
                "{http://www.srcML.org/srcML/cpp}ifdef",
                "{http://www.srcML.org/srcML/cpp}ifndef",
                "{http://www.srcML.org/srcML/cpp}endif",
            )
            if len(child.xpath(".//src:label", namespaces=ns)):
                continue
            if child.tag in scopeless_nodes:
                continue
            elif child.tag in (
                "{http://www.srcML.org/srcML/src}label",
                "{http://www.srcML.org/srcML/src}goto",
            ):
                if is_parent:
                    child.tail = " ;\n\n"
                    continue
            elif child.tag in ("{http://www.srcML.org/srcML/src}return",):
                node_xml = et.fromstring(
                    '<return>return <expr><literal type="number">0</literal></expr>;</return>'
                )
                node_xml.tail = "\n\n"
                child.getparent().replace(child, node_xml)
                continue
            recovery = recover_nodes_in_order(child, scopeless_nodes)
            if len(recovery) >= 1:
                for rec in recovery:
                    child.getprevious().tail = child.getprevious().tail + "\n"
                    child.addprevious(rec)
            # 2 Piece statement
            if block.tag in ['{http://www.srcML.org/srcML/src}do']:
                if child.tag == '{http://www.srcML.org/srcML/src}condition':
                    continue
            block.remove(child)
        if (
            get_pos_row_col(child, "start")[0]
            < lineno
            < get_pos_row_col(child, "end")[0]
        ):
            # We should not edit stuff inside a function call during minimization
            if child.tag in (
                "{http://www.srcML.org/srcML/src}call",
                "{http://www.srcML.org/srcML/src}if_stmt",
            ):
                continue
            validate_removal(lineno, child)


def analyze_struct(nodes, func_name):
    typed_children = {}
    for node in nodes.xpath("./src:block/src:decl_stmt/src:decl", namespaces=ns):
        str_nam = get_name(node)
        str_typ = get_type(node, func_name)
        typed_children[str_nam] = str_typ
    # makeshift handling
    for node in nodes.xpath("./src:block/src:expr_stmt/src:expr", namespaces=ns):
        str_nam = get_name(node)
        if str_nam:
            str_typ = node.xpath("string()").split(str_nam)[0]
            typed_children[str_nam] = str_typ
        else:
            logger.error(f"Failed to resolve {node.xpath('string()')}")
    return typed_children


class Srcml:
    def __init__(self, xml_loc: str):
        self.xml_loc = xml_loc
        self.decl_info = {}
        self.xml = self.parse_xml().getroot()
        self.typed_elements = {}

    def __getstate__(self):
        state = self.__dict__.copy()
        # Don't pickle tree
        del state["xml"]
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Add back tree
        self.xml = self.parse_xml().getroot()

    def parse_xml(self):
        if not os.path.exists(self.xml_loc):
            self.xml_loc = self.xml_loc.replace("_fixed", "")
        return et.parse(self.xml_loc)

    def nxml(self, nxpath):
        return self.xml.xpath(nxpath, namespaces=ns)

    def get_all_defined_functions_and_range(self):
        for file in self.nxml("./src:unit"):
            file_name = file.attrib["filename"]
            self.decl_info[file_name] = {}
            for key in test_nodes:
                for node in file.xpath(key, namespaces=ns):
                    func_name = get_name(node)
                    if not func_name:
                        # like struct/decl anonymouse types cms_attribute_properties
                        logger.warning(
                            "Unable to resolve name for node at {}", node.sourceline
                        )
                        continue
                    is_function = False
                    if key == "./src:function":
                        if func_name == "main":
                            logger.warning("main function found in {}", file_name)
                        func_name = "_" + func_name
                        is_function = True
                    if key == "./src:function_decl":
                        func_name = "_decl_" + func_name
                    if key == "./src:typedef/src:function_decl":
                        func_name = "_decl_" + func_name
                    if key == "./src:struct":
                        ftype = "struct"
                        func_name = "struct " + func_name
                        self.typed_elements = analyze_struct(node, func_name)
                    elif key == "./src:decl":
                        ftype = "decl"
                        func_name = "_" + func_name.split()[-1]
                    elif key == "./src:struct/src:decl":
                        ftype = "struct"
                        func_name = "_" + func_name
                    elif "macro" in key:
                        ftype = "macro"
                        func_name = "macro " + func_name
                    else:
                        ftype = get_type(node, func_name)
                    if func_name and ftype:
                        if self.decl_info[file_name].get(func_name, None):
                            self.decl_info[file_name][func_name] = Function(
                                node,
                                func_name,
                                file_name,
                                ftype,
                                get_pos_row_col(node, "start"),
                                get_pos_row_col(node, "end"),
                                is_function,
                            )
                        else:
                            # TODO could cause issues when function overloading is involved
                            logger.warning(
                                "Existing declaration replaced {}", func_name
                            )
                            self.decl_info[file_name][func_name] = Function(
                                node,
                                func_name,
                                file_name,
                                ftype,
                                get_pos_row_col(node, "start"),
                                get_pos_row_col(node, "end"),
                                is_function,
                            )

            # If any of the used names are an existing function then we.ve found a function pointer!
            for func_name, function in self.decl_info[file_name].items():
                if function.expr_used:
                    expressions = function.expr_used
                    for expr in expressions:
                        name = "_" + expr.split(";")[0]
                        if (name != func_name) and (name in self.decl_info[file_name]):
                            self.decl_info[file_name][func_name].call_arguments.append(
                                expr
                            )
                        name = "_decl_" + expr.split(";")[0]
                        if (name != func_name) and (name in self.decl_info[file_name]):
                            self.decl_info[file_name][func_name].call_arguments.append(
                                expr
                            )

    def get_enclosing_function(self, file_name: str, line: int, defined_funcs_in_file):
        for func_name in defined_funcs_in_file:
            function = self.decl_info[file_name].get(func_name)
            # file_info = self.nxml(f"./src:unit[@filename='{file_name}']")[0]
            # calls = file_info.xpath(".//src:call", namespaces=ns)
            # for call in calls:
            #     if get_pos_row_col(call, "start")[0] == line:
            #         pass

            if function.is_function and function.encloses(line):
                res_func = function
                return res_func
        return None

    def get_used_types(self, file_name: str, func_name: str, used_types, lineno=None):
        function_info = self.decl_info[file_name].get(func_name)
        if function_info is not None:
            for inf_key in ("types_used", "expr_used"):
                if lineno is not None:
                    for types in getattr(function_info, inf_key):
                        if int(types.split(";")[1]) <= lineno:
                            name = types.split(";")[0]
                            if name not in used_types:
                                used_types.add(name)
                                used_types.update(
                                    self.get_used_types(
                                        file_name, name, used_types, lineno
                                    )
                                )

                else:
                    for types in getattr(function_info, inf_key):
                        name = types.split(";")[0]
                        if name not in used_types:
                            used_types.add(name)
                            used_types.update(
                                self.get_used_types(file_name, name, used_types, lineno)
                            )

        return used_types

    def internal_function_references(self, file_name, used_types, line):
        # call_arguments = []
        # for node in s_node.xpath(".//src:call//src:argument/src:expr", namespaces=ns):
        #     # Get all parameters in same format with the modifier *
        #     name_mult = get_name(node, True)
        #     for name in name_mult:
        #         call_arguments.append(name + ";" + str(get_pos_row_col(node, "start")[0]))

        ref_functions = set()
        for type in used_types:
            if self.decl_info[file_name].get(type) is not None:
                args = self.decl_info[file_name].get(type).call_arguments
                for arg in args:
                    func_name = "_" + arg.split(";")[0]
                    lineno = arg.split(";")[1]
                    if (line is None) or int(lineno) <= int(line):
                        ref_functions.update([func_name])

        return ref_functions

    def get_calls_recursively(
        self, file_name: str, func_name: str, lineno=None, all_calls=None
    ):
        if all_calls is None:
            all_calls = set()
        function_info = self.decl_info[file_name].get(func_name)
        if function_info is not None:
            if lineno is not None:
                filtered_calls = {
                    "_" + call.split(";")[0]
                    for call in function_info.calls
                    if int(call.split(";")[1]) <= lineno
                }
                call_arguments = {
                    "_" + call.split(";")[0]
                    for call in function_info.call_arguments
                    if int(call.split(";")[1]) <= lineno
                }
            else:
                filtered_calls = {
                    "_" + call.split(";")[0] for call in function_info.calls
                }
                call_arguments = {
                    "_" + call.split(";")[0] for call in function_info.call_arguments
                }
            for sub_func in filtered_calls:
                if sub_func not in all_calls:
                    all_calls.add(sub_func)
                    all_calls = all_calls.union(
                        self.get_calls_recursively(
                            file_name, sub_func, all_calls=all_calls
                        )
                    )
            # Needed for function pointers
            for sub_func in call_arguments:
                if self.decl_info[file_name].get(sub_func) is not None:
                    if sub_func not in all_calls:
                        all_calls.add(sub_func)
                        all_calls = all_calls.union(
                            self.get_calls_recursively(
                                file_name, sub_func, all_calls=all_calls
                            )
                        )
        # name mangling to keep track of functions easily
        return {tf for tf in all_calls}

    def mark(self, line_no):
        xml_file = self.xml_loc
        pre_xml = '\n<comment type="line">// clang-format off</comment>\n'
        insert_xml = '<comment type="line">/*target_line*/</comment>'
        post_xml = '\n<comment type="line">// clang-format on</comment>\n'
        with open(xml_file, "r") as f:
            lines = f.readlines()
        line = lines[line_no].strip()
        lines[line_no] = insert_xml + line
        lines.insert(line_no, pre_xml)
        lines.insert(line_no + 2, post_xml)
        with open(xml_file, "w") as f:
            f.write("\n".join(lines))
        self.__init__(xml_file)

    def drop(self, drop_set, used):
        for xtype in test_nodes:
            for node in self.nxml(xtype):
                func_name = get_name(node)
                if not func_name:
                    continue
                if xtype == "./src:decl_stmt/src:decl":
                    if func_name in used:
                        continue
                    else:
                        if node.tail and ";" in node.tail:
                            if node.getprevious() is not None:
                                node.getprevious().tail = node.tail;
                        elif node[0].tag == '{http://www.srcML.org/srcML/src}type':
                            if node.getnext() is not None:
                                node.getnext()[0].addprevious(node[0])
                        node.getparent().remove(node)
                        continue
                if xtype == "./src:function":
                    func_name = "_" + func_name
                elif xtype == "./src:function_decl":
                    # _decl_ but just so it is retained whenever function is used
                    func_name = "_" + func_name
                elif xtype == "./src:typedef/src:function_decl":
                    func_name = "_" + func_name
                elif xtype == "./src:struct":
                    func_name = "struct " + func_name
                elif xtype == "./src:decl":
                    func_name = "_" + func_name.split()[-1]
                elif "macro" in xtype:
                    func_name = "macro " + func_name
                elif xtype == "./src:struct/src:decl":
                    func_name = "_" + func_name
                if func_name in drop_set:
                    # if xtype == './/src:type' and node.getparent().tag != '{http://www.srcML.org/srcML/src}unit':
                    #     continue
                    # self.xml.xpath("text()")

                    # ! Macro - functions which return function pointer malformed cus next function to be wrongly
                    # interpretted

                    if node.getprevious() is not None:
                        unattended_text = node.getprevious()
                    else:
                        unattended_text = node.getparent().getprevious()
                    if unattended_text.tail:
                        unattended_text.tail = (
                            unattended_text.tail.rsplit("\n", 1)[0] + "\n"
                        )

                    # noinspection PyBroadException
                    try:
                        if xtype in (
                            "./src:decl_stmt/src:decl",
                            "./src:struct/src:decl",
                            # "./src:enum/src:decl",
                            "./src:typedef/src:function_decl",
                        ):
                            if (
                                node.getparent().getnext() is not None
                                and node.getparent().getnext().tag
                                == "{http://www.srcML.org/srcML/src}empty_stmt"
                            ):
                                # remove extra ;
                                self.xml.remove(node.getparent().getnext())
                            self.xml.remove(node.getparent())
                        elif xtype in ("./src:macro",):
                            next_block = node.getnext()
                            if next_block is not None:
                                if (
                                    next_block.tag
                                    == "{http://www.srcML.org/srcML/src}expr_stmt"
                                ):
                                    continue
                                    # self.xml.remove(next_block)
                                    # next_block = node.getnext()
                                    # if next_block is not None and next_block.tag == '{http://www.srcML.org/srcML/src}return':
                                    #     next_block.text = ""
                                    #     next_block.tail = "\n\n" + next_block.tail.strip().split("\n")[-1]
                                elif (
                                    next_block.tag
                                    == "{http://www.srcML.org/srcML/src}block"
                                ):
                                    self.xml.remove(next_block)
                            self.xml.remove(node)
                        else:
                            self.xml.remove(node)
                    except Exception as _:
                        logger.error(
                            "Node {} not child of unit file {}",
                            func_name,
                            self.xml.base,
                        )

    def trim(self, func, lineno):
        if not lineno:
            return

        rename_nodes = self.nxml("./src:function/src:name[text()='main']")
        for node in rename_nodes:
            # If this executes then a main is going to be fuzzed
            node.text = "original_main"
            logger.warning(
                "Renamed main to original_main at {}",
                node.getparent().getparent().get("filename"),
            )

        for node in self.nxml(".//src:function"):
            func_name = "_" + get_name(node)
            if func_name == func:
                block = node.find("{http://www.srcML.org/srcML/src}block").find(
                    "{http://www.srcML.org/srcML/src}block_content"
                )
                if block is not None:
                    validate_removal(lineno, block, True)

    def save(self, file_src, pretty=True):
        with open(file_src, "wb") as fp:
            fp.write(et.tostring(self.xml, pretty_print=pretty))

    def fix_srcml(self, xml_location):
        # for node in self.nxml("//src:macro/following-sibling::src:expr_stmt/following-sibling::src:return"):
        rename_nodes = self.nxml("./src:unit/src:function/src:name[text()='main']")
        for node in rename_nodes:
            node.text = "original_main"
            logger.warning(
                "Renamed main to original_main at {}",
                node.getparent().getparent().get("filename"),
            )
        # broken_enum_semi = self.nxml("./src:unit/src:enum/src:decl")
        # broken_struct_semi = self.nxml("./src:unit/src:struct/src:decl")
        # affected_children = defaultdict(list)
        # for node in broken_enum_semi+broken_struct_semi:
        #     parent = node.getparent()
        #     for broken_child in node.getparent().getchildren():
        #         if broken_child.tag in ['{http://www.srcML.org/srcML/src}specifier', '{http://www.srcML.org/srcML/src}name']:
        #             continue
        #         elif broken_child.tag in ['{http://www.srcML.org/srcML/src}block']:
        #             broken_child.tail = ";\n\n"
        #         else:
        #             affected_children[parent].append(broken_child)
        # for parent, broken_children in affected_children.items():
        #     # if broken_child in parent.getchildren():
        #     #     parent.remove(broken_child)
        #     parent.getparent().extend(broken_children)
        #     parent.getparent().remove(parent)
        #     # super_parent.remove(parent)
        # filtered_query = [
        #     node
        #     for node in self.nxml("./src:unit/cpp:define/cpp:value")
        #     if node.text and node.text.startswith("(")
        # ]
        # for node in filtered_query:
        #     result = subprocess.run(
        #         [
        #             "srcml",
        #             "--no-xml-declaration",
        #             "--position",
        #             "--language",
        #             "C",
        #             "-t",
        #             repr(node.text),
        #         ],
        #         stderr=subprocess.PIPE,
        #         stdout=subprocess.PIPE,
        #     )
        #     if result.stderr:
        #         logger.warning("Node with content {} replacement failed", node.text)
        #         logger.error(result.stderr.decode())
        #         continue
        #     node_xml = et.fromstring(result.stdout.decode())[0]
        #     logger.info("Node with content {} replaced", node.text)
        #     node.text = ""
        #     node.append(node_xml)
        self.save(xml_location, False)
