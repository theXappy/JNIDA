import ida_bytes
import idaapi
import ida_kernwin
import ida_name
import ida_typeinf
import re

class JNINativeMethodSignature:
    __tokens = [
        ('ARGS_START', r'\('),
        ('STRING', r'Ljava.lang.String;'),
        ('CLASS', r'Ljava.lang.Class;'),
        ('THROWABLE', r'Ljava.lang.Throwable;'),
        ('OBJECT', r'L([^;]+);'),
        ('OBJECT_ARRAY', r'\[L([^;]+);'),
        ('VOID', r'V'),
        ('BOOLEAN', r'Z'),
        ('BYTE', r'B'),
        ('CHAR', r'C'),
        ('SHORT', r'S'),
        ('INTEGER', r'I'),
        ('LONG', r'J'),
        ('FLOAT', r'F'),
        ('DOUBLE', r'D'),
        ('BOOLEAN_ARRAY', r'\[Z'),
        ('BYTE_ARRAY', r'\[B'),
        ('CHAR_ARRAY', r'\[C'),
        ('SHORT_ARRAY', r'\[S'),
        ('INTEGER_ARRAY', r'\[I'),
        ('LONG_ARRAY', r'\[J'),
        ('FLOAT_ARRAY', r'\[F'),
        ('DOUBLE_ARRAY', r'\[D'),
        ('ARGS_END', r'\)'),
        ('MISMATCH', r'.'),
    ]

    __regex = '|'.join('(?P<%s>%s)' % pair for pair in __tokens)

    __mapping = {
        'OBJECT': 'jobject',
        'CLASS': 'jclass',
        'STRING': 'jstring',
        'THROWABLE': 'jthrowable',
        'VOID': 'void',
        'BOOLEAN': 'jboolean',
        'BYTE': 'jbyte',
        'CHAR': 'jchar',
        'SHORT': 'jshort',
        'INTEGER': 'jint',
        'LONG': 'jlong',
        'FLOAT': 'jfloat',
        'DOUBLE': 'jdouble',
        'OBJECT_ARRAY': 'jobjectArray',
        'BOOLEAN_ARRAY': 'jbooleanArray',
        'BYTE_ARRAY': 'jbyteArray',
        'CHAR_ARRAY': 'jcharArray',
        'SHORT_ARRAY': 'jshortArray',
        'INTEGER_ARRAY': 'jintArray',
        'LONG_ARRAY': 'jlongArray',
        'FLOAT_ARRAY': 'jfloatArray',
        'DOUBLE_ARRAY': 'jdoubleArray',
    }

    def __init__(self, name, signature):
        self.name = name
        self.signature = signature
        if isinstance(self.signature, bytes):
            self.signature = self.signature.decode()
        self.c = self.__parse()
        pass

    def __parse(self):
        args = ["JNIEnv* env", "jobject thiz"]
        ret = 'VOID'
        args_end = False
        index = 0
        for matches in re.finditer(self.__regex, self.signature):
            kind = matches.lastgroup
            if args_end:
                ret = self.__mapping[kind]
                continue
            if kind == 'ARGS_START':
                continue
            if kind == 'ARGS_END':
                args_end = True
                continue
            if kind == 'MISMATCH':
                raise JNINativeMethodError()
            args.append(self.__mapping[kind] + (' a%i' % index))
            index += 1
        return "%s %s(%s);" % (ret, self.name, ', '.join(args))


class JNINativeMethodError(Exception):
    pass













class JNINativeMethodHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        selection = idaapi.read_range_selection(None)
        if not selection[0]:
            return 0

        start = selection[1] - 1
        stop = selection[2] + 1

        print('Parsing selection between %X -> %X' % (start, stop))

        prefix = ida_kernwin.ask_str('', 0, 'Prefix')

        if prefix is not None:
            prefix = prefix.replace('/', '::')

        while True:
            name_address = ida_bytes.next_head(start, stop)

            if name_address == idaapi.BADADDR:
                break

            name_offset = ida_bytes.get_dword(name_address)

            name = ida_bytes.get_strlit_contents(name_offset, -1, 0)

            if isinstance(name, bytes):
                name = name.decode()

            if prefix is not None:
                name = prefix + '::' + name

            signature_address = ida_bytes.next_head(name_address, stop)

            if signature_address == idaapi.BADADDR:
                break

            signature_offset = ida_bytes.get_dword(signature_address)

            signature = ida_bytes.get_strlit_contents(signature_offset, -1, 0)

            function_address = ida_bytes.next_head(signature_address, stop)

            if function_address == idaapi.BADADDR:
                break

            function_offset = ida_bytes.get_dword(function_address)

            if function_offset % 2 != 0:
                function_offset -= 1

            try:
                c_signature = JNINativeMethodSignature(name, signature).c
            except JNINativeMethodError:
                break

            start = function_address

            parsed_decl = ida_typeinf.idc_parse_decl(None, c_signature, ida_typeinf.PT_SIL)

            if parsed_decl is None:
                return 0

            ida_typeinf.apply_type(None, parsed_decl[1], parsed_decl[2], function_offset, 1)

            ida_name.set_name(function_offset, name, ida_name.SN_FORCE)

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def init():
    action_desc = idaapi.action_desc_t(
        'jni_native_method:rename',
        'Rename JNI native methods',
        JNINativeMethodHandler(),
        'Ctrl+/',
        'Rename JNI native methods',
        199
    )

    idaapi.register_action(action_desc)

    idaapi.attach_action_to_menu(
        'Edit/Other/Manual instruction...',
        'jni_native_method:rename',
        idaapi.SETMENU_APP
    )


def fini():
    idaapi.detach_action_from_menu(
        'Edit/Other/Manual instruction...',
        'jni_native_method:rename'
    )

    idaapi.unregister_action('jni_native_method:rename')
