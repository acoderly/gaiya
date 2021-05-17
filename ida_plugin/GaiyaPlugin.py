import idaapi
import idc
import time
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt


class ScrollWidget(QtWidgets.QWidget):

    def __init__(self, parent=None, frame=QtWidgets.QFrame.Box):
        super(ScrollWidget, self).__init__()

        # Container Widget
        widget = QtWidgets.QWidget()
        # Layout of Container Widget
        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        widget.setLayout(self.layout)

        scroll = QtWidgets.QScrollArea()
        scroll.setFrameShape(frame)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        scroll.setWidget(widget)

        scroll_layout = QtWidgets.QVBoxLayout(self)
        scroll_layout.addWidget(scroll)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(scroll_layout)

    def addWidget(self, widget):
        self.layout.addWidget(widget)

    def addLayout(self, layout):
        self.layout.addLayout(layout)


class GaiyaPluginFormClass(PluginForm):
    def __init__(self):
        super(GaiyaPluginFormClass, self).__init__()
        self.parent = None
        self.sig_pattern = """
import idc
import idaapi
import idautils

# func_sig_dump
{FUNC_SIG_DUMP}

# code_sig_dump
{CODE_SIG_DUMP}

def sig_parser(ea_list):
    print("[>>>>>>] sig_parser is called.",[hex(i) for i in ea_list])
    print("[>>>>>>] Function name is:",idc.GetFunctionName(ea_list[0]))

    current_file = idaapi.get_root_filename()
    return False, current_file, None, None


sig = {BEGIN}"name": "{SIG_NAME}",
       "md5": "{FILE_NAME}",
       "date": "{DATE}",
       "code_sig_str": "{CODE_SIG}",
       "code_sig_start_ea": "{CODE_SIG_START_EA}",
       "code_sig_end_ea": "{CODE_SIG_END_EA}",
       "func_sig_str": "{FUNC_SIG}",
       "func_sig_start_ea": "{FUNC_SIG_START_EA}",
       "func_sig_end_ea": "{FUNC_SIG_END_EA}",
       "parser": sig_parser{END}
{HELPER_CODE_STR}
        """
        self.HELPER_CODE_STR = """
####################################################################################################################
####################################################################################################################
####################################################################################################################
g_sigs = [sig, ]
def get_target_func(sig):
    sig_name = sig["name"]
    func_sig = sig["func_sig_str"]
    func_ea = sig["func_sig_start_ea"]
    func_len = len(func_sig.split("_"))
    func_sig = "".join(func_sig.split("_"))
    print("[******] The sig_name:<{}> func_sig:<{}> func_ea:<{}>".format(sig_name, func_sig, func_ea))

    target_func = []
    for func_ea in idautils.Functions():
        flags = idc.GetFunctionFlags(func_ea)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue
        dism_addr = list(idautils.FuncItems(func_ea))
        for idx in range(len(dism_addr)):
            try:
                dis_str = "".join(map(idc.GetMnem, dism_addr[idx:idx + func_len]))
                if dis_str == func_sig:
                    target_func.append(func_ea)
                    break
            except IndexError:
                break

    return target_func


def get_target_code(sig, target_func):
    file_name = idaapi.get_root_filename()
    # logger.info("[>>>>>>] process {} start".format(file_name))
    sig_name = sig["name"]
    code_sig = sig["code_sig_str"]
    code_len = len(code_sig.split("_"))
    code_ea = sig["code_sig_start_ea"]
    code_sig = "".join(code_sig.split("_"))
    print("[******] The sig_name:<{}> code_sig:<{}> code_ea:<{}>".format(sig_name, code_sig, code_ea))
    ret = False
    print("[******] get_target_code param target_func:{}".format(target_func))
    for func_ea in target_func:
        dism_addr = list(idautils.FuncItems(func_ea))
        for idx in range(len(dism_addr)):
            try:
                dism_str = "".join(map(idc.GetMnem, dism_addr[idx:idx + code_len]))
                if dism_str == code_sig:
                    print("[******] get_target_code matched.")
                    parser = sig["parser"]
                    if parser != None:
                        ret, current_file, ip, port = parser(dism_addr[idx:idx + code_len])
                        if ret is not False:
                            print("{}_{}_{}".format(current_file.split(".")[0], ip, port))
                        # TODO How to log the result.
            except IndexError:
                break
    # logger.info("[>>>>>>] process {} end".format(file_name))
    return ret


def parser():
    for sig in g_sigs:
        target_func = get_target_func(sig)
        print("[******] target_func:{}".format(target_func))
        for item in target_func:
            print("[******] target_func_name:{}".format(idc.GetFunctionName(item)))
        ret = get_target_code(sig, target_func)
        # TODO Need log fail stuff.
        if ret is True:
            print("[******] process success.")
        else:
            print("[******] process failed.")


idaapi.autoWait()
parser()
"""

    def OnCreate(self, form):
        """
        Called when the widget is created
        """

        self.form = form
        self.parent = PluginForm.FormToPyQtWidget(form)
        self.populate_form()

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass

    def populate_form(self):
        layout = self.view_configuration_info()
        widget = QtWidgets.QWidget()
        widget.setLayout(layout)
        outer_layout = QtWidgets.QHBoxLayout()
        outer_layout.addWidget(widget)
        self.parent.setLayout(outer_layout)

    def Show(self, caption, options=0):
        options |= PluginForm.WOPN_CENTERED
        super(GaiyaPluginFormClass, self).Show(caption, options)

    def gaiya_layout(self, outer_layout):
        groupbox = QtWidgets.QGroupBox()
        vbox = QtWidgets.QVBoxLayout(groupbox)

        grid_layout = QtWidgets.QGridLayout(groupbox)
        vbox.addLayout(grid_layout)

        self.sig_name_le = QtWidgets.QLineEdit()

        self.func_start_ea_le = QtWidgets.QLineEdit()
        self.func_end_ea_le = QtWidgets.QLineEdit()

        self.code_start_ea_le = QtWidgets.QLineEdit()
        self.code_end_ea_le = QtWidgets.QLineEdit()

        self.output_le = QtWidgets.QTextEdit()

        layout = QtWidgets.QHBoxLayout()
        # self.server_message = QtWidgets.QLabel()
        # layout.addWidget(self.server_message)
        layout.addStretch()
        vbox.addSpacing(20)
        vbox.addLayout(layout)

        grid_layout.addWidget(QtWidgets.QLabel('Sig Name:'), 0, 0)
        grid_layout.addWidget(self.sig_name_le, 0, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Target Function Start EA:'), 1, 0)
        grid_layout.addWidget(self.func_start_ea_le, 1, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Target Function End EA:'), 2, 0)
        grid_layout.addWidget(self.func_end_ea_le, 2, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Target Code Start EA:'), 3, 0)
        grid_layout.addWidget(self.code_start_ea_le, 3, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Target Code End EA:'), 4, 0)
        grid_layout.addWidget(self.code_end_ea_le, 4, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Output:'), 5, 0)
        grid_layout.addWidget(self.output_le, 5, 1)

        grid_layout.setColumnMinimumWidth(0, 75)
        grid_layout.setSpacing(10)
        grid_layout.setContentsMargins(10, 10, 10, 10)

        outer_layout.addWidget(groupbox)

    def view_configuration_info(self):
        container = QtWidgets.QVBoxLayout()

        layout = QtWidgets.QHBoxLayout()
        self.message = QtWidgets.QLabel()
        layout.addWidget(self.message)
        layout.addStretch()
        gen_button = QtWidgets.QPushButton('Gen')
        layout.addWidget(gen_button)
        gen_button.clicked.connect(self.gen_output)

        scroll_layout = ScrollWidget(frame=QtWidgets.QFrame.NoFrame)
        self.gaiya_layout(scroll_layout)
        container.addWidget(scroll_layout)
        container.addLayout(layout)

        return container

    def gen_sig(self):

        self.func_start_ea = self.func_start_ea_le.text()
        self.func_end_ea = self.func_end_ea_le.text()
        self.code_start_ea = self.code_start_ea_le.text()
        self.code_end_ea = self.code_end_ea_le.text()
        res = "func_start_ea:{}\nfunc_end_ea:{}\ncode_start_ea:{}\ncode_end_ea:{}\n".format(
            self.func_start_ea, self.func_end_ea, self.code_start_ea, self.code_end_ea
        )
        print("gen_sig button is clicked {}".format(res))
        self.output_le.setText(res)

    def get_sig(self, start_ea, end_ea):
        ea = start_ea
        end = end_ea
        sig = []
        while ea < end:
            sig.append(idc.GetMnem(ea))
            ea = ea + idc.get_item_size(ea)
        return "_".join(sig)

    def get_disasm(self, start_ea, end_ea):
        ea = start_ea
        end = end_ea
        dis = []
        while ea < end:
            dis.append(idc.GetDisasm(ea))
            ea = ea + idc.get_item_size(ea)
        tmp = []
        for idx in range(0, len(dis)):
            item = "# {} {}".format(idx, dis[idx])
            tmp.append(item)
        return "\n".join(tmp)

    def gen_output(self):
        self.sig_name = self.sig_name_le.text()
        self.func_start_ea = int(self.func_start_ea_le.text(), base=16)
        self.func_end_ea = int(self.func_end_ea_le.text(), base=16)
        self.code_start_ea = int(self.code_start_ea_le.text(), base=16)
        self.code_end_ea = int(self.code_end_ea_le.text(), base=16)
        self.output = self.sig_pattern.format(BEGIN="{",
                                              FUNC_SIG_DUMP=self.get_disasm(self.func_start_ea,
                                                                            self.func_end_ea),
                                              CODE_SIG_DUMP=self.get_disasm(self.code_start_ea,
                                                                            self.code_end_ea),
                                              SIG_NAME=self.sig_name + "_" + time.strftime('%Y-%m-%d_%H',
                                                                                           time.localtime(time.time())),
                                              FILE_NAME=idaapi.get_root_filename(),
                                              DATE=time.strftime('%Y-%m-%d_%H:%M:%S', time.localtime(time.time())),
                                              CODE_SIG=self.get_sig(self.code_start_ea, self.code_end_ea),
                                              CODE_SIG_START_EA=hex(self.code_start_ea),
                                              CODE_SIG_END_EA=hex(self.code_end_ea),
                                              FUNC_SIG=self.get_sig(self.func_start_ea, self.func_end_ea),
                                              FUNC_SIG_START_EA=hex(self.func_start_ea),
                                              FUNC_SIG_END_EA=hex(self.func_end_ea),
                                              END="}",
                                              HELPER_CODE_STR=self.HELPER_CODE_STR)
        self.output_le.setText(self.output)


try:
    class Gen_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET


    class Gen(Gen_Menu_Context):
        def activate(self, ctx):
            self.plugin.run()
            return 1
except:
    pass

p_initialized = False


class gaiyasigen_t(idaapi.plugin_t):  # pragma: no cover
    comment = ""
    help = "todo"
    wanted_name = "GaiyaSigGen"
    wanted_hotkey = "Ctrl-Alt-G"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Gen.register(self, "GaiyaSigGen")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "GaiyaSigGen",
                "Gaiya sig generator",
                Gen(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Gen", "GaiyaSigGen", idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        plg = GaiyaPluginFormClass()
        plg.Show("Gaiya Sig Generator")


def PLUGIN_ENTRY():  # pragma: no cover
    return gaiyasigen_t()
# /Applications/IDAPro7.0/ida64.app/Contents/MacOS/plugins/GaiyaPlugin.py
# /Applications/IDAPro7.0/ida.app/Contents/MacOS/plugins/GaiyaPlugin.py
