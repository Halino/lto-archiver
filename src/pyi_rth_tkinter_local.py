import os
import sys


if getattr(sys, "frozen", False):
    bundle = getattr(sys, "_MEIPASS")
    os.environ["TCL_LIBRARY"] = os.path.join(bundle, "_tcl_data")
    os.environ["TK_LIBRARY"] = os.path.join(bundle, "_tk_data")
