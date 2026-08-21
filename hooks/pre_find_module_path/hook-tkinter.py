def pre_find_module_path(hook_api):
    # The bundled build runtime can create Tk windows, but PyInstaller's Tcl()
    # probe rejects its layout. Keep normal module discovery and package the
    # known-good Tcl/Tk directories explicitly in the project spec.
    return None
