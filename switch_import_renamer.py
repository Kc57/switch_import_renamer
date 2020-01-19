# Switch Import switch_import_renamer
# Author: Rob Simon (@_Kc57)

import idaapi

imports = []

def name_exists(name):
    # Return 'True' if name exists in current IDB file.
    for _, existing_names in Names():  # generates (addr, name) tuples
        if name in existing_names:
            return True
    return False

def imp_cb(ea, name, ord):
    if name:
        # This is returning offsets that are +8 bytes more than it should be and I don't know why.
        # So subtracting 8 bytes to address this for now.
        # if ea-8 == 0x71027FEBD0 :
        imports.append((ea-8, name))
    return True

# Get the number of imports
nimps = idaapi.get_import_module_qty()

print "Found %d import(s)..." % nimps

# enumerate imports an add to our list
for i in xrange(0, nimps):
    idaapi.enum_import_names(i, imp_cb)


# This code could just go in imp_cb to avoid another loop
# Loop through the imports and process them
for i in imports:
    ea, name = i

    # Let IDA attempt to get a demangled name
    demangled = idc.Demangle(name, idc.GetLongPrm(idc.INF_LONG_DN))

    if demangled:
        parsedName = demangled

        # demangled name includes the parameters and we don't need that, just get the function name
        if '(' in demangled:
            parsedName = demangled[:demangled.find('(')]

        # handle things like std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>>::assign
        if '<' in demangled:
            parsedName = demangled[:demangled.find('<')]

        # handle destructors like nn::hid::VibrationPlayer::~VibrationPlayer()
        if '~' in demangled:
            parsedName = parsedName.replace('~','') + "_destructor"

        # cleanup
        parsedName = parsedName.replace("::", "_")

    else:
        # if a demangled name was not obtained just use the name from the import table
        parsedName = name

    # I like to prefix my renamed functions so I can search/sort easier
    parsedName = "imp_" + parsedName

    # print the details for each import (use the full demangled name here just for inspection)
    # should add a code comment with the demangled name + parameters later
    print "ea: %08x       name: %s      demangled: %s" % (ea, name, demangled)

    # Find all the code references to the import
    for addr in XrefsTo(ea, flags=0):
        print "  xref type: %s xref addr: %08x" % (XrefTypeName(addr.type), addr.frm)

        # get the containing function referencing the import
        func = idaapi.get_func(addr.frm)
        if func:
            # get the size in bytes of the function
            funcsize = func.endEA - func.startEA

            # The functions that are 16 bytes seem to be jumps to the import.
            # Longer ones may contain additional logic and should not be renamed without manual analysis
            if(funcsize == 16):
                # output some details about the found function
                funcname = GetFunctionName(func.startEA)
                print "     called from %s(0x%x)" % (funcname, addr.frm)
                print "     function starts at %x" % func.startEA
                print "     function ends at %x" % func.endEA
                print "     function size is %d" % funcsize


                defaultName = "sub_%08X" % func.startEA
                print "     defaultName: %s" % defaultName
                # If the function has the default name (sub_address)
                if funcname == defaultName:
                    num = 1
                    tmp = parsedName
                    # The code may have multiple functions that we will rename to the same import
                    # Keep looping until we have a unique function name by appending an underscore and digit
                    while name_exists(tmp):
                        tmp = parsedName + "_%d" % num
                        num = num + 1
                    # Perform the rename using tmp (IDA should replace bad characters in out name like ':' with '_')
                    # but we did some processing ahead of time just in case it doesn't work out
                    idc.MakeNameEx(func.startEA, tmp, idc.SN_NOCHECK | idc.SN_NOWARN)

                    # Make a repeatable comment using the demangled name while we are here
                    idaapi.set_func_cmt(func, demangled, 1)
                    print "     renamed to: %s" % tmp

print "All done..."
