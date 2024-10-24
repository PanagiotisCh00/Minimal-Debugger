# Minimal Debugger
Project Overview

The Mini Debugger (mdb) is a lightweight debugger designed in C for debugging ELF programs on Linux-based operating systems. This tool allows users to load and execute ELF binaries, set multiple software breakpoints, and inspect running code. It provides essential debugging functionality, enabling a smooth debugging experience with minimal overhead.
Features

    ELF Binary Loading: mdb loads and prepares an ELF executable for execution, supporting Linux-based systems.
    Breakpoint Management: Users can add, list, and delete multiple software breakpoints using either symbols or hexadecimal addresses.
    Program Execution Control: mdb allows users to run the program until a breakpoint is hit or the program exits. It also supports continuing the execution after a breakpoint.
    Disassembly Output: When a breakpoint is hit, mdb provides a disassembly of the current instruction and the next 10 instructions or until the function ends.

Supported Commands

    Load ELF Binary:
        Command: mdb <path_to_binary>
        Loads an ELF executable for debugging.

    Set Breakpoints (b):
        Command: b <symbol> or b *<hex_address>
        Adds a software breakpoint at the specified symbol or address.

    List Breakpoints (l):
        Command: l
        Lists all currently enabled breakpoints.

    Delete Breakpoints (d):
        Command: d <breakpoint_number>
        Deletes the specified breakpoint from the list.

    Run Program (r):
        Command: r
        Runs the program until a breakpoint is hit or the program exits. On hitting a breakpoint, mdb disassembles and prints the current instruction and the following 10 instructions (or until the function ends).

    Continue Program (c):
        Command: c
        Continues execution from the current breakpoint.

Bonus Features (Optional)

    Single-Step Instruction (si):
        Command: si
        Executes a single instruction when the program is stopped.
    Disassemble Current Instruction (disas):
        Command: disas
        Disassembles and prints the current instruction and the next 10 instructions (or until the function ends).

This project was developed as part of the Software Analysis course (EPL451) at the University of Cyprus, under the supervision of Prof. Elias Athanasopoulos.
