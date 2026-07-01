# @runtime Jython
#!/usr/bin/env python2
# -*- coding:utf-8 -*-

"""
Python Script used to communicate with Ghidra's API.
It will extract the ASSEMBLY instructions of all functions of a defined binary and
save results into the specified output file.
"""

import sys
import __main__ as ghidra_app
args = ghidra_app.getScriptArgs()

# Get the current program listing, which contains all assembly instructions.
listing = currentProgram.getListing()

# Get every function in the current program.
functions = currentProgram.getFunctionManager().getFunctions(True)

print("Current Python version: " + str(sys.version.decode()))

# Iterate over all functions and extract their assembly instructions.
with open(args[0], "w") as output_file:
    for function in list(functions):
        # Write a function header marker compatible with the outer parser.
        output_file.write("// Function: " + function.getName() + "\n")
        
        # Get all instructions within the function body.
        instructions = listing.getInstructions(function.getBody(), True)
        
        for instr in instructions:
            # Extract the instruction address, for example: 00010204.
            address = instr.getMinAddress().toString()
            # Extract the complete assembly text, for example: addi sp,sp,-0x10.
            asm_text = instr.toString()
            
            # Format the output as: address: assembly instruction.
            output_file.write("    " + address + ": " + asm_text + "\n")
            
        output_file.write("\n")
