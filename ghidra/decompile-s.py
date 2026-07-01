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

# 获取当前程序的清单(Listing)，包含了所有的汇编指令
listing = currentProgram.getListing()

# 获取当前程序的所有函数
functions = currentProgram.getFunctionManager().getFunctions(True)

print("Current Python version: " + str(sys.version.decode()))

# 遍历所有函数并提取其内部的汇编指令
with open(args[0], "w") as output_file:
    for function in list(functions):
        # 写入函数头标记 (兼容你的外层解析逻辑)
        output_file.write("// Function: " + function.getName() + "\n")
        
        # 获取属于该函数体(Body)范围内的所有指令
        instructions = listing.getInstructions(function.getBody(), True)
        
        for instr in instructions:
            # 提取指令的内存地址 (例如: 00010204)
            address = instr.getMinAddress().toString()
            # 提取完整的汇编文本 (例如: addi sp,sp,-0x10)
            asm_text = instr.toString()
            
            # 格式化输出:   地址: 汇编代码
            output_file.write("    " + address + ": " + asm_text + "\n")
            
        output_file.write("\n")