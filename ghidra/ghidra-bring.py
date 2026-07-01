import os
import tempfile
import subprocess

timeout_duration = 60 # 建议适当调大，Ghidra 启动和分析较慢

# --- 配置路径与参数 ---
# 请确保以下路径正确
ghidra_path = os.path.abspath("/home/lhw/ghidra_12.0.3_PUBLIC/support/analyzeHeadless")
postscript = os.path.abspath("./decompile.py") 
project_name = "tmp_ghidra_proj"

# 🎯 【修改点 1】修改为包含所有优化级别文件夹的父目录 (根据截图，修改为 build_outputs)
# 如果 build_outputs 不在当前运行目录下，请使用绝对路径，例如 "/path/to/build_outputs"
base_root_folder = os.path.abspath("/home/lhw/codetran/1/build_outputs") 

# 🎯 【修改点 2】设为 None 即可扫描并反编译全部优化级别子文件夹 (O1, O2, O3 等)
target_opt_level = "O1" 

# 🎯 基础输出目录
base_output_dir = os.path.abspath("dec-bring")
os.makedirs(base_output_dir, exist_ok=True)

print(f"开始扫描基础目录: {base_root_folder}")
if target_opt_level:
    print(f"🎯 过滤模式：仅处理优化级别 [{target_opt_level}] 的文件")
else:
    print("🎯 全量模式：处理所有优化级别的文件")

# 使用 os.walk 遍历所有子目录
for dirpath, dirnames, filenames in os.walk(base_root_folder):
    for filename in filenames:
        if filename.endswith(".o"):
            target_o_file = os.path.join(dirpath, filename)
            base_name = os.path.splitext(filename)[0]
            
            # 动态获取优化级别并创建对应输出目录
            # 获取当前文件所在目录相对于基础根目录的相对路径 (例如 'O1', 'O2/subfolder')
            rel_path = os.path.relpath(dirpath, base_root_folder)
            
            # 提取第一级目录名作为优化级别标识 (例如 'O1', 'O2', 'O3')
            opt_level = rel_path.split(os.sep)[0]
            
            # 如果 .o 文件直接存放在 base_root_folder 根目录下，rel_path 会是 '.'
            if opt_level == '.':
                opt_level = 'default_level'
                
            # 检查当前文件是否属于指定的优化级别 (如果 target_opt_level 为 None 则跳过此检查)
            if target_opt_level and opt_level != target_opt_level:
                continue
                
            # 拼接并创建对应优化级别的输出文件夹 (例如 dec-human/O1)
            current_output_dir = os.path.join(base_output_dir, opt_level)
            os.makedirs(current_output_dir, exist_ok=True)
            
            print("\n" + "="*50)
            print(f"[{opt_level}][{base_name}] 正在准备使用 Ghidra 分析文件: {target_o_file}...")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                output_path = os.path.join(temp_dir, "decompiled_output.c")
                
                # 调用 Ghidra Headless 分析器
                command = [
                    ghidra_path,
                    temp_dir,
                    project_name,
                    "-import", target_o_file,
                    "-scriptPath", os.path.dirname(postscript), 
                    "-postScript", os.path.basename(postscript), output_path, 
                    "-deleteProject",  
                ]
                
                print(f"[{opt_level}][{base_name}] 正在使用 Ghidra 进行反编译...")
                try:
                    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout_duration)
                except subprocess.TimeoutExpired:
                    print(f"[{opt_level}][{base_name}] ❌ Ghidra 分析超时 (超过 {timeout_duration} 秒)！跳过此文件。")
                    continue
                except Exception as e:
                    print(f"[{opt_level}][{base_name}] ❌ 运行 Ghidra 时发生错误: {e}")
                    continue
                
                # 检查文件是否生成
                if not os.path.exists(output_path):
                    print(f"[{opt_level}][{base_name}] ❌ Ghidra 未能成功生成反编译文件！跳过此文件。")
                    continue
                
                # 解析并提取所有函数的反编译结果
                try:
                    with open(output_path, 'r', encoding='utf-8') as f:
                        c_decompile = f.read()
                        
                    functions_dict = {}
                    current_func = None
                    
                    # 逐行解析，利用 '// Function:' 分割识别出所有的函数
                    for line in c_decompile.split('\n'):
                        if '// Function:' in line:
                            parts = line.split('// Function:')
                            if len(parts) > 1:
                                func_name = parts[1].strip().split()[0]
                                current_func = func_name
                                functions_dict[current_func] = [line]
                        elif current_func is not None:
                            functions_dict[current_func].append(line)
                            
                    if not functions_dict:
                        print(f"[{opt_level}][{base_name}] ⚠️ 未找到任何函数，请检查该 .o 文件或 decompile.py 输出格式。跳过此文件。")
                        continue
                        
                    print(f"[{opt_level}][{base_name}] 🎯 发现 {len(functions_dict)} 个函数，正在提取并保存...")
                    
                    # 将文件保存到对应优化级别的文件夹内
                    output_c_filepath = os.path.join(current_output_dir, f"{base_name}_ghidra.c")
                    
                    with open(output_c_filepath, 'w', encoding='utf-8') as f_out:
                        # 遍历并写入每一个提取出的函数
                        for func_name, c_func_lines in functions_dict.items():
                            # 移除前面的无关注释信息，定位到具体的函数体签名
                            start_idx = 0
                            for idx_tmp in range(1, len(c_func_lines)):
                                if func_name in c_func_lines[idx_tmp]:
                                    start_idx = idx_tmp
                                    break
                            c_func_lines = c_func_lines[start_idx:]
                            
                            # 生成纯净的反编译代码字符串
                            pure_decompiled_code = '\n'.join(c_func_lines).strip()

                            if pure_decompiled_code:
                                # 写入函数并在函数之间添加分隔符和空行
                                f_out.write(f"// --- Function: {func_name} ---\n")
                                f_out.write(pure_decompiled_code)
                                f_out.write("\n\n")
                                
                    print(f"  -> [成功] 已保存至: {output_c_filepath}")
                    
                except Exception as e:
                    print(f"[{opt_level}][{base_name}] ❌ 处理反编译结果时发生未知错误: {e}")

print("\n" + "="*50)
print("✅ 所有 .o 文件批量处理完成！")