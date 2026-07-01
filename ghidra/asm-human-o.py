import os
import json
import subprocess

# ================= Configuration =================
JSON_FILE = "/home/lhw/codetran/test/humaneval_decompile.json"  # Path to the input JSON file.

# Cross-compilation toolchain.
CC = "aarch64-linux-gnu-gcc"

# Root output directory dedicated to generated .c and .o files.
base_output_dir = os.path.abspath("compiled-o-files")
# ==========================================

def compile_json_to_o_files():
    if not os.path.exists(JSON_FILE):
        print(f"❌ 错误: 找不到文件 {JSON_FILE}")
        return

    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"📥 成功加载 {len(data)} 个任务，准备进行批量编译 (C -> .o)...\n")

    for idx, item in enumerate(data):
        task_id = item.get("task_id", idx)
        opt_type = item.get("type", "Unknown") 
        c_func = item.get("c_func", "")

        if not c_func:
            continue

        # Create a subdirectory for each optimization level.
        output_dir = os.path.join(base_output_dir, opt_type)
        os.makedirs(output_dir, exist_ok=True)

        base_name = f"task_{task_id}_{opt_type}"
        output_c_filepath = os.path.join(output_dir, f"{base_name}.c")
        output_o_filepath = os.path.join(output_dir, f"{base_name}.o")
        
        # Skip the task if its .o file already exists.
        if os.path.exists(output_o_filepath):
            print(f"[{base_name}] ⏭️ .o 文件已经存在，跳过...")
            continue

        print(f"[{base_name}] 正在编译 (优化级别: {opt_type})...")

        # Extract the original code from JSON and save it as a .c file for inspection.
        with open(output_c_filepath, "w", encoding='utf-8') as f_out:
            f_out.write(c_func)

        # Compile dynamically with GCC into a .o file, including -g debug information.
        opt_flag = f"-{opt_type}" if opt_type.startswith("O") else "-O0"
        compile_cmd = [CC, "-c", output_c_filepath, "-o", output_o_filepath, opt_flag, "-w", "-g"]
        
        try:
            comp_res = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=10)
            if comp_res.returncode != 0:
                print(f"[{base_name}] ❌ 编译失败: {comp_res.stderr.strip()}")
            else:
                print(f"  -> [成功] 生成: {output_o_filepath}")
        except Exception as e:
            print(f"[{base_name}] ❌ 编译异常: {e}")

    print("\n" + "="*50)
    print("✅ 所有 C 代码已成功编译为 .o 文件！")

if __name__ == "__main__":
    compile_json_to_o_files()
