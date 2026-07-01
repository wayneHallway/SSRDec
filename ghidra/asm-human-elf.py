import os
import json
import subprocess
import re  # Regular-expression support.

# ================= Configuration =================
# Path to the input JSON file.
JSON_FILE = "/home/lhw/codetran/test/humaneval_decompile.json"  

# Cross-compilation toolchain.
CC = "aarch64-linux-gnu-gcc"

# Root output directory for generated .c and .elf files.
base_output_dir = os.path.abspath("compiled-elf-files")
# ==========================================

def compile_json_to_elf_files():
    if not os.path.exists(JSON_FILE):
        print(f"❌ 错误: 找不到文件 {JSON_FILE}")
        return

    try:
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ 错误: 读取或解析 JSON 文件失败: {e}")
        return

    print(f"📥 成功加载 {len(data)} 个任务，准备进行批量编译 (C -> .elf)...\n")

    success_count = 0
    fail_count = 0
    skip_count = 0

    for idx, item in enumerate(data):
        task_id = item.get("task_id", idx)
        opt_type = item.get("type", "Unknown") 
        c_func = item.get("c_func", "")

        if not c_func:
            print(f"[task_{task_id}] ⚠️ 警告: c_func 为空，跳过...")
            skip_count += 1
            continue

        # Create a subdirectory for each optimization level.
        output_dir = os.path.join(base_output_dir, opt_type)
        os.makedirs(output_dir, exist_ok=True)

        base_name = f"task_{task_id}_{opt_type}"
        output_c_filepath = os.path.join(output_dir, f"{base_name}.c")
        output_elf_filepath = os.path.join(output_dir, f"{base_name}.elf")
        
        # Skip the task if its .elf file already exists.
        if os.path.exists(output_elf_filepath):
            print(f"[{base_name}] ⏭️ .elf 文件已经存在，跳过...")
            skip_count += 1
            continue

        print(f"[{base_name}] 正在编译 (优化级别: {opt_type})...")

        # ---------------------------------------------------------
        # Use a regular expression to match the main function precisely.
        # This avoids matching identifiers that merely contain "main", such as remaining or domain.
        # \bmain\s*\( matches main at a word boundary, optional whitespace, and an opening parenthesis.
        # ---------------------------------------------------------
        c_test = item.get("c_test", "")
        
        if not re.search(r'\bmain\s*\(', c_func):
            if c_test and re.search(r'\bmain\s*\(', c_test):
                cleaned_lines = []
                for line in c_test.split('\n'):
                    # Comment out lines containing assert to prevent assertion failures.
                    if 'assert' in line:
                        cleaned_lines.append('    // [assertion removed] ' + line.lstrip())
                    else:
                        cleaned_lines.append(line)
                
                c_func += "\n\n/* --- Injected matching main function (extracted from c_test) --- */\n"
                c_func += "\n".join(cleaned_lines)
            else:
                # Fall back to a dummy main when c_test is unavailable.
                c_func += "\n\n/* Injected dummy main function for the linking stage. */\nint main() {\n    return 0;\n}\n"

        # Extract the original code from JSON and save it as a .c file for inspection.
        try:
            with open(output_c_filepath, "w", encoding='utf-8') as f_out:
                f_out.write(c_func)
        except Exception as e:
            print(f"[{base_name}] ❌ 写入 .c 文件失败: {e}")
            fail_count += 1
            continue

        # Select the optimization flag dynamically.
        opt_flag = f"-{opt_type}" if opt_type.startswith("O") else "-O0"
        
        # Compile the source into an ELF file.
        # Link libm with "-lm" so ceil/floor resolve correctly at O0.
        compile_cmd = [CC, output_c_filepath, "-o", output_elf_filepath, opt_flag, "-w", "-g", "-lm"]
        
        try:
            comp_res = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=10)
            if comp_res.returncode != 0:
                print(f"[{base_name}] ❌ 编译失败: {comp_res.stderr.strip()}")
                fail_count += 1
            else:
                print(f"  -> [成功] 生成: {output_elf_filepath}")
                success_count += 1
        except subprocess.TimeoutExpired:
            print(f"[{base_name}] ❌ 编译超时 (>10s)")
            fail_count += 1
        except Exception as e:
            print(f"[{base_name}] ❌ 编译异常: {e}")
            fail_count += 1

    print("\n" + "="*50)
    print("✅ 批量编译任务结束！")
    print(f"总计处理: {len(data)} 个任务")
    print(f"成功: {success_count}")
    print(f"失败: {fail_count}")
    print(f"跳过: {skip_count}")
    print(f"输出目录: {base_output_dir}")
    print("="*50)

if __name__ == "__main__":
    compile_json_to_elf_files()
