import os
import json
import subprocess
import re  # 💡 引入正则表达式模块

# ================= 配置区 =================
# 🎯 你的 JSON 文件路径
JSON_FILE = "/home/lhw/codetran/test/humaneval_decompile.json"  

# 🎯 交叉编译工具
CC = "aarch64-linux-gnu-gcc"

# 🎯 根输出目录（存放编译出的 .c 和 .elf 文件）
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

        # 根据不同的优化级别动态创建子文件夹
        output_dir = os.path.join(base_output_dir, opt_type)
        os.makedirs(output_dir, exist_ok=True)

        base_name = f"task_{task_id}_{opt_type}"
        output_c_filepath = os.path.join(output_dir, f"{base_name}.c")
        output_elf_filepath = os.path.join(output_dir, f"{base_name}.elf")
        
        # 如果 .elf 文件已存在可以跳过
        if os.path.exists(output_elf_filepath):
            print(f"[{base_name}] ⏭️ .elf 文件已经存在，跳过...")
            skip_count += 1
            continue

        print(f"[{base_name}] 正在编译 (优化级别: {opt_type})...")

        # ---------------------------------------------------------
        # 💡 修改逻辑：使用正则表达式精准匹配 main 函数
        # 避免被带有 main 的变量名（如 remaining, domain）误导
        # \bmain\s*\( 匹配：单词边界的 main，后跟0或多个空格，接着是左括号 (
        # ---------------------------------------------------------
        c_test = item.get("c_test", "")
        
        if not re.search(r'\bmain\s*\(', c_func):
            if c_test and re.search(r'\bmain\s*\(', c_test):
                cleaned_lines = []
                for line in c_test.split('\n'):
                    # 如果行中包含 assert 关键字，则将其注释掉以避免断言报错
                    if 'assert' in line:
                        cleaned_lines.append('    // [已去除断言] ' + line.lstrip())
                    else:
                        cleaned_lines.append(line)
                
                c_func += "\n\n/* --- 自动注入配套 main 函数 (提取自 c_test) --- */\n"
                c_func += "\n".join(cleaned_lines)
            else:
                # 如果没有提供 c_test 兜底，依然使用 dummy main
                c_func += "\n\n/* 自动注入 dummy main 函数以通过链接阶段 */\nint main() {\n    return 0;\n}\n"

        # 将 JSON 中的原生代码提取并写入 .c 文件供排查
        try:
            with open(output_c_filepath, "w", encoding='utf-8') as f_out:
                f_out.write(c_func)
        except Exception as e:
            print(f"[{base_name}] ❌ 写入 .c 文件失败: {e}")
            fail_count += 1
            continue

        # 动态设置优化 flag
        opt_flag = f"-{opt_type}" if opt_type.startswith("O") else "-O0"
        
        # 编译为 ELF 文件
        # 💡 新增了 "-lm" 参数，用来链接标准数学库，修复了 O0 时找不到 ceil/floor 的问题
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