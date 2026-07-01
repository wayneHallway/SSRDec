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
        print(f"❌ Error: file not found: {JSON_FILE}")
        return

    try:
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error: failed to read or parse the JSON file: {e}")
        return

    print(f"📥 Loaded {len(data)} tasks; starting batch compilation (C -> .elf)...\n")

    success_count = 0
    fail_count = 0
    skip_count = 0

    for idx, item in enumerate(data):
        task_id = item.get("task_id", idx)
        opt_type = item.get("type", "Unknown") 
        c_func = item.get("c_func", "")

        if not c_func:
            print(f"[task_{task_id}] ⚠️ Warning: c_func is empty; skipping...")
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
            print(f"[{base_name}] ⏭️ The .elf file already exists; skipping...")
            skip_count += 1
            continue

        print(f"[{base_name}] Compiling (optimization level: {opt_type})...")

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
            print(f"[{base_name}] ❌ Failed to write the .c file: {e}")
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
                print(f"[{base_name}] ❌ Compilation failed: {comp_res.stderr.strip()}")
                fail_count += 1
            else:
                print(f"  -> [success] Generated: {output_elf_filepath}")
                success_count += 1
        except subprocess.TimeoutExpired:
            print(f"[{base_name}] ❌ Compilation timed out (>10s)")
            fail_count += 1
        except Exception as e:
            print(f"[{base_name}] ❌ Compilation exception: {e}")
            fail_count += 1

    print("\n" + "="*50)
    print("✅ Batch compilation complete!")
    print(f"Tasks processed: {len(data)}")
    print(f"Succeeded: {success_count}")
    print(f"Failed: {fail_count}")
    print(f"Skipped: {skip_count}")
    print(f"Output directory: {base_output_dir}")
    print("="*50)

if __name__ == "__main__":
    compile_json_to_elf_files()
