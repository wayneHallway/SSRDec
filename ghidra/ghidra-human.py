import os
import tempfile
import subprocess

timeout_duration = 60 # Increase if needed because Ghidra startup and analysis can be slow.

# --- Paths and options ---
ghidra_path = os.path.abspath("/home/lhw/ghidra_12.0.3_PUBLIC/support/analyzeHeadless")
postscript = os.path.abspath("./decompile.py") 
project_name = "tmp_ghidra_proj"

# Set this to the parent directory that contains every optimization-level folder.
base_root_folder = os.path.abspath("/home/lhw/codetran/ghidra/compiled-elf-files")

# Select one optimization level to scan, or use None to scan all levels.
target_opt_level = "O3"  # Change to O1, O2, O3, and so on, or use None to scan everything.

# Base output directory.
base_output_dir = os.path.abspath("dec-human")
os.makedirs(base_output_dir, exist_ok=True)

print(f"Scanning base directory: {base_root_folder}")
if target_opt_level:
    print(f"🎯 Filter mode: processing optimization level [{target_opt_level}] only")

# Traverse every subdirectory with os.walk.
for dirpath, dirnames, filenames in os.walk(base_root_folder):
    for filename in filenames:
        if filename.endswith(".elf"):
            target_o_file = os.path.join(dirpath, filename)
            base_name = os.path.splitext(filename)[0]
            
            # Determine the optimization level and create its output directory dynamically.
            # Get the file's parent path relative to the base root, for example 'O0' or 'O2/subfolder'.
            rel_path = os.path.relpath(dirpath, base_root_folder)
            
            # Use the first path component as the optimization-level label, for example O0.
            opt_level = rel_path.split(os.sep)[0]
            
            # rel_path is '.' when a .o file is stored directly in base_root_folder.
            if opt_level == '.':
                opt_level = 'default_level'
                
            # Check whether the file belongs to the requested optimization level.
            if target_opt_level and opt_level != target_opt_level:
                continue
                
            # Build and create the matching output directory, for example decompile-human/O0.
            current_output_dir = os.path.join(base_output_dir, opt_level)
            os.makedirs(current_output_dir, exist_ok=True)
            
            print("\n" + "="*50)
            print(f"[{opt_level}][{base_name}] Preparing Ghidra analysis: {target_o_file}...")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                output_path = os.path.join(temp_dir, "decompiled_output.c")
                
                # Invoke the Ghidra headless analyzer.
                command = [
                    ghidra_path,
                    temp_dir,
                    project_name,
                    "-import", target_o_file,
                    "-scriptPath", os.path.dirname(postscript), 
                    "-postScript", os.path.basename(postscript), output_path, 
                    "-deleteProject",  
                ]
                
                print(f"[{opt_level}][{base_name}] Decompiling with Ghidra...")
                try:
                    # Apply a timeout so the subprocess cannot hang indefinitely.
                    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout_duration)
                except subprocess.TimeoutExpired:
                    print(
                        f"[{opt_level}][{base_name}] ❌ Ghidra analysis timed out "
                        f"after {timeout_duration} seconds; skipping this file."
                    )
                    continue
                except Exception as e:
                    print(f"[{opt_level}][{base_name}] ❌ Error while running Ghidra: {e}")
                    continue
                
                # Verify that the output file was generated.
                if not os.path.exists(output_path):
                    print(
                        f"[{opt_level}][{base_name}] ❌ Ghidra did not generate a "
                        "decompiled file; skipping this input."
                    )
                    continue
                
                # Parse and extract the decompiled output for every function.
                try:
                    with open(output_path, 'r', encoding='utf-8') as f:
                        c_decompile = f.read()
                        
                    functions_dict = {}
                    current_func = None
                    
                    # Parse line by line and split functions at '// Function:' markers.
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
                        print(
                            f"[{opt_level}][{base_name}] ⚠️ No functions found. "
                            "Check the .o file and decompile.py output format; "
                            "skipping this input."
                        )
                        continue
                        
                    print(
                        f"[{opt_level}][{base_name}] 🎯 Found {len(functions_dict)} "
                        "function(s); extracting and saving..."
                    )
                    
                    # Save the file in the matching optimization-level directory.
                    output_c_filepath = os.path.join(current_output_dir, f"{base_name}_ghidra.c")
                    
                    with open(output_c_filepath, 'w', encoding='utf-8') as f_out:
                        # Iterate over and write each extracted function.
                        for func_name, c_func_lines in functions_dict.items():
                            # Remove leading metadata comments and locate the function signature.
                            start_idx = 0
                            for idx_tmp in range(1, len(c_func_lines)):
                                if func_name in c_func_lines[idx_tmp]:
                                    start_idx = idx_tmp
                                    break
                            c_func_lines = c_func_lines[start_idx:]
                            
                            # Build a clean decompiled-code string.
                            pure_decompiled_code = '\n'.join(c_func_lines).strip()

                            if pure_decompiled_code:
                                # Write the function with separators and blank lines between functions.
                                f_out.write(f"// --- Function: {func_name} ---\n")
                                f_out.write(pure_decompiled_code)
                                f_out.write("\n\n")
                                
                    print(f"  -> [success] Saved to: {output_c_filepath}")
                    
                except Exception as e:
                    print(
                        f"[{opt_level}][{base_name}] ❌ Unexpected error while "
                        f"processing decompiler output: {e}"
                    )

print("\n" + "="*50)
print("✅ Finished processing the selected binary files!")
