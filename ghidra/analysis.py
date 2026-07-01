import os
import re
import argparse
try:
    from pycparser import c_parser, c_ast
except ImportError:
    print("Error: install pycparser first. Command: pip install pycparser")
    exit(1)

class DecompilerTrapVisitor(c_ast.NodeVisitor):
    """
    AST visitor that finds C syntax constructs which may disrupt a
    decompiler's type inference.
    """
    def __init__(self):
        self.issues = []

    def add_issue(self, node, issue_type, reason):
        # pycparser's node.coord contains the line number and other location data.
        line = node.coord.line if node.coord else "unknown"
        self.issues.append((line, issue_type, reason))

    def visit_Union(self, node):
        """Detect union definitions."""
        self.add_issue(
            node,
            "Union definition",
            "Union members overlap in memory, making it difficult for a decompiler "
            "to determine which field type is active during static analysis. This "
            "usually degrades type inference.",
        )
        self.generic_visit(node)

    def visit_Struct(self, node):
        """Detect bit-fields in structures."""
        if node.decls:
            for decl in node.decls:
                if decl.bitsize: # A bit width is specified, for example: int flag : 3;
                    self.add_issue(
                        decl,
                        "Bit-field",
                        "Bit-fields depend heavily on compiler-specific layout, "
                        "alignment, and endianness. A decompiler may infer complex "
                        "bit-mask operations instead of structure fields.",
                    )
        self.generic_visit(node)

    def visit_Cast(self, node):
        """Detect dangerous casts used for type punning."""
        # Check whether the target type is a pointer.
        if isinstance(node.to_type.type, c_ast.PtrDecl):
            # Get the base type of the target pointer.
            ptr_type_node = node.to_type.type.type
            if isinstance(ptr_type_node, c_ast.TypeDecl):
                target_type = ptr_type_node.type.names[0] if ptr_type_node.type.names else ""
                
                # Pay special attention to casts to char* or void* for byte-level operations.
                if target_type in ('char', 'void'):
                    self.add_issue(
                        node,
                        f"Cast to {target_type}*",
                        "Casting a structure or variable pointer to a byte pointer "
                        "often precedes arithmetic across type boundaries, which "
                        "erases type structure from the decompiler's view.",
                    )
        self.generic_visit(node)

    def visit_ArrayRef(self, node):
        """Detect suspicious array access with a basic bounds check."""
        # Look for constant negative subscripts or operations that may go out of bounds.
        if isinstance(node.subscript, c_ast.UnaryOp) and node.subscript.op == '-':
            self.add_issue(
                node,
                "Negative array subscript",
                "A negative array subscript often indicates an out-of-bounds memory "
                "access technique, such as reaching a preceding structure header. "
                "This can break the decompiler's type-propagation chain.",
            )
        self.generic_visit(node)

class ASTBasedDetector:
    def __init__(self):
        self.parser = c_parser.CParser()

    def clean_c_code(self, source_code):
        """
        Prepare C code for pycparser.

        pycparser does not support unprocessed preprocessor directives such as
        #include and #define, or comments. Perform a lightweight cleanup and
        inject common standard-library and reverse-engineering type definitions
        to prevent parse errors.
        """
        # 1. Remove block comments: /* ... */
        cleaned_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        # 2. Remove line comments: // ...
        cleaned_code = re.sub(r'//.*', '', cleaned_code)
        # 3. Remove preprocessor directives such as #include and #define.
        cleaned_code = re.sub(r'^\s*#.*$', '', cleaned_code, flags=re.MULTILINE)
        
        # Inject standard placeholder types and common Ghidra types to prevent parse errors.
        mock_headers = """
        typedef int size_t;
        typedef int ssize_t;
        typedef char int8_t;
        typedef short int16_t;
        typedef int int32_t;
        typedef long long int64_t;
        typedef unsigned char uint8_t;
        typedef unsigned short uint16_t;
        typedef unsigned int uint32_t;
        typedef unsigned long long uint64_t;
        typedef void* FILE;
        
        /* Common types found in Ghidra decompiler output. */
        typedef unsigned char   undefined;
        typedef unsigned char   undefined1;
        typedef unsigned short  undefined2;
        typedef unsigned int    undefined4;
        typedef unsigned long long undefined8;
        typedef unsigned char   byte;
        typedef unsigned short  word;
        typedef unsigned int    dword;
        typedef unsigned long long qword;
        typedef unsigned int    uint;
        typedef unsigned short  ushort;
        typedef unsigned char   uchar;
        typedef unsigned long   ulong;
        typedef long long       longlong;
        """
        return mock_headers + cleaned_code

    def analyze_c_code(self, source_code, filepath):
        cleaned_code = self.clean_c_code(source_code)
        try:
            # Parse the C code into an abstract syntax tree (AST).
            ast = self.parser.parse(cleaned_code, filename=filepath)
            
            # Use the visitor to locate decompilation traps.
            visitor = DecompilerTrapVisitor()
            visitor.visit(ast)
            
            # Remove the line offset introduced by the synthetic header above.
            adjusted_issues = []
            for line, issue_type, reason in visitor.issues:
                if isinstance(line, int):
                    real_line = line - 12
                    if real_line > 0:
                        adjusted_issues.append((real_line, issue_type, reason))
                else:
                    adjusted_issues.append((line, issue_type, reason))
                    
            return adjusted_issues
        except Exception as e:
            # Record the parse failure, then skip the file and continue scanning.
            return [
                (
                    "parse failed",
                    "AST construction failed",
                    "The code contains a syntax error or lacks a custom typedef. "
                    f"Details: {str(e)}",
                )
            ]

def scan_directory(directory_path):
    detector = ASTBasedDetector()
    all_issues = {}
    valid_extensions = ('.c', '.h') # pycparser primarily targets plain C.

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith(valid_extensions):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        source_code = f.read()
                    
                    issues = detector.analyze_c_code(source_code, file)
                    if issues:
                        all_issues[filepath] = issues
                except UnicodeDecodeError:
                    try:
                        with open(filepath, 'r', encoding='gbk') as f:
                            source_code = f.read()
                        issues = detector.analyze_c_code(source_code, file)
                        if issues:
                            all_issues[filepath] = issues
                    except Exception:
                        pass
    return all_issues

def print_report(all_issues):
    print("=" * 70)
    print("AST-Based Decompiler Type-Inference Risk Report")
    print("=" * 70)
    
    if not all_issues:
        print("  ✓ No obvious decompilation traps were found.")
        return

    total_files = len(all_issues)
    total_issues = sum(len(issues) for issues in all_issues.values())
    print(
        f"Scan complete: found {total_issues} potential issue(s) "
        f"in {total_files} file(s).\n"
    )

    for filepath, issues in all_issues.items():
        print(f"📁 Target file: {filepath}")
        for issue in issues:
            line, issue_type, reason = issue
            if issue_type == "AST construction failed":
                print(f"  [!] Parse warning: {reason}")
            else:
                print(f"  [Line {line}] ⚠️ Structural feature: {issue_type}")
                print(f"    -> Impact: {reason}\n")
        print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan a directory of C source files for decompilation traps"
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="/home/lhw/codetran/ghidra/dec-bring/O2",
        help="Directory containing C source files",
    )
    args = parser.parse_args()

    target_dir = args.directory
    
    if not os.path.isdir(target_dir):
        print(f"Error: directory not found: '{target_dir}'")
    else:
        print(f"Scanning directory: {target_dir} ...")
        report_data = scan_directory(target_dir)
        print_report(report_data)
