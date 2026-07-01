import os
import re
import argparse
try:
    from pycparser import c_parser, c_ast
except ImportError:
    print("错误: 请先安装 pycparser 库。命令: pip install pycparser")
    exit(1)

class DecompilerTrapVisitor(c_ast.NodeVisitor):
    """
    AST 遍历器：查找可能破坏反编译器类型推断的 C 语法结构
    """
    def __init__(self):
        self.issues = []

    def add_issue(self, node, issue_type, reason):
        # pycparser 的 node.coord 包含行号等位置信息
        line = node.coord.line if node.coord else "未知"
        self.issues.append((line, issue_type, reason))

    def visit_Union(self, node):
        """检测：联合体 (Union)"""
        self.add_issue(node, "联合体 (Union) 定义", 
                       "联合体成员在内存中重叠，反编译器很难在静态分析时确定当前使用的是哪个类型的字段，通常会降级推断。")
        self.generic_visit(node)

    def visit_Struct(self, node):
        """检测：结构体中的位域 (Bit-fields)"""
        if node.decls:
            for decl in node.decls:
                if decl.bitsize: # 如果指定了位宽，比如 int flag : 3;
                    self.add_issue(decl, "位域 (Bit-field)", 
                                   "位域高度依赖编译器的具体实现（对齐、大小端），反编译器极易将其错误推断为复杂的位掩码运算而非结构体字段。")
        self.generic_visit(node)

    def visit_Cast(self, node):
        """检测：危险的强制类型转换 (类型双关)"""
        # 如果是强制转换成指针类型
        if isinstance(node.to_type.type, c_ast.PtrDecl):
            # 获取目标指针的基础类型
            ptr_type_node = node.to_type.type.type
            if isinstance(ptr_type_node, c_ast.TypeDecl):
                target_type = ptr_type_node.type.names[0] if ptr_type_node.type.names else ""
                
                # 特别关注：强转为 char* 或 void* 进行字节级操作
                if target_type in ('char', 'void'):
                    self.add_issue(node, f"强转为 {target_type}*", 
                                   "将结构体或变量指针强转为字节指针通常意味着后续有越过类型边界的硬算术运算，这会抹除反编译器眼中的类型结构。")
        self.generic_visit(node)

    def visit_ArrayRef(self, node):
        """检测：可疑的数组访问 (简单越界探测)"""
        # 尝试查看数组下标是否是常量负数或者可能越界的运算
        if isinstance(node.subscript, c_ast.UnaryOp) and node.subscript.op == '-':
            self.add_issue(node, "负数数组下标", 
                           "使用负数下标访问数组通常是内存越界的 Hack 技巧（如访问前面的结构体头部），这会导致反编译器的类型传播链断裂。")
        self.generic_visit(node)

class ASTBasedDetector:
    def __init__(self):
        self.parser = c_parser.CParser()

    def clean_c_code(self, source_code):
        """
        清理 C 代码以适应 pycparser
        pycparser 不支持未处理的预编译指令 (#include, #define 等) 以及注释，
        这里做一个简单的清理，并注入常见的标准库和逆向工具类型定义，防止解析报错。
        """
        # 1. 移除块注释 /* ... */
        cleaned_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        # 2. 移除单行注释 // ...
        cleaned_code = re.sub(r'//.*', '', cleaned_code)
        # 3. 移除 #include 和 #define 等预处理指令
        cleaned_code = re.sub(r'^\s*#.*$', '', cleaned_code, flags=re.MULTILINE)
        
        # 注入标准伪类型及 Ghidra 常见类型，防止 pycparser 报错
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
        
        /* 注入 Ghidra 反编译常见的特定类型 */
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
            # 将 C 代码解析为抽象语法树 (AST)
            ast = self.parser.parse(cleaned_code, filename=filepath)
            
            # 使用遍历器查找陷阱
            visitor = DecompilerTrapVisitor()
            visitor.visit(ast)
            
            # 过滤掉模拟头文件产生的行号偏移（前12行是我们加的伪类型）
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
            # 记录解析失败的文件，但跳过它继续扫描
            return [("解析失败", "AST 构建失败", f"代码存在语法错误或缺少自定义类型(typedef)。错误详情: {str(e)}")]

def scan_directory(directory_path):
    detector = ASTBasedDetector()
    all_issues = {}
    valid_extensions = ('.c', '.h') # pycparser 主要针对纯 C 语言

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
    print("基于 AST (抽象语法树) 的反编译类型推断缺陷分析报告")
    print("=" * 70)
    
    if not all_issues:
        print("  ✓ 未发现明显的反编译陷阱。")
        return

    total_files = len(all_issues)
    total_issues = sum(len(issues) for issues in all_issues.values())
    print(f"扫描完毕！在 {total_files} 个文件中发现了 {total_issues} 处潜在问题。\n")

    for filepath, issues in all_issues.items():
        print(f"📁 目标文件: {filepath}")
        for issue in issues:
            line, issue_type, reason = issue
            if issue_type == "AST 构建失败":
                print(f"  [!] 解析警告: {reason}")
            else:
                print(f"  [第 {line} 行] ⚠️ 结构化特征: {issue_type}")
                print(f"    -> 影响原理: {reason}\n")
        print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="批量分析 C 源码文件夹中的反编译陷阱")
    parser.add_argument("directory", nargs="?", default="/home/lhw/codetran/ghidra/dec-bring/O2", help="要分析的 C 代码文件夹路径 (默认为当前目录)")
    args = parser.parse_args()

    target_dir = args.directory
    
    if not os.path.isdir(target_dir):
        print(f"错误: 找不到文件夹 '{target_dir}'")
    else:
        print(f"正在扫描文件夹: {target_dir} ...")
        report_data = scan_directory(target_dir)
        print_report(report_data)