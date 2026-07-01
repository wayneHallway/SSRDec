#!/usr/bin/env python3
import os
import angr
import numpy as np

# 假设你已经将右侧的 graph_rag_db.py 放在同级目录
# from graph_rag_db import GraphVectorDB

def extract_cfg_to_db(binary_path, db: 'GraphVectorDB'):
    """
    使用 angr 提取二进制文件的 CFG，并直接存入 GraphVectorDB
    """
    print(f"\n[*] 正在加载二进制文件: {binary_path}")
    # auto_load_libs=False 可以极大加快分析速度，因为我们通常只关心目标程序本身
    proj = angr.Project(binary_path, auto_load_libs=False)

    print("[*] 正在生成控制流图 (CFGFast)...")
    # normalize=True 会规整基本块，防止基本块重叠
    cfg = proj.analyses.CFGFast(normalize=True)

    print(f"[*] 成功提取！共发现 {len(cfg.graph.nodes())} 个节点，{len(cfg.graph.edges())} 条边。")
    print("[*] 正在将数据录入 GraphVectorDB...")

    # 1. 遍历所有节点 (基本块)，存入数据库
    for node in cfg.nodes():
        # 跳过没有实际代码的占位节点
        if node.block is None or node.size == 0:
            continue
            
        # 提取该基本块的汇编指令文本
        asm_instructions = []
        try:
            for insn in node.block.capstone.insns:
                asm_instructions.append(f"{insn.mnemonic}\t{insn.op_str}")
        except Exception:
            asm_instructions.append(";; failed to disassemble")
            
        asm_text = "\n".join(asm_instructions)
        
        # 模拟 Graph4MM 生成的向量 (在真实场景中，你会把 asm_text 喂给你的模型生成 embedding)
        mock_embedding = np.random.randn(db.embedding_dim)
        
        # 存入图向量数据库
        db.add_basic_block(address=node.addr, asm_code=asm_text, embedding=mock_embedding)

    # 2. 遍历所有边 (跳转关系)，存入数据库
    for src, dst, data in cfg.graph.edges(data=True):
        if src.block is None or dst.block is None:
            continue
            
        jumpkind = data.get('jumpkind', '')
        edge_type = 'cfg_unknown'
        desc = f"angr 跳转类型: {jumpkind}"
        
        # 将 angr 的跳转类型映射为我们数据库理解的类型
        if jumpkind == 'Ijk_Boring':
            # 普通跳转，检查源节点有几个出口来判断是否是条件跳转
            out_degree = cfg.graph.out_degree(src)
            if out_degree > 1:
                edge_type = 'cfg_conditional'
                desc = "条件分支 (If/Else)"
            else:
                edge_type = 'cfg_unconditional'
                desc = "无条件跳转 / 顺序执行"
        elif jumpkind == 'Ijk_Call':
            edge_type = 'cfg_call'
            desc = "函数调用 (Call)"
        elif jumpkind == 'Ijk_Ret':
            edge_type = 'cfg_return'
            desc = "函数返回 (Return)"

        # 存入数据库的图结构中
        db.add_edge(src.addr, dst.addr, edge_type, desc)
        
    print(f"[+] {os.path.basename(binary_path)} 的图谱数据已成功入库！\n")

# ================= 测试流水线 =================
if __name__ == "__main__":
    # 这里的 GraphVectorDB 结构参照你右侧文档里的代码
    from graph_rag_db import GraphVectorDB
    
    # 1. 初始化你的图向量库
    db = GraphVectorDB(embedding_dim=256)
    
    # 2. 假设你的编译输出目录下有一个 elf 或 .o 文件
    # 请把这里换成你实际的 .o 或 .elf 路径
    sample_binary = "/home/lhw/codetran/ghidra/compiled-o-files/O0/task_0_O0.o" 
    
    if os.path.exists(sample_binary):
        # 3. 执行提取与入库
        extract_cfg_to_db(sample_binary, db)
        
        # 4. 测试一下 RAG 检索 (随便找一个刚刚入库的地址)
        if db.addresses:
            test_anchor = db.addresses[0]  # 取第一个存入的基本块地址
            print(f"--- 正在为地址 {hex(test_anchor)} 生成 Graph RAG Context ---")
            print(db.retrieve_structural_context(test_anchor))
    else:
        print(f"请提供一个有效的二进制文件路径以供测试: {sample_binary}")