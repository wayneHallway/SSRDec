#!/usr/bin/env python3
import os
import angr
import numpy as np

# Assumes graph_rag_db.py is available in the same directory.
# from graph_rag_db import GraphVectorDB

def extract_cfg_to_db(binary_path, db: 'GraphVectorDB'):
    """
    Extract a binary's CFG with angr and store it directly in GraphVectorDB.
    """
    print(f"\n[*] Loading binary: {binary_path}")
    # auto_load_libs=False greatly speeds up analysis when only the target program matters.
    proj = angr.Project(binary_path, auto_load_libs=False)

    print("[*] Generating the control-flow graph (CFGFast)...")
    # normalize=True regularizes basic blocks and prevents overlaps.
    cfg = proj.analyses.CFGFast(normalize=True)

    print(
        f"[*] Extraction complete: found {len(cfg.graph.nodes())} node(s) "
        f"and {len(cfg.graph.edges())} edge(s)."
    )
    print("[*] Inserting data into GraphVectorDB...")

    # 1. Traverse all nodes (basic blocks) and store them in the database.
    for node in cfg.nodes():
        # Skip placeholder nodes that contain no code.
        if node.block is None or node.size == 0:
            continue
            
        # Extract the assembly text for this basic block.
        asm_instructions = []
        try:
            for insn in node.block.capstone.insns:
                asm_instructions.append(f"{insn.mnemonic}\t{insn.op_str}")
        except Exception:
            asm_instructions.append(";; failed to disassemble")
            
        asm_text = "\n".join(asm_instructions)
        
        # Simulate a Graph4MM vector; in production, generate an embedding from asm_text.
        mock_embedding = np.random.randn(db.embedding_dim)
        
        # Store the block in the graph vector database.
        db.add_basic_block(address=node.addr, asm_code=asm_text, embedding=mock_embedding)

    # 2. Traverse all edges (control transfers) and store them in the database.
    for src, dst, data in cfg.graph.edges(data=True):
        if src.block is None or dst.block is None:
            continue
            
        jumpkind = data.get('jumpkind', '')
        edge_type = 'cfg_unknown'
        desc = f"angr jump kind: {jumpkind}"
        
        # Map angr jump kinds to the database's edge types.
        if jumpkind == 'Ijk_Boring':
            # Inspect the source's outgoing edges to detect conditional branches.
            out_degree = cfg.graph.out_degree(src)
            if out_degree > 1:
                edge_type = 'cfg_conditional'
                desc = "Conditional branch (If/Else)"
            else:
                edge_type = 'cfg_unconditional'
                desc = "Unconditional jump / sequential execution"
        elif jumpkind == 'Ijk_Call':
            edge_type = 'cfg_call'
            desc = "Function call"
        elif jumpkind == 'Ijk_Ret':
            edge_type = 'cfg_return'
            desc = "Function return"

        # Store the edge in the database graph.
        db.add_edge(src.addr, dst.addr, edge_type, desc)
        
    print(f"[+] Graph data for {os.path.basename(binary_path)} was stored successfully!\n")

# ================= Test pipeline =================
if __name__ == "__main__":
    # GraphVectorDB follows the structure documented alongside this script.
    from graph_rag_db import GraphVectorDB
    
    # 1. Initialize the graph vector database.
    db = GraphVectorDB(embedding_dim=256)
    
    # 2. Point to an ELF or .o file in the compiler output directory.
    # Replace this with the actual .o or .elf path.
    sample_binary = "/home/lhw/codetran/ghidra/compiled-o-files/O0/task_0_O0.o" 
    
    if os.path.exists(sample_binary):
        # 3. Extract the graph and store it.
        extract_cfg_to_db(sample_binary, db)
        
        # 4. Test RAG retrieval with an address that was just inserted.
        if db.addresses:
            test_anchor = db.addresses[0]  # Use the address of the first stored basic block.
            print(f"--- Generating Graph RAG context for address {hex(test_anchor)} ---")
            print(db.retrieve_structural_context(test_anchor))
    else:
        print(f"Provide a valid binary path for testing: {sample_binary}")
