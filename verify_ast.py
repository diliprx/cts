import os
from analyzer_engine import CodeAnalyzer, Language

def test_ast_fallback():
    print("Initializing CodeAnalyzer...")
    analyzer = CodeAnalyzer()
    
    # Check tools availability
    print("\nTool Availability:")
    for tool, available in analyzer.tool_runner.tools_available.items():
        print(f"  - {tool}: {'AVAILABLE' if available else 'MISSING'}")
    
    # Test file path
    test_file = os.path.join('test_samples', 'vulnerable.php')
    
    with open('verification_log.txt', 'w') as log:
        if os.path.exists(test_file):
            log.write(f"Analyzing {test_file}...\n")
            results = analyzer.analyze_file(test_file)
            
            log.write(f"\nFound {len(results)} vulnerabilities:\n")
            for i, v in enumerate(results, 1):
                log.write(f"[{i}] {v.rule_name} ({v.severity.value}) - {v.matched_pattern}\n")
                
            # Check if we have regex results (since tools are likely missing)
            regex_found = any([v.matched_pattern != "AST Analysis" for v in results])
            ast_found = any([v.matched_pattern == "AST Analysis" for v in results])
            
            if regex_found:
                log.write("\nSUCCESS: Regex fallback is working.\n")
            else:
                log.write("\nWARNING: No regex vulnerabilities found (unexpected for vulnerable.php).\n")
                
            if ast_found:
                log.write("SUCCESS: AST tools successfully detected issues.\n")
            else:
                log.write("INFO: No AST issues found (expected if tools are missing).\n")
                
        else:
            log.write(f"Error: Test file {test_file} not found.\n")

if __name__ == "__main__":
    test_ast_fallback()
