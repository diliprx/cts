from analyzer_engine import CodeAnalyzer

analyzer = CodeAnalyzer()

# A03: SQL Injection
code_sqli = """
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $userId;
$result = mysqli_query($conn, $query);
"""

# A03: XSS
code_xss = """
echo $_GET['name'];
print $_POST['comment'];
"""

with open("verification_results.txt", "w") as f:
    f.write("Running Regex Tests:\n\n")

    vulns_sqli = analyzer.analyze_code_string(code_sqli, "php", "sqli_test.php")
    f.write(f"SQLi vulns: {len(vulns_sqli)}\n")
    for v in vulns_sqli:
        f.write(f"  - {v.rule_id}: {v.rule_name} (Line {v.line_number})\n")

    vulns_xss = analyzer.analyze_code_string(code_xss, "php", "xss_test.php")
    f.write(f"\nXSS vulns: {len(vulns_xss)}\n")
    for v in vulns_xss:
        f.write(f"  - {v.rule_id}: {v.rule_name} (Line {v.line_number})\n")
    
    # Also test the exact line from user screenshot
    code_concat = '$query = "SELECT * FROM users WHERE id = " . $userId;'
    vulns_concat = analyzer.analyze_code_string(code_concat, "php", "concat_test.php")
    f.write(f"\nConcatenation vulns: {len(vulns_concat)}\n")
    for v in vulns_concat:
        f.write(f"  - {v.rule_id}: {v.rule_name} (Line {v.line_number})\n")

