# Secure Code Analyzer - VS Code Extension

This directory contains a lightweight VS Code extension that wraps the Python `secure-code-analyzer` engine.

## 🚀 How to Run (Development Mode)

1. **Prerequisites**:
   - Node.js installed.
   - The `cli_analyzer.py` script must be available (extensions looks for it in workspace root).

2. **Install Dependencies**:
   ```bash
   cd vscode-extension
   npm install
   ```

3. **Launch in VS Code**:
   - Open this `vscode-extension` folder in VS Code.
   - Press **F5** (Run & Debug).
   - This will open a **new** VS Code window (Extension Development Host).
   - Open your project folder (where `cli_analyzer.py` is) in that new window.
   - Open a JS or PHP file (e.g., `test_samples/vulnerable.js`).
   - Hit **Save** (Ctrl+S).

4. **Verify**:
   - You should see **red squiggly lines** under vulnerable code.
   - Hover over them to see the security warning and remediation.

## ⚙️ Configuration

You can configure the extension in `.vscode/settings.json` of your project:

```json
{
    "secureCodeAnalyzer.pythonPath": "python",
    "secureCodeAnalyzer.scriptPath": "c:/absolute/path/to/cli_analyzer.py" 
}
```
*Note: The extension attempts to auto-discover `cli_analyzer.py` in the workspace root.*
