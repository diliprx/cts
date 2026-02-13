const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const fs = require('fs');

const DIAGNOSTIC_COLLECTION_NAME = 'secureCodeAnalyzer';

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    const outputChannel = vscode.window.createOutputChannel('Secure Code Analyzer');
    context.subscriptions.push(outputChannel);
    
    outputChannel.appendLine('Secure Code Analyzer activating...');
    outputChannel.show(true);

    vscode.window.showInformationMessage('Secure Code Analyzer Active! Open output channel for logs.');

    const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    context.subscriptions.push(diagnosticCollection);

    // Analyze on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((document) => {
        analyzeDocument(document, diagnosticCollection, outputChannel);
    }));

    // Analyze on open
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((document) => {
        analyzeDocument(document, diagnosticCollection, outputChannel);
    }));
    
    // Analyze active editor on activation
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document, diagnosticCollection, outputChannel);
    }

    // Manual analysis command
    context.subscriptions.push(vscode.commands.registerCommand('secureCodeAnalyzer.analyzeFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            analyzeDocument(editor.document, diagnosticCollection, outputChannel);
            vscode.window.showInformationMessage('Manual analysis triggered.');
        } else {
            vscode.window.showErrorMessage('No active file to analyze.');
        }
    }));
}

function analyzeDocument(document, diagnosticCollection, outputChannel) {
    if (!isValidLanguage(document.languageId)) {
        return;
    }

    const config = vscode.workspace.getConfiguration('secureCodeAnalyzer');
    const pythonPath = config.get('pythonPath') || 'python';
    
    // Try to find the script in the workspace root if not configured
    let scriptPath = config.get('scriptPath');
    if (!scriptPath) {
        // Search in workspace folders
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders) {
            for (const folder of workspaceFolders) {
                // Check root
                let potentialPath = path.join(folder.uri.fsPath, 'cli_analyzer.py');
                if (fs.existsSync(potentialPath)) {
                    scriptPath = potentialPath;
                    break;
                }
                // Check 'cts' subdir (if workspace is parent)
                potentialPath = path.join(folder.uri.fsPath, 'cts', 'cli_analyzer.py');
                if (fs.existsSync(potentialPath)) {
                    scriptPath = potentialPath;
                    break;
                }
            }
        }
    }
    
    // Developer Fallback: Try relative to extension file (assuming structure: /cts/vscode-extension/extension.js -> /cts/cli_analyzer.py)
    if (!scriptPath || !fs.existsSync(scriptPath)) {
        const potentialPath = path.resolve(__dirname, '..', 'cli_analyzer.py');
        if (fs.existsSync(potentialPath)) {
            scriptPath = potentialPath;
        }
    }

    if (!scriptPath || !fs.existsSync(scriptPath)) {
        outputChannel.appendLine(`Error: Could not find cli_analyzer.py in workspace or parent directory.`);
        outputChannel.appendLine(`Please configure "secureCodeAnalyzer.scriptPath" in settings.`);
        return;
    }

    const filePath = document.uri.fsPath;
    const args = [scriptPath, '--file', filePath, '--format', 'json'];

    outputChannel.appendLine(`Analyzing: ${filePath}`);
    outputChannel.appendLine(`Command: ${pythonPath} ${args.join(' ')}`);

    const process = cp.exec(`"${pythonPath}" "${scriptPath}" --file "${filePath}" --format json`, {
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
    }, (error, stdout, stderr) => {
        if (error) {
            outputChannel.appendLine(`Analyzer failed with exit code ${error.code}`);
            outputChannel.appendLine(`Error: ${error.message}`);
            if (stderr) outputChannel.appendLine(`Stderr: ${stderr}`);
            outputChannel.show(true);
            return;
        }

        if (stderr) {
            outputChannel.appendLine(`Analyzer Stderr: ${stderr}`);
        }

        try {
            const cleanOutput = stdout.trim();
            if (!cleanOutput) {
                outputChannel.appendLine('Analysis complete but returned no output.');
                return;
            }
            
            const results = JSON.parse(cleanOutput);
            const vulnerabilities = results.vulnerabilities || [];
            outputChannel.appendLine(`Analysis complete. Found ${vulnerabilities.length} issues.`);

            const diagnostics = vulnerabilities.map(vuln => {
                const lineIndex = Math.max(0, (vuln.line_number || 1) - 1);
                const range = new vscode.Range(lineIndex, 0, lineIndex, Number.MAX_VALUE);
                
                const severity = mapSeverity(vuln.severity);
                
                const diagnostic = new vscode.Diagnostic(range, `${vuln.rule_name}: ${vuln.description}`, severity);
                diagnostic.code = vuln.rule_id;
                diagnostic.source = 'Secure Code Analyzer';
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range), 
                        `Category: ${vuln.category} | Remediation: ${vuln.remediation}`
                    )
                ];
                return diagnostic;
            });

            diagnosticCollection.set(document.uri, diagnostics);

        } catch (e) {
            outputChannel.appendLine(`Failed to parse analysis results: ${e}`);
            outputChannel.appendLine(`Raw Output: ${stdout}`);
            outputChannel.show(true);
        }
    });
}

function isValidLanguage(languageId) {
    return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'php', 'python'].includes(languageId);
}

function mapSeverity(severityStr) {
    if (!severityStr) return vscode.DiagnosticSeverity.Warning;
    
    switch (severityStr.toUpperCase()) {
        case 'CRITICAL': return vscode.DiagnosticSeverity.Error;
        case 'HIGH': return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
        case 'LOW': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Warning;
    }
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
