// Frontend JavaScript for Secure Code Analyzer

let currentAnalysisData = null;
let allVulnerabilities = [];
let filteredVulnerabilities = [];

// File input handling
document.getElementById('fileInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        displayFileInfo(file);
        analyzeFile(file);
    }
});

// Drag and drop handling
const uploadCard = document.querySelector('.upload-card');
uploadCard.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadCard.classList.add('drag-over');
});

uploadCard.addEventListener('dragleave', () => {
    uploadCard.classList.remove('drag-over');
});

uploadCard.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadCard.classList.remove('drag-over');
    
    const file = e.dataTransfer.files[0];
    if (file && isValidFile(file)) {
        displayFileInfo(file);
        analyzeFile(file);
    } else {
        alert('Please upload a valid JavaScript or PHP file.');
    }
});

function isValidFile(file) {
    const validExtensions = ['.js', '.jsx', '.mjs', '.ts', '.tsx', '.php', '.phtml', '.txt'];
    const extension = '.' + file.name.split('.').pop().toLowerCase();
    return validExtensions.includes(extension);
}

function displayFileInfo(file) {
    const fileInfo = document.getElementById('fileInfo');
    fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
    fileInfo.classList.add('show');
}

async function analyzeFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    showLoading();
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentAnalysisData = data;
            displayResults(data);
        } else {
            showError(data.error || 'Analysis failed');
        }
    } catch (error) {
        showError('Error analyzing file: ' + error.message);
    } finally {
        hideLoading();
    }
}

async function analyzeCodeText() {
    const code = document.getElementById('codeInput').value;
    const language = document.getElementById('languageSelect').value;
    
    if (!code.trim()) {
        alert('Please enter some code to analyze.');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/analyze-text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                language: language,
                filename: `input.${language === 'javascript' ? 'js' : 'php'}`
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentAnalysisData = data;
            displayResults(data);
        } else {
            showError(data.error || 'Analysis failed');
        }
    } catch (error) {
        showError('Error analyzing code: ' + error.message);
    } finally {
        hideLoading();
    }
}

function showLoading() {
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('loadingSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('noIssuesSection').style.display = 'none';
}

function hideLoading() {
    document.getElementById('loadingSection').style.display = 'none';
}

function displayResults(data) {
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('noIssuesSection').style.display = 'none';
    
    // Store all vulnerabilities
    allVulnerabilities = data.vulnerabilities || [];
    filteredVulnerabilities = [...allVulnerabilities];
    
    // Display summary cards
    displaySummaryCards(data.statistics);
    
    // Display security score
    displaySecurityScore(data.security_score);
    
    // Populate category filter
    populateCategoryFilter(data.vulnerabilities);
    
    // Display vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        displayVulnerabilities(filteredVulnerabilities);
    } else {
        showNoIssues();
    }
}

function populateCategoryFilter(vulnerabilities) {
    const categoryFilter = document.getElementById('categoryFilter');
    const categories = [...new Set(vulnerabilities.map(v => v.category))].sort();
    
    // Clear existing options except "All"
    categoryFilter.innerHTML = '<option value="all">All</option>';
    
    categories.forEach(category => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        categoryFilter.appendChild(option);
    });
}

function applyFilters() {
    const severityFilter = document.getElementById('severityFilter').value;
    const categoryFilter = document.getElementById('categoryFilter').value;
    
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
        const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter;
        const matchesCategory = categoryFilter === 'all' || vuln.category === categoryFilter;
        return matchesSeverity && matchesCategory;
    });
    
    displayVulnerabilities(filteredVulnerabilities);
}

function clearFilters() {
    document.getElementById('severityFilter').value = 'all';
    document.getElementById('categoryFilter').value = 'all';
    filteredVulnerabilities = [...allVulnerabilities];
    displayVulnerabilities(filteredVulnerabilities);
}

function displaySummaryCards(stats) {
    const summaryCards = document.getElementById('summaryCards');
    summaryCards.innerHTML = '';
    
    const cards = [
        { label: 'Total Issues', value: stats.total, class: '' },
        { label: 'Critical', value: stats.by_severity.Critical, class: 'critical' },
        { label: 'High', value: stats.by_severity.High, class: 'high' },
        { label: 'Medium', value: stats.by_severity.Medium, class: 'medium' },
        { label: 'Low', value: stats.by_severity.Low, class: 'low' }
    ];
    
    cards.forEach(card => {
        const cardElement = document.createElement('div');
        cardElement.className = `summary-card ${card.class}`;
        cardElement.innerHTML = `
            <div class="value">${card.value}</div>
            <div class="label">${card.label}</div>
        `;
        summaryCards.appendChild(cardElement);
    });
}

function displaySecurityScore(score) {
    const scoreCard = document.getElementById('scoreCard');
    let scoreClass = 'poor';
    if (score >= 80) scoreClass = 'excellent';
    else if (score >= 60) scoreClass = 'good';
    
    scoreCard.innerHTML = `
        <div class="score-value ${scoreClass}">${score}</div>
        <div class="score-label">Security Score</div>
    `;
}

function displayVulnerabilities(vulnerabilities) {
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    
    if (vulnerabilities.length === 0) {
        vulnerabilitiesList.innerHTML = '<div class="no-results">No vulnerabilities match the selected filters.</div>';
        return;
    }
    
    vulnerabilitiesList.innerHTML = '';
    
    vulnerabilities.forEach((vuln, index) => {
        const vulnElement = document.createElement('div');
        vulnElement.className = `vulnerability-item ${vuln.severity.toLowerCase()}`;
        vulnElement.id = `vuln-${index}`;
        
        vulnElement.innerHTML = `
            <div class="vuln-header">
                <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                <span class="vuln-category">${vuln.category}</span>
                <span class="vuln-rule-id">${vuln.rule_id}</span>
            </div>
            <div class="vuln-title">${vuln.rule_name}</div>
            <div class="vuln-meta">
                <span><strong>File:</strong> ${vuln.file_path}</span>
                <span><strong>Line:</strong> ${vuln.line_number}</span>
            </div>
            <div class="vuln-description">
                <strong>Description:</strong> ${vuln.description}
            </div>
            <div class="vuln-code-section">
                <div class="code-header">
                    <span class="code-label">Vulnerable Code:</span>
                    <button class="ai-fix-btn" onclick="getAICorrection(${index})" data-code='${escapeForAttribute(vuln.code_snippet)}' data-description='${escapeForAttribute(vuln.description)}' data-remediation='${escapeForAttribute(vuln.remediation)}'>
                        🤖 Get AI Fix
                    </button>
                </div>
                <div class="vuln-code">
                    <pre>${escapeHtml(vuln.code_snippet)}</pre>
                </div>
                <div class="ai-corrected-code" id="ai-code-${index}" style="display: none;">
                    <div class="code-header">
                        <span class="code-label">AI-Corrected Code:</span>
                    </div>
                    <div class="vuln-code corrected">
                        <pre id="ai-code-content-${index}"></pre>
                    </div>
                </div>
            </div>
            <div class="vuln-remediation">
                <strong>Remediation:</strong> ${vuln.remediation}
            </div>
        `;
        
        vulnerabilitiesList.appendChild(vulnElement);
    });
}

async function getAICorrection(index) {
    const button = event.target;
    const originalText = button.textContent;
    const codeSnippet = button.getAttribute('data-code');
    const description = button.getAttribute('data-description');
    const remediation = button.getAttribute('data-remediation');
    
    button.disabled = true;
    button.textContent = '⏳ Generating...';
    
    try {
        const response = await fetch('/api/ai-fix', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: codeSnippet,
                description: description,
                remediation: remediation
            })
        });
        
        const data = await response.json();
        
        if (data.success && data.corrected_code) {
            const aiCodeDiv = document.getElementById(`ai-code-${index}`);
            const aiCodeContent = document.getElementById(`ai-code-content-${index}`);
            
            aiCodeContent.textContent = data.corrected_code;
            aiCodeDiv.style.display = 'block';
            
            button.textContent = '✅ Code Fixed';
            button.style.background = 'var(--success)';
            
            // Scroll to the corrected code
            aiCodeDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            alert('Error: ' + (data.error || 'Failed to generate corrected code'));
            button.textContent = originalText;
            button.disabled = false;
        }
    } catch (error) {
        alert('Error: ' + error.message);
        button.textContent = originalText;
        button.disabled = false;
    }
}

function escapeForAttribute(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\n/g, ' ');
}

function showNoIssues() {
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('noIssuesSection').style.display = 'block';
}

function showError(message) {
    alert('Error: ' + message);
    document.getElementById('uploadSection').style.display = 'block';
    document.getElementById('loadingSection').style.display = 'none';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function exportReport(format) {
    if (!currentAnalysisData || !currentAnalysisData.vulnerabilities) {
        alert('No analysis data to export.');
        return;
    }
    
    try {
        const response = await fetch(`/api/report/${format}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                vulnerabilities: currentAnalysisData.vulnerabilities
            })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_report.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            const error = await response.json();
            alert('Error exporting report: ' + (error.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Error exporting report: ' + error.message);
    }
}

// Reset functionality
function resetAnalysis() {
    document.getElementById('fileInput').value = '';
    document.getElementById('codeInput').value = '';
    document.getElementById('fileInfo').classList.remove('show');
    document.getElementById('fileInfo').textContent = '';
    document.getElementById('uploadSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('noIssuesSection').style.display = 'none';
    document.getElementById('loadingSection').style.display = 'none';
    currentAnalysisData = null;
    allVulnerabilities = [];
    filteredVulnerabilities = [];
    
    // Clear filters
    if (document.getElementById('severityFilter')) {
        document.getElementById('severityFilter').value = 'all';
    }
    if (document.getElementById('categoryFilter')) {
        document.getElementById('categoryFilter').value = 'all';
    }
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

