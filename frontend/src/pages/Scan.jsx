import React, { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, FileCode, ShieldCheck, Loader2, X, FolderOpen,
  Globe, ClipboardPaste, Archive, SearchCode, AlertTriangle,
  Download, ChevronDown, ChevronRight, Shield, Info,
} from 'lucide-react';

const LANGUAGES = [
  'python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'csharp',
  'go', 'ruby', 'kotlin', 'swift', 'scala', 'rust', 'bash', 'powershell',
  'sql', 'html', 'css', 'xml', 'yaml', 'json', 'dockerfile', 'terraform',
];

const SEVERITY_CONFIG = {
  Critical: { color: 'bg-red-500/20 text-red-400 border border-red-500/30', dot: 'bg-red-500', order: 0 },
  High:     { color: 'bg-orange-500/20 text-orange-400 border border-orange-500/30', dot: 'bg-orange-500', order: 1 },
  Medium:   { color: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30', dot: 'bg-yellow-500', order: 2 },
  Low:      { color: 'bg-blue-500/20 text-blue-400 border border-blue-500/30', dot: 'bg-blue-400', order: 3 },
};

const TAB_CONFIG = [
  { id: 'file',   label: 'Single File', icon: FileCode },
  { id: 'multi',  label: 'Multi-File',  icon: FolderOpen },
  { id: 'zip',    label: 'ZIP Archive', icon: Archive },
  { id: 'repo',   label: 'Repository',  icon: Globe },
  { id: 'paste',  label: 'Paste Code',  icon: ClipboardPaste },
];

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.Low;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {severity}
    </span>
  );
}

function VulnerabilityCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);
  const [aiFix, setAiFix] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const handleAiFix = async () => {
    setAiLoading(true);
    try {
      const res = await fetch('/api/ai-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: vuln.code_snippet,
          description: vuln.description,
          remediation: vuln.remediation,
          language: 'unknown',
        }),
      });
      const data = await res.json();
      if (data.success) setAiFix(data.corrected_code);
    } catch (e) {
      setAiFix('AI fix unavailable at the moment.');
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      className="bg-white/5 border border-white/10 rounded-xl overflow-hidden"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-white/5 transition-colors"
      >
        <span className="text-white/40 font-mono text-xs w-8 shrink-0">#{index + 1}</span>
        <SeverityBadge severity={vuln.severity} />
        <span className="font-semibold text-white text-sm flex-1 truncate">{vuln.rule_name}</span>
        <span className="text-white/40 text-xs hidden sm:block truncate max-w-[200px]">{vuln.file_path}</span>
        {expanded ? <ChevronDown className="w-4 h-4 text-white/40 shrink-0" /> : <ChevronRight className="w-4 h-4 text-white/40 shrink-0" />}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/10 p-4 space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                {[
                  ['Rule ID', vuln.rule_id],
                  ['Category', vuln.category],
                  ['File', vuln.file_path],
                  ['Line', vuln.line_end ? `${vuln.line_number}–${vuln.line_end}` : vuln.line_number],
                  ['Type', vuln.match_type],
                  ['CWE', vuln.cwe || 'N/A'],
                ].map(([label, val]) => (
                  <div key={label} className="bg-white/5 rounded-lg p-3">
                    <div className="text-white/40 mb-1">{label}</div>
                    <div className="text-white font-medium font-mono truncate">{val}</div>
                  </div>
                ))}
              </div>

              <div>
                <div className="text-white/60 text-xs mb-1.5 font-semibold uppercase tracking-wide">Description</div>
                <p className="text-white/80 text-sm leading-relaxed">{vuln.description}</p>
              </div>

              <div>
                <div className="text-white/60 text-xs mb-1.5 font-semibold uppercase tracking-wide">Code Snippet</div>
                <pre className="bg-black/40 rounded-lg p-3 text-xs text-green-300 font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap">{vuln.code_snippet}</pre>
              </div>

              <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3">
                <div className="text-green-400 text-xs mb-1 font-semibold uppercase tracking-wide">✅ Remediation</div>
                <p className="text-white/80 text-sm leading-relaxed">{vuln.remediation}</p>
              </div>

              {!aiFix && (
                <button
                  onClick={handleAiFix}
                  disabled={aiLoading}
                  className="flex items-center gap-2 px-3 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-300 text-xs font-semibold rounded-lg transition-colors disabled:opacity-50"
                >
                  {aiLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                  {aiLoading ? 'Generating AI Fix...' : 'Get AI Fix'}
                </button>
              )}

              {aiFix && (
                <div>
                  <div className="text-purple-400 text-xs mb-1.5 font-semibold uppercase tracking-wide">🤖 AI-Generated Fix</div>
                  <pre className="bg-black/40 rounded-lg p-3 text-xs text-purple-300 font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap">{aiFix}</pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function ResultsPanel({ data, onReset }) {
  const [severityFilter, setSeverityFilter] = useState('All');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [downloading, setDownloading] = useState(null);

  const vulns = data.vulnerabilities || [];
  const stats = data.statistics || {};
  const score = data.security_score ?? 0;
  const grade = data.grade || 'F';

  const gradeColor = grade.startsWith('A') ? 'text-green-400' : grade === 'B' ? 'text-blue-400' : grade === 'C' ? 'text-yellow-400' : 'text-red-400';

  const categories = ['All', ...Array.from(new Set(vulns.map(v => v.category)))];
  const filtered = vulns
    .filter(v => severityFilter === 'All' || v.severity === severityFilter)
    .filter(v => categoryFilter === 'All' || v.category === categoryFilter)
    .filter(v => !searchQuery || v.rule_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.file_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.description.toLowerCase().includes(searchQuery.toLowerCase()));

  const formatExtensions = { json: 'json', csv: 'csv', html: 'html', markdown: 'md', txt: 'txt', pdf: 'pdf' };

  const handleDownload = async (format) => {
    setDownloading(format);
    try {
      const res = await fetch(`/api/report/${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerabilities: vulns }),
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security_report.${formatExtensions[format] || format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      console.error('Download failed', e);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Results</h2>
          <p className="text-white/50 text-sm mt-0.5">
            {data.file_count ? `${data.file_count} files` : data.filename || 'Analysis'} · {vulns.length} findings
          </p>
        </div>
        <button onClick={onReset} className="flex items-center gap-2 px-4 py-2 bg-white/10 hover:bg-white/15 text-white text-sm rounded-xl transition-colors border border-white/10">
          <X className="w-4 h-4" /> New Scan
        </button>
      </div>

      {/* Score Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3">
        {[
          { label: 'Score', value: `${score}`, sub: '/100' },
          { label: 'Grade', value: grade, extra: gradeColor },
          { label: 'Critical', value: stats.by_severity?.Critical ?? 0, color: 'text-red-400' },
          { label: 'High', value: stats.by_severity?.High ?? 0, color: 'text-orange-400' },
          { label: 'Medium', value: stats.by_severity?.Medium ?? 0, color: 'text-yellow-400' },
          { label: 'Low', value: stats.by_severity?.Low ?? 0, color: 'text-blue-400' },
          { label: 'Total', value: vulns.length },
        ].map(({ label, value, sub, color, extra }) => (
          <div key={label} className="bg-white/5 border border-white/10 rounded-xl p-3 text-center">
            <div className={`text-2xl font-bold ${color || extra || 'text-white'}`}>{value}{sub && <span className="text-sm text-white/40">{sub}</span>}</div>
            <div className="text-white/40 text-xs mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {/* Download Bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-white/40 text-xs font-semibold uppercase tracking-wide">Download:</span>
        {['json', 'csv', 'html', 'markdown', 'txt', 'pdf'].map(fmt => (
          <button
            key={fmt}
            onClick={() => handleDownload(fmt)}
            disabled={downloading === fmt}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/10 hover:bg-white/15 border border-white/10 text-white text-xs rounded-lg transition-colors disabled:opacity-50 font-medium uppercase"
          >
            {downloading === fmt ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
            {fmt}
          </button>
        ))}
      </div>

      {/* Filters */}
      {vulns.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-primary/50 flex-1 min-w-48"
          />
          <div className="flex gap-2 flex-wrap">
            {['All', 'Critical', 'High', 'Medium', 'Low'].map(s => (
              <button key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${severityFilter === s ? 'bg-primary text-white' : 'bg-white/5 text-white/60 hover:bg-white/10 border border-white/10'}`}
              >{s}</button>
            ))}
          </div>
          <select
            value={categoryFilter}
            onChange={e => setCategoryFilter(e.target.value)}
            className="bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none"
          >
            {categories.map(c => <option key={c} value={c} className="bg-gray-900">{c}</option>)}
          </select>
        </div>
      )}

      {/* Results */}
      {vulns.length === 0 ? (
        <div className="text-center py-20 bg-green-500/10 border border-green-500/20 rounded-2xl">
          <ShieldCheck className="w-16 h-16 text-green-400 mx-auto mb-4" />
          <h3 className="text-2xl font-bold text-green-400 mb-2">No Vulnerabilities Detected!</h3>
          <p className="text-white/50">Your code follows security best practices. Great work!</p>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-white/40 text-xs">{filtered.length} of {vulns.length} findings shown</p>
          {filtered.sort((a, b) => (SEVERITY_CONFIG[a.severity]?.order ?? 99) - (SEVERITY_CONFIG[b.severity]?.order ?? 99))
            .map((v, i) => <VulnerabilityCard key={`${v.rule_id}-${v.file_path}-${v.line_number}-${i}`} vuln={v} index={i} />)}
        </div>
      )}
    </motion.div>
  );
}

export default function Scan() {
  const [activeTab, setActiveTab] = useState('file');
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [error, setError] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  // File tab
  const [selectedFile, setSelectedFile] = useState(null);

  // Multi tab
  const [multiFiles, setMultiFiles] = useState([]);

  // ZIP tab
  const [zipFile, setZipFile] = useState(null);

  // Repo tab
  const [repoUrl, setRepoUrl] = useState('');

  // Paste tab
  const [pasteCode, setPasteCode] = useState('');
  const [pasteLanguage, setPasteLanguage] = useState('python');

  const fileInputRef = useRef();
  const multiInputRef = useRef();
  const zipInputRef = useRef();

  const reset = () => {
    setAnalysisData(null); setError(null);
    setSelectedFile(null); setMultiFiles([]); setZipFile(null);
    setRepoUrl(''); setPasteCode('');
  };

  const handleResponse = async (res) => {
    const data = await res.json();
    if (data.success) setAnalysisData(data);
    else setError(data.error || 'Analysis failed');
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    if (files.length === 1) { setSelectedFile(files[0]); setActiveTab('file'); }
    else { setMultiFiles(files); setActiveTab('multi'); }
  }, []);

  const runScan = async () => {
    setIsLoading(true); setError(null);
    try {
      if (activeTab === 'file') {
        if (!selectedFile) { setError('Please select a file'); setIsLoading(false); return; }
        const fd = new FormData(); fd.append('file', selectedFile);
        await handleResponse(await fetch('/api/analyze', { method: 'POST', body: fd }));

      } else if (activeTab === 'multi') {
        if (!multiFiles.length) { setError('Please select files'); setIsLoading(false); return; }
        const fd = new FormData();
        multiFiles.forEach(f => fd.append('files', f));
        await handleResponse(await fetch('/api/analyze-multi', { method: 'POST', body: fd }));

      } else if (activeTab === 'zip') {
        if (!zipFile) { setError('Please select a ZIP file'); setIsLoading(false); return; }
        const fd = new FormData(); fd.append('file', zipFile);
        await handleResponse(await fetch('/api/analyze-zip', { method: 'POST', body: fd }));

      } else if (activeTab === 'repo') {
        if (!repoUrl) { setError('Please enter a repository URL'); setIsLoading(false); return; }
        await handleResponse(await fetch('/api/analyze-repo', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: repoUrl }),
        }));

      } else if (activeTab === 'paste') {
        if (!pasteCode) { setError('Please enter code to analyze'); setIsLoading(false); return; }
        await handleResponse(await fetch('/api/analyze-text', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: pasteCode, language: pasteLanguage }),
        }));
      }
    } catch (e) {
      setError('Scan failed: ' + e.message);
    } finally {
      setIsLoading(false);
    }
  };

  if (analysisData) return (
    <div className="pb-20">
      <ResultsPanel data={analysisData} onReset={reset} />
    </div>
  );

  return (
    <div className="pb-20 max-w-3xl mx-auto">
      <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}>
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-primary/20 rounded-2xl mb-4">
            <SearchCode className="w-7 h-7 text-primary" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Scanner</h1>
          <p className="text-white/50">26 languages · SAST · Secret Detection · Dependency Analysis</p>
        </div>

        {/* Tab Selector */}
        <div className="flex gap-1 bg-white/5 border border-white/10 rounded-2xl p-1 mb-6 overflow-x-auto">
          {TAB_CONFIG.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all whitespace-nowrap flex-1 justify-center ${
                activeTab === id ? 'bg-primary text-white shadow-lg shadow-primary/20' : 'text-white/50 hover:text-white hover:bg-white/5'
              }`}
            >
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </div>

        {/* Drop Zone Wrapper */}
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`bg-white/5 border-2 border-dashed rounded-2xl p-6 transition-all ${dragOver ? 'border-primary bg-primary/10' : 'border-white/10'}`}
        >
          <AnimatePresence mode="wait">
            {/* Single File */}
            {activeTab === 'file' && (
              <motion.div key="file" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="text-center">
                  <Upload className="w-10 h-10 text-white/30 mx-auto mb-2" />
                  <p className="text-white/50 text-sm">Drop a file here or</p>
                </div>
                <input ref={fileInputRef} type="file" className="hidden"
                  accept=".py,.js,.jsx,.ts,.tsx,.java,.kt,.c,.cpp,.cs,.php,.rb,.go,.rs,.swift,.scala,.sql,.html,.css,.xml,.json,.yaml,.yml,.tf,.sh,.ps1,dockerfile"
                  onChange={e => setSelectedFile(e.target.files[0])} />
                <button onClick={() => fileInputRef.current?.click()}
                  className="w-full py-3 bg-white/10 hover:bg-white/15 border border-white/10 text-white rounded-xl text-sm font-medium transition-colors">
                  Browse File
                </button>
                {selectedFile && (
                  <div className="flex items-center gap-3 bg-primary/10 border border-primary/20 rounded-xl p-3">
                    <FileCode className="w-5 h-5 text-primary shrink-0" />
                    <span className="text-white text-sm flex-1 truncate">{selectedFile.name}</span>
                    <button onClick={() => setSelectedFile(null)}><X className="w-4 h-4 text-white/40" /></button>
                  </div>
                )}
              </motion.div>
            )}

            {/* Multi-File */}
            {activeTab === 'multi' && (
              <motion.div key="multi" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="text-center">
                  <FolderOpen className="w-10 h-10 text-white/30 mx-auto mb-2" />
                  <p className="text-white/50 text-sm">Select multiple files for bulk scanning</p>
                </div>
                <input ref={multiInputRef} type="file" multiple className="hidden"
                  onChange={e => setMultiFiles(Array.from(e.target.files))} />
                <button onClick={() => multiInputRef.current?.click()}
                  className="w-full py-3 bg-white/10 hover:bg-white/15 border border-white/10 text-white rounded-xl text-sm font-medium transition-colors">
                  Select Files
                </button>
                {multiFiles.length > 0 && (
                  <div className="bg-primary/10 border border-primary/20 rounded-xl p-3 max-h-40 overflow-y-auto space-y-1">
                    {multiFiles.map((f, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-white/70">
                        <FileCode className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="truncate">{f.name}</span>
                        <span className="ml-auto text-white/30 shrink-0">{(f.size / 1024).toFixed(0)}KB</span>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}

            {/* ZIP */}
            {activeTab === 'zip' && (
              <motion.div key="zip" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="text-center">
                  <Archive className="w-10 h-10 text-white/30 mx-auto mb-2" />
                  <p className="text-white/50 text-sm">Upload a ZIP or TAR archive of your project</p>
                </div>
                <input ref={zipInputRef} type="file" className="hidden"
                  accept=".zip,.tar,.tar.gz,.tgz"
                  onChange={e => setZipFile(e.target.files[0])} />
                <button onClick={() => zipInputRef.current?.click()}
                  className="w-full py-3 bg-white/10 hover:bg-white/15 border border-white/10 text-white rounded-xl text-sm font-medium transition-colors">
                  Browse Archive
                </button>
                {zipFile && (
                  <div className="flex items-center gap-3 bg-primary/10 border border-primary/20 rounded-xl p-3">
                    <Archive className="w-5 h-5 text-primary shrink-0" />
                    <span className="text-white text-sm flex-1 truncate">{zipFile.name}</span>
                    <button onClick={() => setZipFile(null)}><X className="w-4 h-4 text-white/40" /></button>
                  </div>
                )}
              </motion.div>
            )}

            {/* Repo */}
            {activeTab === 'repo' && (
              <motion.div key="repo" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="text-center">
                  <Globe className="w-10 h-10 text-white/30 mx-auto mb-2" />
                  <p className="text-white/50 text-sm">Scan a GitHub, GitLab, or Bitbucket repository</p>
                </div>
                <input
                  type="url"
                  value={repoUrl}
                  onChange={e => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/repo"
                  className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder-white/30 focus:outline-none focus:border-primary/50"
                />
                <p className="text-white/30 text-xs">Requires git to be installed. Only public repos supported.</p>
              </motion.div>
            )}

            {/* Paste */}
            {activeTab === 'paste' && (
              <motion.div key="paste" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="flex items-center gap-3">
                  <ClipboardPaste className="w-5 h-5 text-white/30" />
                  <select
                    value={pasteLanguage}
                    onChange={e => setPasteLanguage(e.target.value)}
                    className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none"
                  >
                    {LANGUAGES.map(l => <option key={l} value={l} className="bg-gray-900">{l}</option>)}
                  </select>
                </div>
                <textarea
                  value={pasteCode}
                  onChange={e => setPasteCode(e.target.value)}
                  placeholder="Paste your code here for instant analysis..."
                  className="w-full h-48 bg-black/30 border border-white/10 rounded-xl px-4 py-3 text-white/80 text-xs font-mono placeholder-white/20 focus:outline-none focus:border-primary/50 resize-none"
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Error */}
        {error && (
          <div className="mt-4 flex items-center gap-3 bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-400 text-sm">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            {error}
          </div>
        )}

        {/* Scan Button */}
        <motion.button
          onClick={runScan}
          disabled={isLoading}
          whileTap={{ scale: 0.98 }}
          className="mt-6 w-full py-4 bg-primary hover:bg-primary/90 disabled:opacity-50 text-white font-bold rounded-2xl shadow-lg shadow-primary/20 transition-all flex items-center justify-center gap-3 text-lg"
        >
          {isLoading ? (
            <><Loader2 className="w-5 h-5 animate-spin" /> Scanning for Vulnerabilities...</>
          ) : (
            <><SearchCode className="w-5 h-5" /> Run Security Scan</>
          )}
        </motion.button>

        <p className="text-center text-white/25 text-xs mt-4">
          SAST · Secret Detection · Dependency Analysis · OWASP Top 10
        </p>
      </motion.div>
    </div>
  );
}
