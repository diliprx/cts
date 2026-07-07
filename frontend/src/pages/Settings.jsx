import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon, Shield, Key, Bell, Palette, Code2, Download,
  Save, RefreshCw, CheckCircle, AlertTriangle, Info, Loader2, Trash2,
  Eye, EyeOff, Globe, Lock, Zap, Database, FileText,
} from 'lucide-react';

function Section({ title, icon: Icon, description, children }) {
  return (
    <div className="surface rounded-2xl border border-border overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-border/60 bg-primary/5">
        <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h2 className="text-base font-bold text-textPrimary">{title}</h2>
          {description && <p className="text-xs text-textSecondary mt-0.5">{description}</p>}
        </div>
      </div>
      <div className="p-6 space-y-5">{children}</div>
    </div>
  );
}

function ToggleRow({ label, description, value, onChange }) {
  return (
    <div className="flex items-center justify-between py-1">
      <div>
        <div className="text-sm font-semibold text-textPrimary">{label}</div>
        {description && <div className="text-xs text-textSecondary mt-0.5">{description}</div>}
      </div>
      <button
        onClick={() => onChange(!value)}
        className={`relative w-12 h-6 rounded-full transition-colors duration-200 ${value ? 'bg-primary' : 'bg-border'}`}
      >
        <span
          className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${value ? 'left-7' : 'left-1'}`}
        />
      </button>
    </div>
  );
}

function Field({ label, description, children }) {
  return (
    <div>
      <label className="block text-sm font-semibold text-textPrimary mb-1">{label}</label>
      {description && <p className="text-xs text-textSecondary mb-2">{description}</p>}
      {children}
    </div>
  );
}

function inputCls() {
  return 'w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-textPrimary placeholder:text-textSecondary/50 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary transition';
}

const DEFAULT_SETTINGS = {
  // Scanning
  enable_multi_line: true,
  enable_secret_detection: true,
  enable_dependency_scan: true,
  enable_sast: true,
  scan_binary_files: false,
  max_file_size_mb: 10,

  // Severity thresholds
  fail_on_critical: true,
  fail_on_high: false,
  severity_threshold: 'Low',

  // Report
  default_report_format: 'html',
  include_code_snippets: true,
  include_remediation: true,

  // Notifications
  notify_on_critical: true,
  notify_on_scan_complete: false,

  // API
  gemini_api_key: '',
  github_token: '',

  // UI
  theme: 'dark',
  items_per_page: 25,
};

export default function Settings() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [showGithubToken, setShowGithubToken] = useState(false);
  const [rules, setRules] = useState([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [clearingHistory, setClearingHistory] = useState(false);
  const [health, setHealth] = useState(null);

  // Load from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('cts_settings');
    if (saved) {
      try { setSettings(s => ({ ...s, ...JSON.parse(saved) })); } catch {}
    }
    // Load health + rules count + history count
    fetch('/api/health').then(r => r.json()).then(setHealth).catch(() => {});
    fetchRulesCount();
    fetchHistoryCount();
  }, []);

  const fetchRulesCount = () => {
    setRulesLoading(true);
    fetch('/api/rules').then(r => r.json()).then(d => {
      if (d.success) setRules(d.rules || []);
      setRulesLoading(false);
    }).catch(() => setRulesLoading(false));
  };

  const fetchHistoryCount = () => {
    setHistoryLoading(true);
    fetch('/api/scan-history').then(r => r.json()).then(d => {
      if (d.success) setHistory(d.history || []);
      setHistoryLoading(false);
    }).catch(() => setHistoryLoading(false));
  };

  const set = (key, value) => setSettings(s => ({ ...s, [key]: value }));

  const handleSave = () => {
    localStorage.setItem('cts_settings', JSON.stringify(settings));
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Clear all scan history? This cannot be undone.')) return;
    setClearingHistory(true);
    try {
      await fetch('/api/scan-history', { method: 'DELETE' });
      setHistory([]);
    } finally {
      setClearingHistory(false);
    }
  };

  // Group rules by language
  const rulesByLang = {};
  rules.forEach(r => {
    r.languages.forEach(lang => {
      if (!rulesByLang[lang]) rulesByLang[lang] = 0;
      rulesByLang[lang]++;
    });
  });
  const topLangs = Object.entries(rulesByLang).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold text-textPrimary tracking-tight">Settings</h1>
          <p className="text-textSecondary mt-1">Configure scan behavior, integrations, and preferences.</p>
        </div>
        <button
          onClick={handleSave}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold shadow-lg transition-all ${saved ? 'bg-green-500 text-white' : 'bg-primary text-white hover:scale-[1.02] shadow-primary/20'}`}
        >
          {saved ? <><CheckCircle className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save Settings</>}
        </button>
      </div>

      {/* Platform Status */}
      {health && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-4 flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-green-400 rounded-full animate-pulse" />
            <span className="text-green-400 font-semibold text-sm">Platform Online</span>
          </div>
          <div className="flex gap-4 flex-wrap text-xs text-textSecondary">
            <span>v{health.version}</span>
            <span>·</span>
            <span>{health.features?.languages_supported} Languages</span>
            <span>·</span>
            <span>{rules.length} SAST Rules{rulesLoading && <Loader2 className="inline w-3 h-3 ml-1 animate-spin" />}</span>
            <span>·</span>
            <span>Gemini AI: {health.gemini_available ? '✅ Available' : '❌ Not configured'}</span>
          </div>
        </div>
      )}

      {/* SAST & Scanning */}
      <Section title="SAST & Scanning" icon={Shield} description="Configure what the scanner checks and how deeply it analyzes code.">
        <ToggleRow
          label="Enable SAST Analysis"
          description="Pattern-based static analysis for OWASP Top 10 and language-specific vulnerabilities."
          value={settings.enable_sast}
          onChange={v => set('enable_sast', v)}
        />
        <ToggleRow
          label="Multi-Line Pattern Matching"
          description="Detect vulnerabilities that span multiple lines (slower but more thorough)."
          value={settings.enable_multi_line}
          onChange={v => set('enable_multi_line', v)}
        />
        <ToggleRow
          label="Secret Detection"
          description="Scan for hardcoded API keys, tokens, passwords, and certificates."
          value={settings.enable_secret_detection}
          onChange={v => set('enable_secret_detection', v)}
        />
        <ToggleRow
          label="Dependency Vulnerability Scan"
          description="Analyze package manifests (package.json, requirements.txt, go.mod, Cargo.toml) for vulnerable versions."
          value={settings.enable_dependency_scan}
          onChange={v => set('enable_dependency_scan', v)}
        />
        <div className="pt-2 border-t border-border/50">
          <Field label="Maximum File Size (MB)" description="Files larger than this limit will be skipped during scanning.">
            <input
              type="number"
              min={1}
              max={200}
              value={settings.max_file_size_mb}
              onChange={e => set('max_file_size_mb', Number(e.target.value))}
              className={inputCls()}
            />
          </Field>
        </div>
      </Section>

      {/* Severity & Thresholds */}
      <Section title="Severity & Thresholds" icon={AlertTriangle} description="Set when scans should fail and what minimum severity to report.">
        <ToggleRow
          label="Fail Scan on Critical Findings"
          description="Mark scan as failed if any Critical severity issues are detected."
          value={settings.fail_on_critical}
          onChange={v => set('fail_on_critical', v)}
        />
        <ToggleRow
          label="Fail Scan on High Findings"
          description="Mark scan as failed if any High severity issues are detected."
          value={settings.fail_on_high}
          onChange={v => set('fail_on_high', v)}
        />
        <Field label="Minimum Severity to Report" description="Only report findings at or above this severity level.">
          <select
            value={settings.severity_threshold}
            onChange={e => set('severity_threshold', e.target.value)}
            className={inputCls()}
          >
            <option value="Low">Low (report all)</option>
            <option value="Medium">Medium and above</option>
            <option value="High">High and above</option>
            <option value="Critical">Critical only</option>
          </select>
        </Field>
      </Section>

      {/* Report Settings */}
      <Section title="Report Settings" icon={FileText} description="Control report generation defaults and content.">
        <Field label="Default Report Format" description="Format used when downloading reports from the Reports page.">
          <select
            value={settings.default_report_format}
            onChange={e => set('default_report_format', e.target.value)}
            className={inputCls()}
          >
            <option value="html">HTML (Best for sharing)</option>
            <option value="pdf">PDF (Best for printing)</option>
            <option value="json">JSON (Machine-readable)</option>
            <option value="csv">CSV (Spreadsheet)</option>
            <option value="markdown">Markdown (Developer-friendly)</option>
            <option value="txt">Plain Text</option>
          </select>
        </Field>
        <ToggleRow
          label="Include Code Snippets"
          description="Show vulnerable code snippets in reports (may increase file size)."
          value={settings.include_code_snippets}
          onChange={v => set('include_code_snippets', v)}
        />
        <ToggleRow
          label="Include Remediation Guidance"
          description="Add specific fix recommendations for each finding in reports."
          value={settings.include_remediation}
          onChange={v => set('include_remediation', v)}
        />
      </Section>

      {/* API Keys */}
      <Section title="API Integrations" icon={Key} description="Configure external service integrations and API keys.">
        <Field label="Gemini API Key" description="Used for AI-powered fix suggestions. Get yours at aistudio.google.com.">
          <div className="relative">
            <input
              type={showApiKey ? 'text' : 'password'}
              value={settings.gemini_api_key}
              onChange={e => set('gemini_api_key', e.target.value)}
              placeholder="AIza..."
              className={inputCls() + ' pr-10'}
            />
            <button
              type="button"
              onClick={() => setShowApiKey(!showApiKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-textSecondary hover:text-textPrimary transition-colors"
            >
              {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </Field>
        <Field label="GitHub Personal Access Token" description="Enables scanning of private GitHub repositories. Requires 'repo' scope.">
          <div className="relative">
            <input
              type={showGithubToken ? 'text' : 'password'}
              value={settings.github_token}
              onChange={e => set('github_token', e.target.value)}
              placeholder="ghp_..."
              className={inputCls() + ' pr-10'}
            />
            <button
              type="button"
              onClick={() => setShowGithubToken(!showGithubToken)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-textSecondary hover:text-textPrimary transition-colors"
            >
              {showGithubToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </Field>
        <div className="bg-primary/5 border border-primary/20 rounded-xl p-3 text-xs text-textSecondary">
          <Info className="w-4 h-4 inline mr-1 text-primary" />
          API keys are stored in your browser&apos;s local storage and never sent to external servers.
        </div>
      </Section>

      {/* SAST Rule Coverage */}
      <Section title="SAST Rule Coverage" icon={Code2} description="Current detection rules loaded in the analysis engine.">
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-primary/5 border border-primary/10 rounded-xl p-4 text-center">
            <div className="text-3xl font-bold text-primary mb-1">
              {rulesLoading ? <Loader2 className="w-6 h-6 animate-spin mx-auto" /> : rules.length}
            </div>
            <div className="text-xs text-textSecondary font-medium">Total SAST Rules</div>
          </div>
          <div className="bg-green-500/5 border border-green-500/20 rounded-xl p-4 text-center">
            <div className="text-3xl font-bold text-green-400 mb-1">26</div>
            <div className="text-xs text-textSecondary font-medium">Languages Supported</div>
          </div>
        </div>
        {topLangs.length > 0 && (
          <div>
            <p className="text-xs text-textSecondary font-semibold uppercase tracking-wide mb-3">Rules by Language</p>
            <div className="space-y-2">
              {topLangs.map(([lang, count]) => (
                <div key={lang} className="flex items-center gap-3">
                  <span className="text-xs font-medium text-textSecondary w-20 truncate capitalize">{lang}</span>
                  <div className="flex-1 h-1.5 bg-border rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full"
                      style={{ width: `${Math.min((count / Math.max(...topLangs.map(l => l[1]))) * 100, 100)}%` }}
                    />
                  </div>
                  <span className="text-xs text-textSecondary w-8 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* Scan History Management */}
      <Section title="Data Management" icon={Database} description="Manage local scan history and cached data.">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-textPrimary">Scan History Records</div>
            <div className="text-xs text-textSecondary mt-0.5">
              {historyLoading
                ? 'Loading...'
                : `${history.length} scan record${history.length !== 1 ? 's' : ''} stored locally`}
            </div>
          </div>
          <button
            onClick={handleClearHistory}
            disabled={clearingHistory || history.length === 0}
            className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-xl text-sm font-semibold border border-red-500/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {clearingHistory ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            Clear History
          </button>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-xs text-yellow-400">
          <AlertTriangle className="w-4 h-4 inline mr-1" />
          Scan history is stored in a local JSON file on the server. It is not backed up automatically.
        </div>
      </Section>

      {/* Platform Info */}
      <Section title="Platform Information" icon={Info} description="Version and capability details.">
        <div className="grid grid-cols-2 gap-3 text-sm">
          {[
            ['Platform', 'CTS Secure Code Analyzer'],
            ['Version', health?.version || '3.0'],
            ['SAST Engine', 'Multi-language OWASP v3'],
            ['Secret Detection', '25+ pattern categories'],
            ['Dependency Scanner', 'npm, pip, go, cargo'],
            ['Report Formats', 'HTML, PDF, JSON, CSV, MD, TXT'],
            ['Repo Support', 'GitHub, GitLab, Bitbucket'],
            ['AI Fix Engine', health?.gemini_available ? 'Gemini (Active)' : 'Gemini (Needs Key)'],
          ].map(([label, val]) => (
            <div key={label} className="bg-background/50 border border-border/50 rounded-xl p-3">
              <div className="text-xs text-textSecondary mb-1">{label}</div>
              <div className="font-semibold text-textPrimary text-xs">{val}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* Save Button at bottom */}
      <div className="flex justify-end pt-2 pb-8">
        <button
          onClick={handleSave}
          className={`flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-bold shadow-lg transition-all ${saved ? 'bg-green-500 text-white' : 'bg-primary text-white hover:scale-[1.02] shadow-primary/20'}`}
        >
          {saved ? <><CheckCircle className="w-4 h-4" /> Settings Saved!</> : <><Save className="w-4 h-4" /> Save All Settings</>}
        </button>
      </div>
    </div>
  );
}
