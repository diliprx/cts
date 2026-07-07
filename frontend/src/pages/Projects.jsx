import React, { useEffect, useState } from 'react';
import { FolderGit2, Search, MoreVertical, ShieldAlert, GitPullRequest, Code2, Trash2, RefreshCw, Loader2, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const STATUS_CONFIG = {
  Critical: { color: 'text-red-500', bg: 'bg-red-500/10 border-red-500/20', dot: 'bg-red-500' },
  High: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20', dot: 'bg-orange-400' },
  Medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20', dot: 'bg-yellow-400' },
  Low: { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
  Clean: { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
};

function getStatus(scan) {
  if (scan.critical > 0) return 'Critical';
  if ((scan.high || 0) > 0) return 'High';
  if (scan.total > 0) return 'Medium';
  return 'Clean';
}

function timeAgo(timestamp) {
  try {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  } catch {
    return '';
  }
}

const SCAN_TYPE_LABELS = {
  single_file: 'Single File',
  multi_file: 'Multi File',
  zip: 'ZIP Archive',
  repository: 'Repository',
  text: 'Code Snippet',
};

export default function Projects() {
  const navigate = useNavigate();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [clearing, setClearing] = useState(false);

  const fetchHistory = () => {
    setLoading(true);
    fetch('/api/scan-history')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.history) setHistory(data.history);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchHistory(); }, []);

  const handleClearHistory = async () => {
    if (!window.confirm('Clear all scan history? This cannot be undone.')) return;
    setClearing(true);
    try {
      await fetch('/api/scan-history', { method: 'DELETE' });
      setHistory([]);
    } finally {
      setClearing(false);
    }
  };

  const filtered = history.filter(h =>
    !searchQuery ||
    h.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
    h.scan_type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold text-textPrimary tracking-tight">Scan History</h1>
          <p className="text-textSecondary mt-1">All past security scans and their results.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchHistory}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-primary/10 text-primary hover:bg-primary/20 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {history.length > 0 && (
            <button
              onClick={handleClearHistory}
              disabled={clearing}
              className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-xl text-sm font-semibold transition-colors border border-red-500/20 disabled:opacity-50"
            >
              <Trash2 className="w-4 h-4" />
              {clearing ? 'Clearing...' : 'Clear All'}
            </button>
          )}
          <button
            onClick={() => navigate('/scan')}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-xl text-sm font-semibold shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
          >
            <ShieldAlert className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="flex items-center gap-4 bg-surface border border-border rounded-xl p-2 px-4 shadow-inner">
        <Search className="w-5 h-5 text-textSecondary" />
        <input
          type="text"
          placeholder="Search by source or scan type..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="flex-1 bg-transparent border-none outline-none text-textPrimary placeholder:text-textSecondary/50 text-sm py-2"
        />
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-20 text-textSecondary">
          <Loader2 className="w-8 h-8 animate-spin mb-3 text-primary" />
          <p>Loading scan history...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center bg-surface border border-border rounded-2xl">
          <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8 text-primary" />
          </div>
          <h3 className="text-xl font-bold text-textPrimary mb-2">
            {searchQuery ? 'No results found' : 'No Scans Yet'}
          </h3>
          <p className="text-textSecondary text-sm mb-6 max-w-sm">
            {searchQuery
              ? 'Try a different search term.'
              : 'Run your first security scan to see results here. Supports files, folders, ZIP archives, repositories, and code snippets.'}
          </p>
          {!searchQuery && (
            <button
              onClick={() => navigate('/scan')}
              className="flex items-center gap-2 px-6 py-3 bg-primary text-white rounded-xl font-semibold shadow-lg shadow-primary/20 hover:scale-[1.02] transition-all"
            >
              <ShieldAlert className="w-4 h-4" />
              Start First Scan
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtered.map(scan => {
            const status = getStatus(scan);
            const cfg = STATUS_CONFIG[status];
            const label = SCAN_TYPE_LABELS[scan.scan_type] || scan.scan_type;
            return (
              <div
                key={scan.id}
                className="surface rounded-2xl border border-border p-6 hover:border-primary/50 transition-all duration-200 group cursor-pointer relative overflow-hidden"
                onClick={() => navigate('/scan')}
              >
                {/* Top accent bar */}
                <div className={`absolute top-0 left-0 w-full h-1 rounded-t-2xl bg-gradient-to-r from-primary to-purple-500 opacity-0 group-hover:opacity-100 transition-opacity`} />

                <div className="flex justify-between items-start mb-4">
                  <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                    <FolderGit2 className="w-6 h-6 text-primary" />
                  </div>
                  <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${cfg.bg} ${cfg.color}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                    {status}
                  </div>
                </div>

                <h3 className="text-base font-bold text-textPrimary mb-1 truncate">{scan.source}</h3>

                <p className="text-sm text-textSecondary flex items-center gap-2 mb-5">
                  <Code2 className="w-4 h-4 shrink-0" />
                  <span className="px-2 py-0.5 bg-primary/10 text-primary text-xs rounded-md font-semibold">{label}</span>
                </p>

                {/* Score bar */}
                <div className="mb-4">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-textSecondary font-medium">Security Score</span>
                    <span className={`font-bold ${scan.score >= 80 ? 'text-green-400' : scan.score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>{scan.score}/100</span>
                  </div>
                  <div className="w-full h-1.5 bg-border rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${scan.score >= 80 ? 'bg-green-400' : scan.score >= 60 ? 'bg-yellow-400' : 'bg-red-500'}`}
                      style={{ width: `${scan.score}%` }}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-border/50">
                  <div className="flex items-center gap-3 text-xs text-textSecondary">
                    <div className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                      <span>{scan.critical || 0} Critical</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-orange-400" />
                      <span>{scan.high || 0} High</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-textSecondary font-medium">
                    <GitPullRequest className="w-3.5 h-3.5" />
                    {timeAgo(scan.timestamp)}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
