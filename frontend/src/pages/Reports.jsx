import React, { useEffect, useState } from 'react';
import { FileText, Download, Filter, ChevronRight, CheckCircle2, AlertTriangle, ShieldAlert, Loader2 } from 'lucide-react';

export default function Reports() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);

  useEffect(() => {
    fetch('/api/scan-history')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.history) {
          setHistory(data.history);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const formatExtensions = { pdf: 'pdf', html: 'html', csv: 'csv', json: 'json', markdown: 'md', txt: 'txt' };

  const handleDownload = async (scan, format) => {
    setDownloadingId(`${scan.id}-${format}`);
    try {
      const res = await fetch(`/api/report/${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          vulnerabilities: [
            {
              rule_id: 'HISTORICAL-SUMMARY',
              rule_name: `Summary for Scan: ${scan.source}`,
              category: 'Summary',
              severity: scan.critical > 0 ? 'Critical' : 'High',
              file_path: scan.source,
              line_number: 1,
              code_snippet: `Scan Summary: ${scan.total} total issues found with security score of ${scan.score}%`,
              description: `This is a summary record for scan operation: ${scan.source} executed on ${scan.timestamp}.`,
              remediation: 'Review full reports by conducting a fresh scan via the Quick Scan tab.',
            }
          ]
        }),
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_report_${scan.id}.${formatExtensions[format] || format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      console.error(e);
    } finally {
      setDownloadingId(null);
    }
  };

  const getRiskLevel = (scan) => {
    if (scan.critical > 0) return 'Critical';
    if (scan.high > 0) return 'High';
    if (scan.total > 0) return 'Medium';
    return 'Low';
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-textPrimary tracking-tight">Compliance & Reports</h1>
          <p className="text-textSecondary mt-1">Generate and review executive security summaries.</p>
        </div>
      </div>

      <div className="surface rounded-2xl border border-border overflow-hidden">
        <div className="grid grid-cols-6 gap-4 p-4 border-b border-border/50 bg-[#1C1C1E] text-xs font-bold text-textSecondary uppercase tracking-wider">
          <div className="col-span-2">Report ID / Project</div>
          <div>Date</div>
          <div>Scan Type</div>
          <div>Risk Level</div>
          <div>Action</div>
        </div>
        
        <div className="divide-y divide-border/30">
          {loading ? (
            <div className="p-8 text-center text-textSecondary">
              <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
              Loading history...
            </div>
          ) : history.length === 0 ? (
            <div className="p-8 text-center text-textSecondary">
              No reports generated yet. Start a scan to create reports.
            </div>
          ) : (
            history.map((scan) => {
              const risk = getRiskLevel(scan);
              const dateStr = new Date(scan.timestamp).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
              });
              return (
                <div key={scan.id} className="grid grid-cols-6 gap-4 p-4 items-center hover:bg-white/5 transition-colors group cursor-pointer">
                  <div className="col-span-2 flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <FileText className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <div className="font-bold text-textPrimary">REP-{scan.id}</div>
                      <div className="text-xs text-textSecondary font-medium truncate max-w-[200px]">{scan.source}</div>
                    </div>
                  </div>
                  
                  <div className="text-sm text-textSecondary font-medium">{dateStr}</div>
                  
                  <div className="text-sm text-textPrimary font-medium">
                    <span className="px-2.5 py-1 rounded-md bg-secondary/10 text-secondary text-xs capitalize">
                      {scan.scan_type.replace('_', ' ')}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {risk === 'Critical' || risk === 'High' ? <ShieldAlert className="w-4 h-4 text-error" /> : 
                     risk === 'Medium' ? <AlertTriangle className="w-4 h-4 text-warning" /> : 
                     <CheckCircle2 className="w-4 h-4 text-success" />}
                    <span className={`text-sm font-bold ${
                      risk === 'Critical' || risk === 'High' ? 'text-error' : 
                      risk === 'Medium' ? 'text-warning' : 'text-success'
                    }`}>{risk}</span>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {['pdf', 'html', 'csv', 'markdown', 'txt', 'json'].map(fmt => (
                      <button 
                        key={fmt}
                        disabled={downloadingId === `${scan.id}-${fmt}`}
                        onClick={() => handleDownload(scan, fmt)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-white/5 hover:bg-white/10 text-textSecondary hover:text-textPrimary rounded border border-border/50 disabled:opacity-50"
                      >
                        {downloadingId === `${scan.id}-${fmt}` ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <Download className="w-3 h-3" />
                        )}
                        <span className="uppercase text-[9px]">{fmt}</span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
