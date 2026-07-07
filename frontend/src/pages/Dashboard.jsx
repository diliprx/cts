import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, Info, CheckCircle, Search, UploadCloud, GitBranch } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
  const navigate = useNavigate();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

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

  // Compute stats from scan history
  const totalScans = history.length;
  const latestScan = history[0] || null;
  const avgScore = totalScans > 0 ? Math.round(history.reduce((acc, h) => acc + h.score, 0) / totalScans) : 100;
  const totalIssuesFound = history.reduce((acc, h) => acc + h.total, 0);
  const totalCritical = history.reduce((acc, h) => acc + (h.critical || 0), 0);
  const totalHigh = history.reduce((acc, h) => acc + (h.high || 0), 0);

  // Map average score to Grade
  const getGrade = (score) => {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  };

  const currentGrade = getGrade(avgScore);

  const severityData = [
    { name: 'Critical', value: totalCritical, color: '#FF3B30' },
    { name: 'High', value: totalHigh, color: '#FF9500' },
    { name: 'Medium', value: history.reduce((acc, h) => acc + (h.medium || 0), 0), color: '#FFCC00' },
    { name: 'Low', value: history.reduce((acc, h) => acc + (h.low || 0), 0), color: '#34C759' },
  ];

  // Map history to trend data (up to last 7 scans)
  const trendData = [...history].reverse().slice(-7).map((h, i) => ({
    name: h.source.substring(0, 8) + (h.source.length > 8 ? '..' : ''),
    critical: h.critical || 0,
    high: h.high || 0,
    medium: h.medium || 0,
  }));

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-textPrimary tracking-tight">Security Overview</h1>
          <p className="text-textSecondary mt-1">Enterprise-wide vulnerability posture and trends.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => navigate('/scan')}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-xl text-sm font-semibold shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
          >
            <UploadCloud className="w-4 h-4" /> Start New Scan
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="surface p-6 rounded-2xl border border-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-textSecondary font-medium">Avg Security Score</h3>
            <ShieldAlert className="w-5 h-5 text-primary" />
          </div>
          <div className="text-4xl font-bold text-textPrimary mb-2">{avgScore}/100</div>
          <p className="text-sm text-success flex items-center gap-1">
            <CheckCircle className="w-4 h-4" /> Grade: {currentGrade}
          </p>
        </div>

        <div className="surface p-6 rounded-2xl border border-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-textSecondary font-medium">Total Critical</h3>
            <AlertTriangle className="w-5 h-5 text-error" />
          </div>
          <div className="text-4xl font-bold text-error mb-2">{totalCritical}</div>
          <p className="text-sm text-textSecondary flex items-center gap-1">
            Across {totalScans} scan cycles
          </p>
        </div>

        <div className="surface p-6 rounded-2xl border border-border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-textSecondary font-medium">Open Findings</h3>
            <Info className="w-5 h-5 text-warning" />
          </div>
          <div className="text-4xl font-bold text-textPrimary mb-2">{totalIssuesFound}</div>
          <p className="text-sm text-textSecondary flex items-center gap-1">
            {totalScans > 0 ? `Latest: ${latestScan ? latestScan.total : 0} issues` : 'No scans performed'}
          </p>
        </div>

        <div className="surface p-6 rounded-2xl border border-border bg-gradient-to-br from-primary/10 to-transparent">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-textSecondary font-medium">Total Scan Operations</h3>
            <Search className="w-5 h-5 text-primary" />
          </div>
          <div className="text-4xl font-bold text-textPrimary mb-2">{totalScans}</div>
          <p className="text-sm text-textSecondary flex items-center gap-1">
            SAST, Dependency, and Secrets
          </p>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="lg:col-span-2 surface p-6 rounded-2xl border border-border">
          <h3 className="text-lg font-bold text-textPrimary mb-6">Vulnerability Trends (Recent Scans)</h3>
          <div className="h-72">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF3B30" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#FF3B30" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF9500" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#FF9500" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                  <XAxis dataKey="name" stroke="#666" tick={{fill: '#888'}} axisLine={false} tickLine={false} />
                  <YAxis stroke="#666" tick={{fill: '#888'}} axisLine={false} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1C1C1E', borderColor: '#333', borderRadius: '12px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Area type="monotone" dataKey="critical" stroke="#FF3B30" strokeWidth={3} fillOpacity={1} fill="url(#colorCritical)" />
                  <Area type="monotone" dataKey="high" stroke="#FF9500" strokeWidth={3} fillOpacity={1} fill="url(#colorHigh)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-textSecondary text-sm">
                No scan trend data available. Start a scan to view graphs.
              </div>
            )}
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="surface p-6 rounded-2xl border border-border">
          <h3 className="text-lg font-bold text-textPrimary mb-6">Severity Breakdown</h3>
          <div className="h-72">
            {totalIssuesFound > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} layout="vertical" margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={true} vertical={false} />
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{fill: '#888', fontWeight: 600}} width={70} />
                  <Tooltip 
                    cursor={{fill: 'rgba(255,255,255,0.05)'}}
                    contentStyle={{ backgroundColor: '#1C1C1E', borderColor: '#333', borderRadius: '12px' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-textSecondary text-sm">
                No issues found yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
