import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Shield, ShieldCheck, Activity } from 'lucide-react';

export default function DashboardStats({ stats, score }) {
  const getScoreColor = (s) => {
    if (s >= 80) return 'text-success';
    if (s >= 60) return 'text-warning';
    return 'text-error';
  };

  const getScoreRing = (s) => {
    if (s >= 80) return 'border-success/30';
    if (s >= 60) return 'border-warning/30';
    return 'border-error/30';
  };

  const cards = [
    { label: 'Total Issues', value: stats.total, color: 'text-textPrimary', icon: <Activity className="w-5 h-5" /> },
    { label: 'Critical', value: stats.by_severity.Critical, color: 'text-error', icon: <ShieldAlert className="w-5 h-5 text-error" /> },
    { label: 'High', value: stats.by_severity.High, color: 'text-warning', icon: <ShieldAlert className="w-5 h-5 text-warning" /> },
    { label: 'Medium', value: stats.by_severity.Medium, color: 'text-warning', icon: <Shield className="w-5 h-5 text-warning" /> },
    { label: 'Low', value: stats.by_severity.Low, color: 'text-primary', icon: <ShieldCheck className="w-5 h-5 text-primary" /> },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {/* Score Card */}
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.1 }}
        className="md:col-span-1 elevated rounded-3xl p-8 flex flex-col items-center justify-center text-center relative overflow-hidden"
      >
        <div className={`w-32 h-32 rounded-full border-[6px] ${getScoreRing(score)} flex items-center justify-center mb-4 relative`}>
          <span className={`text-5xl font-bold tracking-tighter ${getScoreColor(score)}`}>
            {score}
          </span>
        </div>
        <h3 className="text-lg font-semibold text-textSecondary">Security Score</h3>
      </motion.div>

      {/* Stats Grid */}
      <div className="md:col-span-2 grid grid-cols-2 md:grid-cols-3 gap-4">
        {cards.map((card, idx) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 + (idx * 0.05) }}
            className="surface rounded-3xl p-6 flex flex-col justify-between"
          >
            <div className="flex justify-between items-start mb-4">
              <span className="text-sm font-semibold uppercase tracking-wider text-textSecondary">{card.label}</span>
              {card.icon}
            </div>
            <div className={`text-4xl font-bold ${card.color}`}>
              {card.value}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
