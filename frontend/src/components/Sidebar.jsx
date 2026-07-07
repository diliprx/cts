import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FolderKanban, FileBarChart, Settings, ShieldAlert, Zap, SearchCode } from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs) {
  return twMerge(clsx(inputs));
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Scan History', href: '/projects', icon: FolderKanban },
  { name: 'Quick Scan', href: '/scan', icon: SearchCode },
  { name: 'Reports', href: '/reports', icon: FileBarChart },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Sidebar() {
  return (
    <div className="flex flex-col w-64 bg-surface border-r border-border min-h-screen pt-6 pb-4">
      <div className="px-6 flex items-center gap-3 mb-10">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-purple-500 flex items-center justify-center shadow-lg shadow-primary/20">
          <ShieldAlert className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-textPrimary tracking-tight">CTS Security</h1>
          <p className="text-xs text-textSecondary font-medium">Secure Code Analysis</p>
        </div>
      </div>

      <nav className="flex-1 px-4 space-y-1.5">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                "group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-textSecondary hover:bg-secondary/10 hover:text-textPrimary"
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon className={cn("w-5 h-5 transition-colors", isActive ? "text-primary" : "text-textSecondary group-hover:text-textPrimary")} />
                {item.name}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="px-6 mt-auto">
        <div className="p-4 rounded-2xl bg-gradient-to-br from-secondary/10 to-transparent border border-secondary/20">
          <div className="flex items-center gap-2 text-primary font-bold mb-1">
            <Zap className="w-4 h-4 fill-primary" />
            <span>Pro Plan</span>
          </div>
          <p className="text-xs text-textSecondary font-medium mb-3">Unlimited AI Scans enabled.</p>
          <div className="w-full bg-border rounded-full h-1.5 overflow-hidden">
            <div className="bg-primary w-2/3 h-full rounded-full" />
          </div>
          <p className="text-[10px] text-textSecondary font-medium mt-2 text-right">6.5M LOC Analyzed</p>
        </div>
      </div>
    </div>
  );
}
