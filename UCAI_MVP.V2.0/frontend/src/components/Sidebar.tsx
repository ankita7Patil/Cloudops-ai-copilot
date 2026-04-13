import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Cpu, Settings, Activity, FolderOpen, Terminal } from 'lucide-react'

export default function Sidebar() {
  const links = [
    { to: '/dashboard', label: 'Overview', icon: <LayoutDashboard size={20} />, end: true },
    { to: '/dashboard/projects', label: 'GCP Projects', icon: <FolderOpen size={20} /> },
    { to: '/dashboard/command-center', label: 'Command Center', icon: <Terminal size={20} /> },
    { to: '/dashboard/incidents', label: 'Threats', icon: <ShieldAlert size={20} /> },
    { to: '/dashboard/finops', label: 'FinOps', icon: <Activity size={20} /> },
  ]

  return (
    <aside className="w-64 bg-[#05080E] border-r border-white/5 hidden md:flex flex-col z-10 relative shadow-2xl">
      <div className="h-16 flex items-center px-6 border-b border-white/5">
        <h1 className="text-xl font-bold tracking-wider text-white flex items-center gap-2">
          <Cpu className="text-blue-500" />
          <span className="neon-text-blue">UACI</span> MVP
        </h1>
      </div>

      <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all duration-200 font-medium text-sm ` +
              (isActive
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20 shadow-[0_0_10px_rgba(59,130,246,0.08)]'
                : 'text-gray-400 hover:bg-white/5 hover:text-gray-100')
            }
          >
            {link.icon}
            {link.label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-white/5">
        <NavLink
          to="/dashboard/profile"
          className={({ isActive }) =>
            `flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all duration-200 font-medium text-sm ` +
            (isActive
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
              : 'text-gray-400 hover:bg-white/5 hover:text-gray-100')
          }
        >
          <Settings size={20} />
          Settings
        </NavLink>
      </div>
    </aside>
  )
}
