import { Bell, Search, X, ShieldAlert, DollarSign, Zap, Info } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../AuthContext'

const NOTIFICATIONS = [
  { id: 1, type: 'critical', icon: <ShieldAlert size={16} className="text-red-400"/>, title: 'IAM Role Over-privileged', desc: 'service-account@project.iam has roles/owner — should be least-privilege.', time: '2 min ago', unread: true },
  { id: 2, type: 'warning', icon: <DollarSign size={16} className="text-orange-400"/>, title: 'Billing Spike Detected', desc: 'Cloud SQL spend +45% above 7-day average. Agent recommends resize.', time: '18 min ago', unread: true },
  { id: 3, type: 'info', icon: <Zap size={16} className="text-blue-400"/>, title: 'Autonomous Action Completed', desc: 'GKE node pool autoscaling adjusted successfully. MTTR reduced by 18%.', time: '1 hr ago', unread: false },
  { id: 4, type: 'info', icon: <Info size={16} className="text-gray-400"/>, title: 'Health Score Updated', desc: 'Environment health score moved from 84 → 91 after patching.', time: '3 hr ago', unread: false },
]

export default function Topbar() {
  const { user } = useAuth()
  const [open, setOpen] = useState(false)
  const [notes, setNotes] = useState(NOTIFICATIONS)
  const ref = useRef<HTMLDivElement>(null)
  const unreadCount = notes.filter(n => n.unread).length

  // Close panel on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const markAllRead = () => setNotes(prev => prev.map(n => ({ ...n, unread: false })))
  const dismiss = (id: number) => setNotes(prev => prev.filter(n => n.id !== id))

  const initial = user?.email?.charAt(0).toUpperCase() || 'A'

  return (
    <header className="h-16 border-b border-white/5 bg-[#05080E]/80 backdrop-blur-lg flex items-center justify-between px-8 sticky top-0 z-20">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-64 group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-blue-400 transition-colors" size={18} />
          <input
            type="text"
            placeholder="Search telemetry..."
            className="w-full bg-[#111827] border border-white/5 rounded-full py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 text-gray-200 transition-all placeholder:text-gray-600"
          />
        </div>
      </div>

      <div className="flex items-center gap-6">
        {/* Notification Bell */}
        <div className="relative" ref={ref}>
          <button
            onClick={() => setOpen(prev => !prev)}
            className="relative text-gray-400 hover:text-white transition-colors p-1"
          >
            <Bell size={20} className={open ? 'text-white' : ''} />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full border-2 border-[#05080E] flex items-center justify-center">
                {unreadCount}
              </span>
            )}
          </button>

          {/* Dropdown Panel */}
          {open && (
            <div className="absolute right-0 top-12 w-96 bg-[#0D1117] border border-white/10 rounded-2xl shadow-2xl shadow-black/60 z-50 overflow-hidden animate-fade-in">
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-white/5 bg-white/[0.02]">
                <div>
                  <h3 className="text-sm font-bold text-white">Notifications</h3>
                  <p className="text-xs text-gray-500 mt-0.5">{unreadCount} unread alerts</p>
                </div>
                <button onClick={markAllRead} className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors">
                  Mark all read
                </button>
              </div>

              {/* Items */}
              <div className="max-h-80 overflow-y-auto divide-y divide-white/5">
                {notes.length === 0 && (
                  <div className="px-5 py-10 text-center text-sm text-gray-500">All caught up! No active alerts.</div>
                )}
                {notes.map(n => (
                  <div key={n.id} className={`flex gap-3 px-5 py-4 hover:bg-white/5 transition-colors group relative ${n.unread ? 'bg-blue-500/[0.03]' : ''}`}>
                    <div className={`mt-0.5 p-2 rounded-lg shrink-0 ${
                      n.type === 'critical' ? 'bg-red-500/10' :
                      n.type === 'warning' ? 'bg-orange-500/10' : 'bg-white/5'
                    }`}>
                      {n.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-semibold text-gray-100 leading-tight">{n.title}</p>
                        {n.unread && <span className="w-2 h-2 bg-blue-500 rounded-full shrink-0 mt-1.5" />}
                      </div>
                      <p className="text-xs text-gray-400 mt-1 leading-relaxed">{n.desc}</p>
                      <p className="text-[10px] text-gray-600 mt-1.5">{n.time}</p>
                    </div>
                    <button
                      onClick={() => dismiss(n.id)}
                      className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity text-gray-600 hover:text-gray-300"
                    >
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </div>

              {/* Footer */}
              <div className="px-5 py-3 border-t border-white/5 bg-white/[0.02]">
                <Link to="/dashboard/incidents" onClick={() => setOpen(false)} className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors flex items-center gap-1">
                  View all incidents →
                </Link>
              </div>
            </div>
          )}
        </div>

        <div className="h-8 w-px bg-white/10" />

        <Link to="/dashboard/profile" className="flex items-center gap-3 group cursor-pointer">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-sm font-semibold shadow-lg group-hover:shadow-[0_0_15px_rgba(59,130,246,0.5)] transition-all">
            {initial}
          </div>
          <span className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">Admin</span>
        </Link>
      </div>
    </header>
  )
}
