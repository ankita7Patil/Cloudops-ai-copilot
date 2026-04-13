import { ShieldAlert, TrendingUp, Zap, Clock, Activity, FileDown, ArrowRight } from 'lucide-react'
import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const API_URL = import.meta.env.VITE_API_URL || 'https://uaci-backend-497422153083.us-central1.run.app/api'

// Simulated live telemetry — in production this is replaced by BigQuery streaming inserts
function useLiveEvents() {
  const EVENTS = [
    { svc: 'payment-gateway', msg: 'Error rate spike 0.4% → 1.2%', severity: 'high' },
    { svc: 'gke-node-alpha', msg: 'Memory utilisation crossed 88%', severity: 'medium' },
    { svc: 'cloud-sql-prod', msg: 'Slow query detected (>3s)', severity: 'medium' },
    { svc: 'iam-audit', msg: 'New service account key created', severity: 'low' },
    { svc: 'billing-export', msg: 'Daily spend $240 — within budget', severity: 'low' },
    { svc: 'pubsub-ingest', msg: 'Throughput 12k msg/s — nominal', severity: 'low' },
    { svc: 'security-cmd', msg: 'New HIGH finding: public Cloud SQL', severity: 'high' },
  ]
  const [log, setLog] = useState<typeof EVENTS>([])
  useEffect(() => {
    const push = () => setLog(prev => [EVENTS[Math.floor(Math.random() * EVENTS.length)], ...prev].slice(0, 20))
    push()
    const t = setInterval(push, 2800)
    return () => clearInterval(t)
  }, [])
  return log
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [mttr, setMttr] = useState(1.2)
  const [actions, setActions] = useState(847)
  const [reportLoading, setReportLoading] = useState(false)
  const events = useLiveEvents()
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const timer = setInterval(() => {
      setActions(prev => prev + Math.floor(Math.random() * 3))
      setMttr(prev => Math.max(0.5, prev - Math.random() * 0.01))
    }, 2500)
    return () => clearInterval(timer)
  }, [])

  // Auto-scroll event log to top when new event arrives
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = 0
  }, [events])

  const handleReport = async () => {
    setReportLoading(true)
    try {
      const res = await fetch(`${API_URL}/reports/generate?type=full`)
      const data = await res.json()
      // Download as JSON file
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `uaci-report-${data.report_id || Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Report generation failed — ensure backend is reachable.')
    }
    setReportLoading(false)
  }

  const METRICS = [
    { id: 1, label: 'Active Critical Risks', value: '12', icon: <ShieldAlert className="text-red-400" size={24} />, trend: '+2 today', color: 'from-red-500/20 to-transparent', border: 'border-red-500/20' },
    { id: 2, label: 'Autonomous Actions', value: actions.toString(), icon: <Zap className="text-blue-400" size={24} />, trend: '98.5% success', color: 'from-blue-500/20 to-transparent', border: 'border-blue-500/20' },
    { id: 3, label: 'Cloud Cost Drift', value: '$2,104', icon: <TrendingUp className="text-orange-400" size={24} />, trend: '+14% weekly', color: 'from-orange-500/20 to-transparent', border: 'border-orange-500/20' },
    { id: 4, label: 'Avg MTTR', value: `${mttr.toFixed(2)} hr`, icon: <Clock className="text-emerald-400" size={24} />, trend: '-34% weekly', color: 'from-emerald-500/20 to-transparent', border: 'border-emerald-500/20' },
  ]

  const DIAGNOSTICS = [
    { title: 'Cloud SQL exposed to public', desc: 'Agent drafted firewall rule fix in 8s.', dot: 'bg-red-500' },
    { title: 'IAM over-provisioned role', desc: 'Recommendation: restrict to roles/viewer.', dot: 'bg-orange-500' },
    { title: 'GKE autoscaling adjusted', desc: 'Node pool scaled-in. $180 saved this week.', dot: 'bg-blue-500' },
  ]

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-tight">Executive Overview</h2>
          <p className="text-gray-400 mt-2">Unified insights across Security, SRE, and FinOps domains.</p>
        </div>
        <button
          onClick={handleReport}
          disabled={reportLoading}
          className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-sm font-medium transition-all disabled:opacity-50 active:scale-95"
        >
          <FileDown size={16} className={reportLoading ? 'animate-bounce' : ''} />
          {reportLoading ? 'Generating...' : 'Generate Report'}
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {METRICS.map(m => (
          <div key={m.id} className={`glass-panel p-6 bg-gradient-to-b ${m.color} ${m.border} hover:-translate-y-1 transition-transform duration-300 relative overflow-hidden group`}>
            <div className="absolute top-0 right-0 w-32 h-32 bg-white/[0.02] rounded-full blur-2xl -mr-10 -mt-10 group-hover:bg-white/[0.04] transition-colors" />
            <div className="flex justify-between items-start">
              <div>
                <p className="text-gray-400 text-sm font-medium mb-1">{m.label}</p>
                <h3 className="text-3xl font-bold tracking-tight text-white mb-2">{m.value}</h3>
                <p className="text-xs text-gray-500">{m.trend}</p>
              </div>
              <div className="p-3 bg-black/40 rounded-xl backdrop-blur-sm shadow-inner">
                {m.icon}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Activity Feed + Diagnostics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Live Platform Activity — real-time event stream */}
        <div className="glass-panel p-6 lg:col-span-2 flex flex-col">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 shrink-0">
            <Activity className="text-blue-400" size={18} />
            Platform Activity
            <span className="ml-auto flex items-center gap-1.5 text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Live Stream
            </span>
          </h3>

          <div ref={logRef} className="flex-1 overflow-y-auto space-y-2 max-h-64 pr-1 scrollbar-thin">
            {events.map((ev, i) => (
              <div
                key={i}
                className={`flex items-start gap-3 p-3 rounded-xl border transition-all ${
                  i === 0 ? 'bg-blue-500/5 border-blue-500/20' : 'bg-white/[0.02] border-white/5'
                }`}
                style={{ animation: i === 0 ? 'fadeIn 0.4s ease' : undefined }}
              >
                <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${
                  ev.severity === 'high' ? 'bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.8)]' :
                  ev.severity === 'medium' ? 'bg-orange-500' : 'bg-emerald-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-blue-400 truncate">{ev.svc}</p>
                  <p className="text-sm text-gray-200">{ev.msg}</p>
                </div>
                <span className="text-[10px] text-gray-600 shrink-0">just now</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Diagnostics */}
        <div className="glass-panel p-6">
          <h3 className="text-lg font-semibold mb-6">Recent Diagnostics</h3>
          <div className="space-y-4">
            {DIAGNOSTICS.map((d, i) => (
              <div key={i} className="flex gap-4 items-start p-3 hover:bg-white/5 rounded-lg transition-colors cursor-pointer border border-transparent hover:border-white/5">
                <div className={`w-2 h-2 mt-2 rounded-full ${d.dot} shadow-[0_0_8px_rgba(59,130,246,0.8)] shrink-0`} />
                <div>
                  <p className="text-sm font-medium text-gray-200">{d.title}</p>
                  <p className="text-xs text-gray-500 mt-1">{d.desc}</p>
                </div>
              </div>
            ))}
          </div>
          <button
            onClick={() => navigate('/dashboard/incidents')}
            className="w-full mt-6 py-2.5 bg-blue-500/10 text-blue-400 rounded-lg text-sm font-medium border border-blue-500/20 hover:bg-blue-500/20 transition-colors flex items-center justify-center gap-2"
          >
            View All Incidents <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  )
}
