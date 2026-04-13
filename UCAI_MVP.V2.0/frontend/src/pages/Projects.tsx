import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, RefreshCw, Trash2, CloudCog, AlertTriangle, CheckCircle, Clock, X, UploadCloud } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || 'https://uaci-backend-497422153083.us-central1.run.app/api'

interface Project {
  project_id: string
  project_name: string
  health_score: number
  risk_level: string
  connection_status: string
  last_sync: string
  alerts_count: number
  monthly_cost: number
  cost_drift: string
}

function HealthRing({ score }: { score: number }) {
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'
  const r = 28, circ = 2 * Math.PI * r
  const dash = (score / 100) * circ
  return (
    <svg width="72" height="72" className="rotate-[-90deg]">
      <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
      <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.8s ease', filter: `drop-shadow(0 0 4px ${color})` }} />
      <text x="36" y="36" textAnchor="middle" dominantBaseline="central"
        fill="white" fontSize="13" fontWeight="700" className="rotate-[90deg] origin-center"
        style={{ transform: 'rotate(90deg)', transformOrigin: '36px 36px' }}>
        {score}
      </text>
    </svg>
  )
}

export default function Projects() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [adding, setAdding] = useState(false)
  const [refreshing, setRefreshing] = useState<string | null>(null)
  const [form, setForm] = useState({ project_id: '', project_name: '' })
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState('')

  const fetchProjects = useCallback(async () => {
    try {
      const res = await fetch(`${API}/projects/`)
      const data = await res.json()
      setProjects(data.projects || [])
    } catch { /* backend may not be running locally */ }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchProjects()
    const t = setInterval(fetchProjects, 30000) // auto-refresh every 30s
    return () => clearInterval(t)
  }, [fetchProjects])

  const addProject = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) { setError('Please select your Service Account JSON key file.'); return }
    setAdding(true); setError('')
    const fd = new FormData()
    fd.append('project_id', form.project_id)
    fd.append('project_name', form.project_name || form.project_id)
    fd.append('service_account_json', file)
    try {
      const res = await fetch(`${API}/projects/`, { method: 'POST', body: fd })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed')
      setShowAdd(false); setForm({ project_id: '', project_name: '' }); setFile(null)
      await fetchProjects()
    } catch (e: any) { setError(e.message) }
    setAdding(false)
  }

  const refreshProject = async (projectId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setRefreshing(projectId)
    try {
      await fetch(`${API}/projects/${projectId}/refresh`, { method: 'POST' })
      await fetchProjects()
    } catch {}
    setRefreshing(null)
  }

  const removeProject = async (projectId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm(`Remove project "${projectId}"? This cannot be undone.`)) return
    await fetch(`${API}/projects/${projectId}`, { method: 'DELETE' })
    await fetchProjects()
  }

  const statusConfig = (p: Project) => {
    if (p.health_score >= 80) return { label: 'Healthy', color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5', icon: <CheckCircle size={14} className="text-emerald-400" /> }
    if (p.health_score >= 60) return { label: 'Warning', color: 'text-yellow-400', border: 'border-yellow-500/20', bg: 'bg-yellow-500/5', icon: <AlertTriangle size={14} className="text-yellow-400" /> }
    return { label: 'Critical', color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/5', icon: <AlertTriangle size={14} className="text-red-400" /> }
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <CloudCog className="text-blue-400" size={32} /> GCP Projects
          </h2>
          <p className="text-gray-400 mt-2">{projects.length} project{projects.length !== 1 ? 's' : ''} monitored · auto-refreshes every 30s</p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold shadow-[0_0_20px_rgba(59,130,246,0.3)] transition-all hover:-translate-y-0.5 border border-blue-400/30"
        >
          <Plus size={18} /> Connect Project
        </button>
      </div>

      {/* Project Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1,2,3].map(i => <div key={i} className="glass-panel p-6 h-48 animate-pulse bg-white/5" />)}
        </div>
      ) : projects.length === 0 ? (
        <div className="glass-panel p-16 text-center border-dashed">
          <CloudCog size={48} className="text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-gray-400 mb-2">No Projects Connected</h3>
          <p className="text-gray-500 text-sm mb-6">Connect your first GCP project to start autonomous monitoring.</p>
          <button onClick={() => setShowAdd(true)} className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold transition-all">
            <Plus size={16} className="inline mr-2" />Connect Your First Project
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map(p => {
            const st = statusConfig(p)
            return (
              <div
                key={p.project_id}
                onClick={() => navigate(`/dashboard/projects/${p.project_id}`)}
                className={`glass-panel p-6 cursor-pointer group hover:-translate-y-1.5 transition-all duration-300 border ${st.border} ${st.bg} relative overflow-hidden`}
              >
                <div className="absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-20 -mr-8 -mt-8 transition-opacity group-hover:opacity-40"
                  style={{ background: p.health_score >= 80 ? '#10b981' : p.health_score >= 60 ? '#f59e0b' : '#ef4444' }} />

                {/* Top row */}
                <div className="flex items-start justify-between mb-4 relative z-10">
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold text-white text-lg truncate group-hover:text-blue-300 transition-colors">{p.project_name}</h3>
                    <p className="text-xs font-mono text-gray-500 truncate">{p.project_id}</p>
                  </div>
                  <div className="flex items-center gap-1 ml-2">
                    <button
                      onClick={(e) => refreshProject(p.project_id, e)}
                      className="p-1.5 text-gray-500 hover:text-white hover:bg-white/10 rounded-lg transition-all"
                      title="Refresh metrics"
                    >
                      <RefreshCw size={14} className={refreshing === p.project_id ? 'animate-spin' : ''} />
                    </button>
                    <button
                      onClick={(e) => removeProject(p.project_id, e)}
                      className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                      title="Remove project"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>

                {/* Health Ring + Stats */}
                <div className="flex items-center gap-5 relative z-10">
                  <HealthRing score={p.health_score} />
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Status</span>
                      <span className={`flex items-center gap-1 font-semibold ${st.color}`}>{st.icon}{st.label}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Alerts</span>
                      <span className={`font-semibold ${p.alerts_count > 0 ? 'text-orange-400' : 'text-gray-300'}`}>{p.alerts_count}</span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Monthly Cost</span>
                      <span className="font-semibold text-gray-200">${p.monthly_cost?.toFixed(0) ?? '--'}</span>
                    </div>
                  </div>
                </div>

                {/* Footer */}
                <div className="mt-4 pt-4 border-t border-white/5 flex items-center gap-1.5 text-[11px] text-gray-600 relative z-10">
                  <Clock size={11} />
                  Synced {new Date(p.last_sync).toLocaleTimeString()}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Add Project Modal */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowAdd(false)}>
          <div className="glass-panel p-8 w-full max-w-md animate-fade-in relative" onClick={e => e.stopPropagation()}>
            <button onClick={() => setShowAdd(false)} className="absolute top-4 right-4 text-gray-500 hover:text-white transition-colors"><X size={20}/></button>

            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-blue-500/10 rounded-xl border border-blue-500/20">
                <UploadCloud className="text-blue-400" size={22}/>
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Connect GCP Project</h3>
                <p className="text-xs text-gray-400">Upload your Service Account JSON key</p>
              </div>
            </div>

            {error && <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg">{error}</div>}

            <form onSubmit={addProject} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase tracking-wider">GCP Project ID *</label>
                <input value={form.project_id} onChange={e => setForm(f => ({...f, project_id: e.target.value}))}
                  placeholder="my-project-123456" required
                  className="w-full bg-[#0A0D14] border border-white/10 rounded-lg p-3 text-white focus:border-blue-500 outline-none transition-colors text-sm" />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase tracking-wider">Display Name</label>
                <input value={form.project_name} onChange={e => setForm(f => ({...f, project_name: e.target.value}))}
                  placeholder="Production Environment"
                  className="w-full bg-[#0A0D14] border border-white/10 rounded-lg p-3 text-white focus:border-blue-500 outline-none transition-colors text-sm" />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase tracking-wider">Service Account Key JSON *</label>
                <div className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-colors ${file ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-white/10 hover:border-blue-500/40 bg-white/[0.02]'}`}>
                  <input type="file" accept=".json" className="hidden" id="sa-file" onChange={e => setFile(e.target.files?.[0] || null)} />
                  <label htmlFor="sa-file" className="cursor-pointer">
                    {file ? (
                      <><CheckCircle size={24} className="text-emerald-400 mx-auto mb-2"/><p className="text-sm text-emerald-400 font-medium">{file.name}</p></>
                    ) : (
                      <><UploadCloud size={24} className="text-gray-500 mx-auto mb-2"/><p className="text-sm text-gray-400">Click to upload <code className="text-blue-400 text-xs">*-key.json</code></p>
                      <p className="text-xs text-gray-600 mt-1">GCP Console → IAM → Service Accounts → Keys → Add Key → JSON</p></>
                    )}
                  </label>
                </div>
              </div>

              <button type="submit" disabled={adding}
                className="w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl font-bold transition-all shadow-lg disabled:opacity-50 active:scale-95 mt-2">
                {adding ? 'Connecting...' : 'Authenticate & Connect'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
