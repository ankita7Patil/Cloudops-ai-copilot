import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, Bot, Send, User, ShieldAlert, DollarSign, Cpu, Activity, Clock, CheckCircle, AlertTriangle, FileDown, Zap } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || 'https://uaci-backend-497422153083.us-central1.run.app/api'

// Severity-coloured incident list per project
const INCIDENT_TEMPLATES = (pid: string) => [
  { title: `IAM over-privileged account in ${pid}`, severity: 'Critical', agent: 'Security Agent', eta: '12s auto-patch' },
  { title: 'Cloud SQL missing automated backup', severity: 'High', agent: 'SRE Agent', eta: 'Pending approval' },
  { title: 'VPC firewall allows 0.0.0.0/0 on port 22', severity: 'High', agent: 'Security Agent', eta: 'Pending approval' },
  { title: 'Cloud Storage bucket has public access', severity: 'Medium', agent: 'Security Agent', eta: 'Review required' },
  { title: 'Billing drift above 15% threshold', severity: 'Medium', agent: 'FinOps Agent', eta: 'Resize drafted' },
]

export default function ProjectDetail() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const [project, setProject] = useState<any>(null)
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [messages, setMessages] = useState<{ role: string; content: string; action?: any }[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'health' | 'incidents' | 'chat' | 'actions'>('health')

  const fetchProject = useCallback(async () => {
    if (!projectId) return
    try {
      const [pRes, hRes] = await Promise.all([
        fetch(`${API}/projects/${projectId}`),
        fetch(`${API}/projects/${projectId}/health`)
      ])
      const pData = await pRes.json()
      const hData = await hRes.json()
      setProject(pData.project)
      setHealth(hData)
    } catch {}
    setLoading(false)
  }, [projectId])

  useEffect(() => {
    fetchProject()
    const t = setInterval(fetchProject, 20000)
    return () => clearInterval(t)
  }, [fetchProject])

  useEffect(() => {
    if (project && messages.length === 0) {
      setMessages([{
        role: 'agent',
        content: `I am now monitoring **${project.project_name}** (${projectId}). Current health score: ${project.health_score}/100 · Risk: ${project.risk_level}. What would you like to analyze or fix?`
      }])
    }
  }, [project])

  const sendChat = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!chatInput.trim()) return
    const msg = chatInput; setChatInput(''); setChatLoading(true)
    setMessages(prev => [...prev, { role: 'user', content: msg }])
    try {
      const res = await fetch(`${API}/projects/${projectId}/chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg })
      })
      const data = await res.json()
      const r = data.response || {}
      const summary = r.summary || `Analyzed query for project ${projectId}.`
      const action = r.recommended_actions?.[0] || null
      setMessages(prev => [...prev, { role: 'agent', content: summary, action }])
    } catch {
      setMessages(prev => [...prev, { role: 'agent', content: 'Backend unreachable — ensure Cloud Run is active.' }])
    }
    setChatLoading(false)
  }

  const approveAction = async (action: any) => {
    try {
      await fetch(`${API}/actions/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: action.action_type || action, resource_id: action.resource_id || 'auto', project_id: projectId })
      })
      setMessages(prev => [...prev, { role: 'agent', content: `✅ Action approved and queued in Saga Engine for **${projectId}**. Monitor the Action Register for completion status.` }])
    } catch { alert('Execution failed.') }
  }

  const downloadReport = async () => {
    setReportLoading(true)
    try {
      const res = await fetch(`${API}/projects/${projectId}/report`)
      const data = await res.json()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = `${projectId}-report.json`; a.click()
      URL.revokeObjectURL(url)
    } catch { alert('Report failed.') }
    setReportLoading(false)
  }

  if (loading) return (
    <div className="animate-fade-in space-y-4">
      <div className="h-10 w-64 bg-white/5 animate-pulse rounded-xl" />
      <div className="glass-panel p-8 h-64 animate-pulse bg-white/5" />
    </div>
  )

  if (!project) return (
    <div className="glass-panel p-12 text-center animate-fade-in">
      <AlertTriangle size={40} className="text-red-400 mx-auto mb-4" />
      <h3 className="text-xl font-bold text-white mb-2">Project Not Found</h3>
      <p className="text-gray-400 mb-6">Project <code className="text-blue-400">{projectId}</code> does not exist or was removed.</p>
      <button onClick={() => navigate('/dashboard/projects')} className="px-6 py-3 bg-blue-600 text-white rounded-xl font-bold">← Back to Projects</button>
    </div>
  )

  const scoreColor = project.health_score >= 80 ? 'text-emerald-400' : project.health_score >= 60 ? 'text-yellow-400' : 'text-red-400'
  const incidents = INCIDENT_TEMPLATES(projectId!)
  const tabs = ['health', 'incidents', 'chat', 'actions'] as const

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Breadcrumb Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/dashboard/projects')}
            className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-all">
            <ArrowLeft size={20} />
          </button>
          <div>
            <h2 className="text-2xl font-bold text-white">{project.project_name}</h2>
            <p className="text-xs font-mono text-gray-500">{projectId}</p>
          </div>
          <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
            project.risk_level === 'Low' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
            project.risk_level === 'Medium' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400' :
            'bg-red-500/10 border-red-500/20 text-red-400'}`}>
            {project.risk_level} Risk
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={fetchProject} className="flex items-center gap-2 px-4 py-2 text-sm text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg transition-all">
            <RefreshCw size={14} /> Refresh
          </button>
          <button onClick={downloadReport} disabled={reportLoading} className="flex items-center gap-2 px-4 py-2 text-sm font-bold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-all disabled:opacity-50">
            <FileDown size={14} className={reportLoading ? 'animate-bounce' : ''} />
            {reportLoading ? 'Generating...' : 'Download Report'}
          </button>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Health Score', value: <span className={`text-2xl font-extrabold ${scoreColor}`}>{project.health_score}/100</span>, icon: <Activity size={18} className="text-blue-400" /> },
          { label: 'Active Alerts', value: <span className="text-2xl font-extrabold text-orange-400">{project.alerts_count}</span>, icon: <AlertTriangle size={18} className="text-orange-400" /> },
          { label: 'Monthly Spend', value: <span className="text-2xl font-extrabold text-white">${project.monthly_cost?.toFixed(0)}</span>, icon: <DollarSign size={18} className="text-emerald-400" /> },
          { label: 'Cost Drift', value: <span className="text-2xl font-extrabold text-red-400">{project.cost_drift}</span>, icon: <Zap size={18} className="text-red-400" /> },
        ].map(k => (
          <div key={k.label} className="glass-panel p-4 flex items-center gap-3">
            <div className="p-2 bg-white/5 rounded-lg">{k.icon}</div>
            <div><p className="text-xs text-gray-400">{k.label}</p>{k.value}</div>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 bg-white/[0.03] border border-white/5 rounded-xl w-fit">
        {tabs.map(t => (
          <button key={t} onClick={() => setActiveTab(t)}
            className={`px-5 py-2 rounded-lg text-sm font-semibold capitalize transition-all ${activeTab === t ? 'bg-blue-600 text-white shadow-lg' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
            {t === 'health' ? '❤️ Health' : t === 'incidents' ? '🚨 Incidents' : t === 'chat' ? '🤖 Agent Chat' : '⚙️ Actions'}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      {activeTab === 'health' && health && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-fade-in">
          {[
            { label: 'CPU Usage', value: health.metrics?.cpu_usage, icon: <Cpu size={20} className="text-blue-400" /> },
            { label: 'Memory Usage', value: health.metrics?.memory_usage, icon: <Activity size={20} className="text-purple-400" /> },
            { label: 'Active Alerts', value: health.metrics?.alerts_count?.toString(), icon: <AlertTriangle size={20} className="text-orange-400" /> },
            { label: 'Monthly Cost', value: `$${health.metrics?.monthly_cost?.toFixed(2)}`, icon: <DollarSign size={20} className="text-emerald-400" /> },
            { label: 'Cost Drift', value: health.metrics?.cost_drift, icon: <Zap size={20} className="text-red-400" /> },
            { label: 'Risk Level', value: health.risk_level, icon: <ShieldAlert size={20} className="text-yellow-400" /> },
          ].map(m => (
            <div key={m.label} className="glass-panel p-5 flex items-center gap-4">
              <div className="p-3 bg-white/5 rounded-xl">{m.icon}</div>
              <div><p className="text-xs text-gray-400">{m.label}</p><p className="text-xl font-bold text-white">{m.value ?? '--'}</p></div>
            </div>
          ))}
          {health.incident_flags?.length > 0 && (
            <div className="lg:col-span-3 glass-panel p-5 border-red-500/20 space-y-3">
              <h4 className="text-sm font-bold text-red-400 flex items-center gap-2"><ShieldAlert size={16}/>Active Incident Flags</h4>
              {health.incident_flags.map((f: string, i: number) => (
                <div key={i} className="text-sm text-gray-300 bg-red-500/5 border border-red-500/10 rounded-lg p-3">{f}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'incidents' && (
        <div className="glass-panel overflow-hidden animate-fade-in">
          <table className="w-full text-left">
            <thead className="bg-white/5 border-b border-white/10 text-xs font-semibold text-gray-400 uppercase tracking-wider">
              <tr><th className="p-4 pl-6">Incident</th><th className="p-4">Severity</th><th className="p-4">Assigned Agent</th><th className="p-4 pr-6 text-right">Resolution</th></tr>
            </thead>
            <tbody>
              {incidents.map((inc, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                  <td className="p-4 pl-6 text-sm text-gray-100 font-medium">{inc.title}</td>
                  <td className="p-4"><span className={`text-xs font-bold px-2 py-1 rounded-full border ${inc.severity === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' : inc.severity === 'High' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>{inc.severity}</span></td>
                  <td className="p-4 text-xs text-gray-400">{inc.agent}</td>
                  <td className="p-4 pr-6 text-right text-xs text-blue-400 font-medium">{inc.eta}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'chat' && (
        <div className="glass-panel flex flex-col h-[500px] overflow-hidden animate-fade-in border-blue-500/20">
          <div className="px-5 py-3 border-b border-white/5 bg-white/[0.02] flex items-center gap-2 shrink-0">
            <Bot size={16} className="text-blue-400" />
            <span className="text-sm font-bold">Agent Chat — scoped to <code className="text-blue-400">{projectId}</code></span>
          </div>
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${m.role === 'user' ? 'bg-gradient-to-tr from-blue-600 to-indigo-600' : 'bg-[#0A0D14] border border-blue-500/50'}`}>
                  {m.role === 'user' ? <User size={16}/> : <Bot size={16} className="text-blue-400"/>}
                </div>
                <div className={`max-w-[80%] p-4 rounded-2xl text-sm leading-relaxed ${m.role === 'user' ? 'bg-blue-600 text-white rounded-tr-sm' : 'bg-[#111827] border border-white/10 text-gray-200 rounded-tl-sm'}`}>
                  {m.content}
                  {m.action && (
                    <div className="mt-3 p-3 bg-black/40 border border-blue-500/30 rounded-xl">
                      <p className="text-[10px] text-blue-400 font-bold uppercase mb-1">Suggested Action</p>
                      <p className="text-sm font-semibold text-white">{m.action.action_type || m.action}</p>
                      <button onClick={() => approveAction(m.action)} className="mt-2 w-full flex justify-center items-center gap-2 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg py-2 text-xs font-bold transition-all">
                        <CheckCircle size={12}/> Approve & Execute
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="flex gap-3">
                <div className="w-9 h-9 rounded-full bg-[#0A0D14] border border-blue-500/50 flex items-center justify-center shrink-0">
                  <Bot size={16} className="text-blue-400 animate-pulse"/>
                </div>
                <div className="p-4 rounded-2xl bg-[#111827] border border-white/10 flex items-center gap-1.5">
                  {[0,1,2].map(i => <div key={i} className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{animationDelay:`${i*0.1}s`}}/>)}
                </div>
              </div>
            )}
          </div>
          <form onSubmit={sendChat} className="p-4 border-t border-white/5 flex gap-3 shrink-0">
            <input value={chatInput} onChange={e=>setChatInput(e.target.value)}
              placeholder={`Ask about ${project.project_name}...`}
              className="flex-1 bg-[#0A0D14] border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-gray-500 focus:border-blue-500 outline-none" />
            <button type="submit" disabled={!chatInput.trim() || chatLoading} className="p-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white rounded-xl transition-colors">
              <Send size={16}/>
            </button>
          </form>
        </div>
      )}

      {activeTab === 'actions' && (
        <div className="glass-panel p-6 animate-fade-in space-y-4">
          <h3 className="font-bold text-white flex items-center gap-2"><Clock size={18} className="text-blue-400"/>Pending HITL Actions — {project.project_name}</h3>
          {[
            { label: 'Restrict IAM role: default service account', risk: 'Low', tier: 'TIER-1' },
            { label: 'Apply firewall rule: restrict SSH to corp CIDR', risk: 'Medium', tier: 'TIER-2' },
            { label: 'Enable automated Cloud SQL backups', risk: 'Low', tier: 'TIER-1' },
          ].map((action, i) => (
            <div key={i} className="flex items-center justify-between p-4 bg-white/[0.03] border border-white/10 rounded-xl gap-4">
              <div>
                <p className="text-sm font-medium text-gray-100">{action.label}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[10px] font-bold px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">{action.tier}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${action.risk === 'Low' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'}`}>Risk: {action.risk}</span>
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button onClick={() => approveAction({ action_type: action.label, resource_id: projectId })} className="px-4 py-2 text-xs font-bold bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg transition-all flex items-center gap-1.5">
                  <CheckCircle size={12}/> Approve
                </button>
                <button className="px-4 py-2 text-xs font-bold bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 rounded-lg transition-all">Skip</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
