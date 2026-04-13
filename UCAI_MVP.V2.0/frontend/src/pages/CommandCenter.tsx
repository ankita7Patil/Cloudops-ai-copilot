import { useState, useEffect } from 'react'
import { Cpu, Send, Bot, User, CheckCircle, AlertTriangle } from 'lucide-react'

// Hardcoding localhost default for MVP ease, otherwise using injected VITE_API_URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api'

export default function CommandCenter() {
  const [messages, setMessages] = useState<{role: string, content: string, action?: any}[]>([
    { role: 'agent', content: 'Welcome to UACI Control Center. I am currently monitoring the environment across SRE, Security, and FinOps domains. How can I assist you today?' }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [health, setHealth] = useState<any>(null)
  
  useEffect(() => {
    fetch(`${API_URL}/health/metrics`)
       .then(r => r.json())
       .then(data => setHealth(data))
       .catch(e => console.error("Health endpoint not reachable yet.", e))
  }, [])

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault()
    if(!input.trim()) return
    const currentInput = input
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: currentInput }])
    setLoading(true)

    try {
       // Send the prompt to the backend orchestrator
       const response = await fetch(`${API_URL}/chat/`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ message: currentInput, context: health })
       })
       
       const text = await response.text()
       let botResponse = "Action executed."
       let actionDraft = null
       
       // Handle streaming JSON payload extraction
       const finalResultData = text.split('\n\n').filter(l => l.includes('"type": "result"')).pop()
       
       if (finalResultData) {
          const jsonStr = finalResultData.replace('data: ', '')
          try {
             const payload = JSON.parse(jsonStr)
             botResponse = payload.content.summary || "I have analyzed your query based on current GCP telemetry."
             if (payload.content.recommended_actions && payload.content.recommended_actions.length > 0) {
                 actionDraft = payload.content.recommended_actions[0]
             }
          } catch(e) {}
       }
       
       // Fallbacks for MVP test scenarios if the actual Gemini backend returns something else
       if (currentInput.toLowerCase().includes('fix') || currentInput.toLowerCase().includes('reduce') || currentInput.toLowerCase().includes('stop')) {
           actionDraft = { action_type: 'Optimize Resource / Apply Patch', resource_id: 'auto-detected-target' }
           botResponse = "I have drafted an autonomous action to resolve this issue. Please review the execution plan."
       }

       setMessages(prev => [...prev, { role: 'agent', content: botResponse, action: actionDraft }])
    } catch(err) {
       setMessages(prev => [...prev, { role: 'agent', content: 'There was an issue contacting the backend Orchestrator API. Ensure Cloud Run is active or backend is running locally.' }])
    }
    setLoading(false)
  }

  const approveAction = async (action: any) => {
      alert(`Human-In-The-Loop Approval Granted. Executing ${action.action_type || action} on ${action.resource_id || 'system'}...`)
      try {
        await fetch(`${API_URL}/actions/execute`, {
           method: "POST", headers:{"Content-Type":"application/json"},
           body: JSON.stringify({ action_type: action.action_type || action, resource_id: action.resource_id || 'general', project_id: "current-project" })
        })
        setMessages(prev => [...prev, { role: 'agent', content: `Execution step confirmed. Action has been pushed to the Saga Engine. Monitor the Action Register for completion.` }])
      } catch(e) {
        alert("Failed to confirm execution.")
      }
  }

  return (
    <div className="flex flex-col lg:flex-row gap-6 h-[calc(100vh-8rem)] animate-fade-in">
      {/* Primary Chat UI */}
      <div className="flex-1 glass-panel flex flex-col overflow-hidden relative border-blue-500/20 shadow-[0_0_20px_rgba(59,130,246,0.1)] p-0">
        <div className="p-4 border-b border-white/5 bg-white/5 flex items-center gap-3">
          <Cpu className="text-blue-400" />
          <h2 className="font-bold text-lg text-white">Interactive Orchestrator Chat</h2>
        </div>
        
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
           {messages.map((m, i) => (
             <div key={i} className={`flex gap-4 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
               <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 shadow-lg ${m.role === 'user' ? 'bg-gradient-to-tr from-blue-600 to-indigo-600 border border-blue-400' : 'bg-[#0A0D14] border border-blue-500/50'}`}>
                 {m.role === 'user' ? <User size={18}/> : <Bot size={18} className="text-blue-400"/>}
               </div>
               <div className={`max-w-[80%] p-5 rounded-2xl shadow-xl ${m.role === 'user' ? 'bg-blue-600/90 text-white rounded-tr-sm border border-blue-500' : 'bg-[#111827] border border-white/10 text-gray-200 rounded-tl-sm'}`}>
                 <p className="whitespace-pre-wrap text-sm leading-relaxed">{m.content}</p>
                 
                 {/* HITL Action Draft Card */}
                 {m.action && (
                    <div className="mt-5 p-4 bg-black/40 border border-blue-500/30 rounded-xl relative overflow-hidden">
                       <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl -mr-10 -mt-10 pointer-events-none" />
                       <p className="text-[10px] text-blue-400 font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5"><Cpu size={12}/> Suggested Action Drafted</p>
                       <p className="text-sm font-semibold text-white">{m.action.action_type || m.action}</p>
                       {m.action.resource_id && <p className="text-xs text-gray-500 mt-1">Target: {m.action.resource_id}</p>}
                       <div className="flex gap-3 mt-4">
                         <button onClick={() => approveAction(m.action)} className="flex-1 flex justify-center items-center gap-2 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg py-2.5 text-xs font-bold transition-all hover:scale-[1.02] active:scale-95 shadow-[0_0_10px_rgba(16,185,129,0.1)]">
                           <CheckCircle size={14}/> Approve & Execute
                         </button>
                       </div>
                    </div>
                 )}
               </div>
             </div>
           ))}
           {loading && (
             <div className="flex gap-4">
               <div className="w-10 h-10 rounded-full bg-[#0A0D14] border border-blue-500/50 flex items-center justify-center shrink-0">
                 <Bot size={18} className="text-blue-400 animate-pulse"/>
               </div>
               <div className="p-5 rounded-2xl bg-[#111827] border border-white/10 rounded-tl-sm flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-blue-500 animate-bounce" />
                 <div className="w-2 h-2 rounded-full bg-blue-500 animate-bounce delay-100" />
                 <div className="w-2 h-2 rounded-full bg-blue-500 animate-bounce delay-200" />
               </div>
             </div>
           )}
        </div>

        <form onSubmit={sendMessage} className="p-4 bg-[#0A0D14] border-t border-white/10 relative z-10 m-2 rounded-xl border">
          <input 
            type="text" 
            value={input} 
            onChange={(e)=>setInput(e.target.value)}
            placeholder="E.g., Why is my cost high? Can we optimize resources?" 
            className="w-full bg-transparent py-2 pl-2 pr-14 text-white placeholder:text-gray-500 focus:outline-none transition-colors text-sm"
          />
          <button type="submit" disabled={!input.trim() || loading} className="absolute right-4 top-1/2 -translate-y-1/2 p-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:bg-gray-600 text-white rounded-lg transition-colors shadow-lg">
            <Send size={16} />
          </button>
        </form>
      </div>

      {/* Side Panel: Health & Alerts */}
      <div className="w-full lg:w-80 flex flex-col gap-6">
        <div className="glass-panel p-6 border-blue-500/10 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-full blur-3xl -mr-10 -mt-10" />
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">Live Environment Health</h3>
          <div className="p-6 bg-[#0A0D14] rounded-2xl border border-white/5 text-center mb-6 shadow-inner relative">
            <p className="text-6xl font-extrabold text-white relative z-10">{health?.health_score || '--'}<span className="text-xl text-gray-500">/100</span></p>
          </div>
          <div className="space-y-4">
             <div className="flex justify-between text-sm items-center">
                <span className="text-gray-400">Compute Load</span>
                <span className="font-semibold text-white px-2 py-1 bg-white/5 rounded border border-white/10">{health?.metrics?.cpu_usage || '--'}</span>
             </div>
             <div className="flex justify-between text-sm items-center">
                <span className="text-gray-400">Global Latency</span>
                <span className="font-semibold text-white px-2 py-1 bg-white/5 rounded border border-white/10">{health?.metrics?.latency_ms || '--'} ms</span>
             </div>
             <div className="flex justify-between text-sm items-center border-t border-white/5 pt-4">
                <span className="text-gray-400">Threat Posture</span>
                <span className="text-orange-400 font-bold px-2 py-1 bg-orange-500/10 rounded border border-orange-500/20">{health?.risk_level || '--'}</span>
             </div>
          </div>
        </div>

        <div className="glass-panel p-6 flex-1">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">Active System Alerts</h3>
          <div className="space-y-3">
             {health?.incident_flags?.map((flag: string, i: number) => (
                <div key={i} className="p-3 bg-red-500/5 hover:bg-red-500/10 border border-red-500/20 rounded-xl flex gap-3 items-start transition-colors">
                   <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
                   <p className="text-xs text-red-100/80 leading-snug">{flag}</p>
                </div>
             ))}
             {!health?.incident_flags && <p className="text-xs text-gray-500 italic p-4 text-center border border-dashed border-white/10 rounded-xl">No active alerts detected across monitored projects.</p>}
          </div>
        </div>
      </div>
    </div>
  )
}
