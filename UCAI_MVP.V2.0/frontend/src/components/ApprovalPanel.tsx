const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api'
const api = { 
  post: async (p: string, b: any) => {
    return fetch(`${API_URL}${p}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b)
    })
  } 
}

export default function ApprovalPanel({ approvals }: { approvals: any[] }) {
  const handleApprove = async (approvalId: string) => {
    try {
      await api.post(`/approvals/${approvalId}`, { action: "approve", user_id: "admin" })
      alert(`Approval ${approvalId} processed successfully!`)
    } catch (e) {
      alert("Error contacting backend")
    }
  }

  if (!approvals || approvals.length === 0) {
    return <p className="text-gray-500 italic text-sm text-center py-6">No pending actions requiring your attention.</p>
  }

  return (
    <div className="space-y-4">
      {approvals.map(a => (
        <div key={a.id} className="p-4 bg-[#111827] border border-white/5 rounded-xl hover:border-blue-500/30 transition-all group">
          <div className="flex justify-between items-start">
            <div>
              <p className="font-semibold text-gray-200">{a.action_type}</p>
              <p className="text-sm text-gray-500 mt-1">Resource: <span className="text-gray-300">{a.resource_id}</span></p>
              <div className="flex gap-2 mt-3">
                <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-blue-500/10 text-blue-400 border border-blue-500/20">{a.tier}</span>
                <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/20">{a.agent_name}</span>
              </div>
            </div>
            <button 
              onClick={() => handleApprove(a.id)}
              className="px-4 py-2 bg-gradient-to-tr from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-[0_0_10px_rgba(59,130,246,0.3)] rounded-lg font-medium text-sm transition-all"
            >
              Approve
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}
