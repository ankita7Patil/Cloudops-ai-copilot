import { useState, useEffect } from 'react'
import { ShieldAlert, Activity, GitCommit, AlertTriangle, CheckCircle, Crosshair } from 'lucide-react'

// Realistic rapidly updating mock data logic to simulate active environment
const INCIDENTS = [
  { id: 'INC-901', title: 'Ransomware IOC Detected', service: 'S3/EC2', severity: 'Critical', rpn: 980, status: 'Mitigating' },
  { id: 'INC-902', title: 'Data Exfiltration via DNS', service: 'VPC', severity: 'High', rpn: 840, status: 'Investigating' },
  { id: 'INC-903', title: 'Container Escape Vulnerability', service: 'GKE', severity: 'High', rpn: 760, status: 'Open' },
  { id: 'INC-904', title: 'Kubelet API Anonymous Access', service: 'AKS', severity: 'Critical', rpn: 990, status: 'Resolved' },
  { id: 'INC-905', title: 'Unusual IAM Role Assumption', service: 'IAM', severity: 'Medium', rpn: 450, status: 'Open' }
]

export default function Incidents() {
  const [active, setActive] = useState(INCIDENTS)
  const [pulse, setPulse] = useState(false)

  // Simulation of incoming telemetry
  useEffect(() => {
    const i = setInterval(() => {
      setPulse(true)
      setTimeout(() => setPulse(false), 500)
    }, 4000)
    return () => clearInterval(i)
  }, [])

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h2 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
          <ShieldAlert className="text-red-500" size={32} /> Active Threats
        </h2>
        <p className="text-gray-400 mt-2">Correlated Security & SRE Signals processed by the UACI Agents.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-panel p-6 border-red-500/20">
          <p className="text-sm text-gray-400">Critical Priority</p>
          <p className="text-4xl font-bold text-white mt-1">2</p>
        </div>
        <div className="glass-panel p-6 border-orange-500/20">
          <p className="text-sm text-gray-400">Average RPN</p>
          <p className="text-4xl font-bold text-white mt-1">804</p>
        </div>
        <div className={`glass-panel p-6 border-blue-500/20 transition-all duration-300 ${pulse ? 'bg-blue-500/10' : ''}`}>
          <p className="text-sm text-gray-400 flex items-center gap-2"><Activity size={16} className="text-blue-400"/> Processing Stream</p>
          <p className="text-4xl font-bold text-white mt-1">Active</p>
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
         <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 border-b border-white/10 text-sm font-semibold text-gray-300">
                <th className="p-4 pl-6">ID</th>
                <th className="p-4">Incident Signature</th>
                <th className="p-4">Service</th>
                <th className="p-4">Severity</th>
                <th className="p-4">RPN Score</th>
                <th className="p-4 text-right pr-6">Agent Status</th>
              </tr>
            </thead>
            <tbody>
              {active.map(inc => (
                <tr key={inc.id} className="border-b border-white/5 hover:bg-white/5 transition-colors group cursor-pointer">
                  <td className="p-4 pl-6 font-mono text-sm text-blue-400">{inc.id}</td>
                  <td className="p-4 font-medium text-gray-100">{inc.title}</td>
                  <td className="p-4 text-gray-400"><span className="px-2 py-1 bg-white/5 rounded text-xs border border-white/10">{inc.service}</span></td>
                  <td className="p-4">
                    <span className={`flex items-center gap-1.5 text-sm ${inc.severity === 'Critical' ? 'text-red-400' : inc.severity === 'High' ? 'text-orange-400' : 'text-yellow-400'}`}>
                      {inc.severity === 'Critical' ? <AlertTriangle size={14}/> : <Crosshair size={14}/>} {inc.severity}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-gray-300">{inc.rpn}</td>
                  <td className="p-4 text-right pr-6">
                    <span className={`inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-full border ${
                      inc.status === 'Resolved' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                      inc.status === 'Mitigating' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                      'bg-orange-500/10 text-orange-400 border-orange-500/20'
                    }`}>
                      {inc.status === 'Resolved' && <CheckCircle size={12}/>}
                      {inc.status === 'Mitigating' && <GitCommit size={12} className="animate-spin-slow"/>}
                      {inc.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
         </table>
      </div>
    </div>
  )
}
