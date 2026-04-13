import { TrendingDown, TrendingUp, DollarSign, Activity } from 'lucide-react'

const FIN_METRICS = [
  { service: 'Cloud Compute', cost: 1845.20, drift: '+12.4%', status: 'anomaly' },
  { service: 'Object Storage', cost: 420.50, drift: '-2.1%', status: 'stable' },
  { service: 'Cloud SQL', cost: 950.00, drift: '+45.0%', status: 'critical' },
  { service: 'Network Egress', cost: 120.30, drift: '+5.4%', status: 'stable' }
]

export default function FinOps() {
  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h2 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
          <DollarSign className="text-emerald-500" size={32} /> FinOps Intelligence
        </h2>
        <p className="text-gray-400 mt-2">Autonomous cost optimization and anomaly detection tracking.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="glass-panel p-6 border-emerald-500/20 bg-emerald-500/5">
          <p className="text-sm text-gray-400">Total Monthly Spend</p>
          <p className="text-4xl font-bold text-white mt-1">$3,336</p>
        </div>
        <div className="glass-panel p-6 border-red-500/20 bg-red-500/5">
          <p className="text-sm text-gray-400">Identified Waste</p>
          <p className="text-4xl font-bold text-white mt-1">$450</p>
        </div>
        <div className="glass-panel p-6 border-blue-500/20">
          <p className="text-sm text-gray-400">Optimizations Applied</p>
          <p className="text-4xl font-bold text-white mt-1">12</p>
        </div>
        <div className="glass-panel p-6 border-purple-500/20">
          <p className="text-sm text-gray-400">Agent Efficiency Score</p>
          <p className="text-4xl font-bold text-white mt-1">94%</p>
        </div>
      </div>

      <h3 className="text-xl font-bold mt-8 mb-4 border-b border-white/5 pb-2">Cost Anomaly Detection</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {FIN_METRICS.map(m => (
          <div key={m.service} className={`glass-panel p-5 flex items-center justify-between group ${m.status === 'critical' ? 'border-red-500/30' : 'border-white/5'}`}>
             <div className="flex items-center gap-4">
               <div className={`p-3 rounded-lg ${m.status === 'critical' ? 'bg-red-500/10 text-red-400' : m.status === 'anomaly' ? 'bg-orange-500/10 text-orange-400' : 'bg-white/5 text-gray-400'}`}>
                 <Activity size={20} />
               </div>
               <div>
                  <h4 className="font-semibold text-gray-100">{m.service}</h4>
                  <p className="text-sm text-gray-500">Current running cost</p>
               </div>
             </div>
             <div className="text-right">
               <p className="text-xl font-bold text-white">${m.cost.toFixed(2)}</p>
               <p className={`text-sm font-medium flex items-center justify-end gap-1 ${
                 m.drift.startsWith('+') ? 'text-red-400' : 'text-emerald-400'
               }`}>
                 {m.drift.startsWith('+') ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                 {m.drift}
               </p>
             </div>
          </div>
        ))}
      </div>
    </div>
  )
}
