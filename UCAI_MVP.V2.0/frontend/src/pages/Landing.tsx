import { Link } from 'react-router-dom';
import { Shield, Zap, Cpu, ArrowRight } from 'lucide-react';

export default function Landing() {
  return (
    <div className="min-h-screen bg-[#0A0D14] text-white overflow-hidden relative selection:bg-blue-500/30">
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[500px] bg-blue-600/20 rounded-full blur-[120px] opacity-50 pointer-events-none" />
      <div className="absolute top-1/4 right-0 w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[120px] opacity-30 pointer-events-none" />

      <nav className="relative z-10 flex items-center justify-between px-8 py-6 max-w-7xl mx-auto">
        <div className="flex items-center gap-2 text-xl font-bold tracking-wider">
          <Cpu className="text-blue-500" />
          <span className="neon-text-blue">UACI</span>
        </div>
        <div className="flex gap-4">
          <Link to="/login" className="px-5 py-2 text-sm font-medium text-gray-300 hover:text-white transition-colors">Sign In</Link>
          <Link to="/register" className="px-5 py-2 text-sm font-bold bg-blue-600 hover:bg-blue-500 text-white rounded-lg shadow-[0_0_15px_rgba(59,130,246,0.5)] transition-all active:scale-95 border border-blue-500/50">Get Started</Link>
        </div>
      </nav>

      <main className="relative z-10 max-w-7xl mx-auto px-8 pt-24 pb-32 text-center lg:pt-36">
         <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm font-semibold mb-8 animate-fade-in shadow-[0_0_15px_rgba(59,130,246,0.1)]">
           <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
          </span>
           Platform v1.0 Online & Ready
         </div>
         <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8 leading-tight">
            Unified Autonomous <br/>
            <span className="bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent">Cloud Intelligence</span>
         </h1>
         <p className="max-w-2xl mx-auto text-lg md:text-xl text-gray-400 mb-12 leading-relaxed">
            The next-generation autonomous AI ecosystem that detects, investigates, and remediates FinOps and Security incidents instantly. No waiting.
         </p>
         <div className="flex flex-col sm:flex-row items-center justify-center gap-6">
            <Link to="/register" className="w-full sm:w-auto px-8 py-4 text-base font-bold bg-blue-600 hover:bg-blue-500 text-white rounded-xl shadow-[0_0_20px_rgba(59,130,246,0.4)] transition-all hover:-translate-y-1 flex items-center justify-center gap-2 border border-blue-400">
              Launch Command Center <ArrowRight size={18} />
            </Link>
            <a href="#features" className="w-full sm:w-auto px-8 py-4 text-base font-bold bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-xl transition-all cursor-pointer">
              Explore The Platform
            </a>
         </div>

         <div id="features" className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-40 text-left">
            <FeatureCard icon={<Shield className="text-emerald-400"/>} title="Auto-Remediation" desc="Critical security vulnerabilities are mitigated in seconds via highly privileged agentic execution." />
            <FeatureCard icon={<Zap className="text-blue-400"/>} title="Real-time Telemetry" desc="Connects directly to your Google Cloud environment via BigQuery continuous event streams." />
            <FeatureCard icon={<Cpu className="text-purple-400"/>} title="Human in the Loop" desc="Maintain absolute control over Tier-1 production modifications via Approval gates." />
         </div>
      </main>
    </div>
  )
}

function FeatureCard({ icon, title, desc }: any) {
  return (
    <div className="glass-panel p-8 hover:-translate-y-2 transition-all duration-300 group hover:border-blue-500/30">
      <div className="w-14 h-14 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
        {icon}
      </div>
      <h3 className="text-xl font-bold text-white mb-3">{title}</h3>
      <p className="text-gray-400 leading-relaxed text-sm">{desc}</p>
    </div>
  )
}
