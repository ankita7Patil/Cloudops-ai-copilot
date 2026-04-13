import { useState } from 'react';
import { Navigate, Link } from 'react-router-dom';
import { signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth';
import { auth } from '../firebase';
import { useAuth } from '../AuthContext';
import { Cpu, ArrowLeft } from 'lucide-react';

export default function Auth({ mode }: { mode: 'login' | 'register' }) {
  const { user, loading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (loading) return <div className="h-screen bg-[#0A0D14] flex justify-center items-center"><div className="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full"/></div>;
  if (user) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      if (mode === 'login') {
        await signInWithEmailAndPassword(auth, email, password);
      } else {
        await createUserWithEmailAndPassword(auth, email, password);
      }
    } catch (err: any) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0A0D14] text-gray-100 font-sans p-4 relative overflow-hidden">
      <div className="absolute top-0 left-0 w-64 h-64 bg-blue-600/10 rounded-full blur-3xl -ml-10 -mt-10" />
      <div className="absolute bottom-0 right-0 w-64 h-64 bg-purple-600/10 rounded-full blur-3xl -mr-10 -mb-10" />
      
      <div className="w-full max-w-[400px] z-10">
        <Link to="/" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white mb-8 transition-colors">
          <ArrowLeft size={16} /> Back to Gateway
        </Link>
        <div className="glass-panel p-8 animate-fade-in shadow-2xl relative">
          <div className="flex justify-center mb-6">
            <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-xl flex items-center justify-center">
              <Cpu className="text-blue-400" size={24} />
            </div>
          </div>
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold text-white mb-2">{mode === 'login' ? 'Welcome Back' : 'Create Deployment'}</h2>
            <p className="text-sm text-gray-400">{mode === 'login' ? 'Sign in to access Command Center' : 'Register a new Admin instance'}</p>
          </div>

          {error && <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg text-center">{error}</div>}

          <form onSubmit={handleSubmit} className="space-y-4">
             <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase tracking-wider">Email Address</label>
                <input type="email" value={email} onChange={(e)=>setEmail(e.target.value)} placeholder="admin@domain.com" className="w-full bg-[#111827]/80 border border-white/10 rounded-lg p-3 text-white focus:border-blue-500 outline-none transition-colors" required />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-500 font-semibold uppercase tracking-wider">Passphrase</label>
                <input type="password" value={password} onChange={(e)=>setPassword(e.target.value)} placeholder="••••••••" className="w-full bg-[#111827]/80 border border-white/10 rounded-lg p-3 text-white focus:border-blue-500 outline-none transition-colors" required />
              </div>
              <button disabled={submitting} type="submit" className="w-full py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-lg font-bold transition-all shadow-lg shadow-blue-500/20 active:scale-95 disabled:opacity-50 mt-4">
                {submitting ? 'Processing...' : (mode === 'login' ? 'Sign In' : 'Register')}
              </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-400">
             {mode === 'login' ? 'Need clearance? ' : 'Already integrated? '}
             <Link to={mode === 'login' ? '/register' : '/login'} className="text-blue-400 hover:text-blue-300 font-medium tracking-wide">
               {mode === 'login' ? 'Register here' : 'Sign in here'}
             </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
