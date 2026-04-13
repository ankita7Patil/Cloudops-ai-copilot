import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './AuthContext'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import Dashboard from './pages/Dashboard'
import Profile from './pages/Profile'
import CommandCenter from './pages/CommandCenter'
import Incidents from './pages/Incidents'
import FinOps from './pages/FinOps'
import Projects from './pages/Projects'
import ProjectDetail from './pages/ProjectDetail'
import Landing from './pages/Landing'
import Auth from './pages/Auth'

function ProtectedRoute({ children }: { children: JSX.Element }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="h-screen bg-[#0A0D14] flex items-center justify-center"><div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"/></div>
  if (!user) return <Navigate to="/login" replace />
  return children
}

function DashboardLayout() {
  return (
    <div className="flex h-screen bg-[#0A0D14] text-gray-100 overflow-hidden font-sans antialiased">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen relative">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-4 md:p-8 relative z-0">
          <div className="mx-auto max-w-7xl">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/command-center" element={<CommandCenter />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/finops" element={<FinOps />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/projects/:projectId" element={<ProjectDetail />} />
              <Route path="/profile" element={<Profile />} />
            </Routes>
          </div>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Auth mode="login" />} />
      <Route path="/register" element={<Auth mode="register" />} />
      <Route path="/dashboard/*" element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
