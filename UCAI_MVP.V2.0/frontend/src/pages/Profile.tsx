import { User, Mail, Shield, Building, Key, Activity, UploadCloud, LogOut } from 'lucide-react'
import { useAuth } from '../AuthContext'
import { auth, storage } from '../firebase'
import { signOut } from 'firebase/auth'
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage'
import { useState } from 'react'

export default function Profile() {
  const { user } = useAuth()
  const [photoURL, setPhotoURL] = useState(user?.photoURL || '')
  const [uploading, setUploading] = useState(false)

  const handleSignOut = () => {
    signOut(auth)
  }

  const handlePhotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !user) return

    try {
      setUploading(true)
      const storageRef = ref(storage, `avatars/${user.uid}`)
      await uploadBytes(storageRef, file)
      const url = await getDownloadURL(storageRef)
      setPhotoURL(url)
      setUploading(false)
      alert('Avatar uploaded to Firebase Storage successfully!')
    } catch (err: any) {
      alert('Error uploading to storage: ' + err.message)
      setUploading(false)
    }
  }

  return (
    <div className="space-y-8 animate-fade-in max-w-4xl">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-tight">Admin Profile</h2>
          <p className="text-gray-400 mt-2">Manage your Unified Autonomous Cloud Intelligence access and permissions.</p>
        </div>
        <button onClick={handleSignOut} className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 rounded-lg text-sm font-bold border border-red-500/20 transition-all">
          <LogOut size={16} /> Terminate Session
        </button>
      </div>

      <div className="glass-panel p-8 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl -mr-10 -mt-10" />
        
        <div className="flex items-center gap-8 relative z-10">
          <div className="relative group cursor-pointer">
            {photoURL ? (
              <img src={photoURL} alt="Avatar" className="w-28 h-28 rounded-full border-4 border-[#0A0D14] object-cover shadow-[0_0_30px_rgba(59,130,246,0.3)]" />
            ) : (
              <div className="w-28 h-28 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-4xl font-bold border-4 border-[#0A0D14] shadow-[0_0_30px_rgba(59,130,246,0.3)]">
                {user?.email?.charAt(0).toUpperCase()}
              </div>
            )}
            
            <label className="absolute inset-0 flex items-center justify-center bg-black/60 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer">
              {uploading ? <Activity size={24} className="animate-spin" /> : <UploadCloud size={24} />}
              <input type="file" className="hidden" accept="image/*" onChange={handlePhotoUpload} disabled={uploading} />
            </label>
          </div>

          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">System Administrator</h1>
            <p className="text-blue-400 font-medium flex items-center gap-2 mt-1">
              <Shield size={16} /> Global Super Admin
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-12 relative z-10">
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-gray-200 border-b border-white/10 pb-2 flex items-center justify-between">
              Account Details
              <span className="text-xs font-normal px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">Firebase Auth</span>
            </h3>
            <div className="space-y-4">
              <ProfileItem icon={<User size={18} />} label="UID" value={user?.uid || 'N/A'} />
              <ProfileItem icon={<Mail size={18} />} label="Email Address" value={user?.email || 'N/A'} />
              <ProfileItem icon={<Building size={18} />} label="Organization" value="UACI Global Command" />
            </div>
          </div>
          
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-gray-200 border-b border-white/10 pb-2 flex items-center gap-2">
              <UploadCloud size={18} className="text-blue-400" /> Cloud Integrations
            </h3>
            <div className="space-y-4">
              <form onSubmit={async (e) => {
                  e.preventDefault()
                  const formData = new FormData(e.currentTarget)
                  try {
                    const res = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8080/api'}/projects/connect-project`, {
                        method: 'POST',
                        body: formData
                    })
                    const data = await res.json()
                    alert(data.message || data.detail || 'Connected')
                  } catch(e: any) { alert(e.message) }
              }} className="p-4 bg-white/5 border border-blue-500/20 rounded-xl space-y-4 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl -mr-10 -mt-10" />
                  <p className="text-sm text-gray-300 font-medium relative z-10">Connect New GCP Project</p>
                  <div className="space-y-2 relative z-10">
                    <input name="project_id" placeholder="GCP Project ID" required className="w-full bg-[#0A0D14] border border-white/10 rounded-lg p-2.5 text-sm text-white focus:border-blue-500 outline-none" />
                    <div className="flex items-center gap-2">
                      <input name="service_account_json" type="file" required accept=".json" className="text-xs text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-blue-500/10 file:text-blue-400 hover:file:bg-blue-500/20" />
                    </div>
                  </div>
                  <button type="submit" className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-lg shadow-lg relative z-10 transition-colors">
                    Authenticate & Connect
                  </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function ProfileItem({ icon, label, value, className = "text-white" }: { icon: React.ReactNode, label: string, value: string, className?: string }) {
  return (
    <div className="flex items-center gap-4">
      <div className="p-2 bg-white/5 rounded-lg text-gray-400">
        {icon}
      </div>
      <div>
        <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">{label}</p>
        <p className={`text-sm font-medium tracking-wide mt-0.5 truncate max-w-[200px] ${className}`}>{value}</p>
      </div>
    </div>
  )
}
