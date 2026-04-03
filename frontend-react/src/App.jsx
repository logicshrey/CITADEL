import { Navigate, Route, Routes } from 'react-router-dom'
import { motion as Motion } from 'framer-motion'
import Navbar from './components/Navbar'
import Analyzer from './pages/Analyzer'
import Dashboard from './pages/Dashboard'
import Feed from './pages/Feed'
import Upload from './pages/Upload'

function App() {
  return (
    <div className="min-h-screen bg-[#0A0F1C] text-[#E5E7EB]">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-0 top-0 h-96 w-96 rounded-full bg-[#00CFFF]/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-[28rem] w-[28rem] rounded-full bg-[#00FF9F]/10 blur-3xl" />
        <div className="absolute left-1/2 top-1/3 h-80 w-80 -translate-x-1/2 rounded-full bg-[#FF3B3B]/8 blur-3xl" />
        <div className="cyber-grid absolute inset-0 opacity-30" />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <Navbar />
        <Motion.main
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45 }}
          className="flex-1 py-6"
        >
          <Routes>
            <Route path="/" element={<Navigate to="/analyzer" replace />} />
            <Route path="/analyzer" element={<Analyzer />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/feed" element={<Feed />} />
            <Route path="/upload" element={<Upload />} />
          </Routes>
        </Motion.main>
      </div>
    </div>
  )
}

export default App
