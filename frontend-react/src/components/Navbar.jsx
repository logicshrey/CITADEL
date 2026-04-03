import { motion as Motion } from 'framer-motion'
import { NavLink } from 'react-router-dom'

const navItems = [
  { label: 'Analyzer', path: '/analyzer' },
  { label: 'Dashboard', path: '/dashboard' },
  { label: 'Threat Feed', path: '/feed' },
  { label: 'Upload', path: '/upload' },
]

function Navbar() {
  return (
    <Motion.header
      initial={{ opacity: 0, y: -18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="glass-card sticky top-4 z-30 rounded-3xl px-4 py-4 sm:px-6"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.4em] text-[#00CFFF]">Cyber Threat Intelligence</p>
          <h1 className="mt-2 text-2xl font-semibold text-white sm:text-3xl">
            Dark Web Threat Intelligence System
          </h1>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2 rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1.5 text-xs text-[#B8FFE3]">
            <span className="h-2.5 w-2.5 rounded-full bg-[#00FF9F] shadow-[0_0_12px_rgba(0,255,159,0.7)]" />
            API-driven React frontend
          </div>

          <nav className="flex flex-wrap gap-2">
            {navItems.map((item) => (
              <NavLink key={item.path} to={item.path}>
                {({ isActive }) => (
                  <Motion.span
                    whileHover={{ y: -1, scale: 1.01 }}
                    whileTap={{ scale: 0.98 }}
                    className={`inline-flex rounded-full px-4 py-2 text-sm font-medium transition ${
                      isActive
                        ? 'bg-[#00CFFF]/18 text-[#D6F7FF] shadow-[0_0_18px_rgba(0,207,255,0.16)]'
                        : 'bg-white/4 text-slate-300 hover:bg-white/8 hover:text-white'
                    }`}
                  >
                    {item.label}
                  </Motion.span>
                )}
              </NavLink>
            ))}
          </nav>
        </div>
      </div>
    </Motion.header>
  )
}

export default Navbar
