import { motion as Motion } from 'framer-motion'

const riskPalette = {
  LOW: '#00FF9F',
  MEDIUM: '#FFC857',
  HIGH: '#FF3B3B',
}

function CircularProgress({ value = 0, riskLevel = 'LOW', label = 'Threat Level' }) {
  const normalizedRisk = String(riskLevel || 'LOW').toUpperCase()
  const color = riskPalette[normalizedRisk] || riskPalette.LOW
  const normalizedValue = Math.max(0, Math.min(100, value))
  const circumference = 2 * Math.PI * 70
  const offset = circumference - (normalizedValue / 100) * circumference

  return (
    <div className="glass-card neon-panel rounded-[28px] p-6">
      <p className="text-xs uppercase tracking-[0.34em] text-slate-400">{label}</p>
      <div className="mt-4 flex items-center justify-center">
        <div className="relative h-56 w-56">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 180 180">
            <circle cx="90" cy="90" r="70" stroke="rgba(148,163,184,0.16)" strokeWidth="14" fill="transparent" />
            <Motion.circle
              cx="90"
              cy="90"
              r="70"
              stroke={color}
              strokeWidth="14"
              strokeLinecap="round"
              fill="transparent"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset: offset }}
              transition={{ duration: 1.1, ease: 'easeOut' }}
              style={{ filter: `drop-shadow(0 0 12px ${color})` }}
            />
          </svg>

          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <Motion.p
              initial={{ opacity: 0, scale: 0.92 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-5xl font-semibold text-white"
            >
              {Math.round(normalizedValue)}
            </Motion.p>
            <p className="mt-2 text-xs uppercase tracking-[0.32em]" style={{ color }}>
              {normalizedRisk}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CircularProgress
