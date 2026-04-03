import { motion as Motion } from 'framer-motion'

function StatCard({ label, value, accent = '#00E5FF', hint, icon, pulse = false }) {
  return (
    <Motion.div
      whileHover={{ y: -6, scale: 1.01 }}
      transition={{ duration: 0.2 }}
      className="glass-card neon-panel rounded-[28px] p-5"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.34em] text-slate-400">{label}</p>
          <div className="mt-4 flex items-end gap-3">
            <p className="text-3xl font-semibold text-white">{value}</p>
            {hint ? <p className="pb-1 text-xs uppercase tracking-[0.2em] text-slate-500">{hint}</p> : null}
          </div>
        </div>

        <div
          className={`flex h-11 w-11 items-center justify-center rounded-2xl border border-white/8 bg-white/5 text-sm ${pulse ? 'flicker' : ''}`}
          style={{ color: accent, boxShadow: `0 0 20px ${accent}22` }}
        >
          {icon || '::'}
        </div>
      </div>

      <div className="mt-5 h-1.5 w-full overflow-hidden rounded-full bg-white/6">
        <Motion.div
          className="h-full rounded-full"
          style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }}
          initial={{ width: '18%' }}
          animate={{ width: '82%' }}
          transition={{ duration: 1, ease: 'easeOut' }}
        />
      </div>
    </Motion.div>
  )
}

export default StatCard
