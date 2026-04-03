import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'

function TerminalConsole({
  title = 'System Console',
  lines = [],
  accent = '#00E5FF',
  typing = true,
  minHeight = 'min-h-[220px]',
}) {
  const normalizedLines = useMemo(() => lines.filter(Boolean), [lines])
  const [visibleCount, setVisibleCount] = useState(1)

  useEffect(() => {
    if (!typing || normalizedLines.length <= 1) {
      return
    }

    const intervalId = window.setInterval(() => {
      setVisibleCount((current) => {
        if (current >= normalizedLines.length) {
          window.clearInterval(intervalId)
          return current
        }
        return current + 1
      })
    }, 650)

    return () => window.clearInterval(intervalId)
  }, [normalizedLines, typing])

  const linesToRender = typing ? normalizedLines.slice(0, visibleCount) : normalizedLines

  return (
    <div className={`glass-card neon-panel rounded-[28px] p-5 ${minHeight}`}>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.34em]" style={{ color: accent }}>
            {title}
          </p>
          <p className="mt-2 text-sm text-slate-400">Live event trace and model orchestration logs</p>
        </div>
        <div className="terminal-text rounded-full border border-white/8 bg-black/20 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-slate-400">
          trace online
        </div>
      </div>

      <div className="terminal-text rounded-[22px] border border-white/8 bg-[#020617]/85 p-4 text-sm text-slate-300 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
        {normalizedLines.length === 0 ? (
          <p className="text-slate-500">No console activity available.</p>
        ) : (
          <div className="space-y-2">
            {linesToRender.map((line, index) => (
              <Motion.p
                key={`${line}-${index}`}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                className={index === linesToRender.length - 1 && typing && visibleCount < normalizedLines.length ? 'terminal-caret' : ''}
              >
                <span style={{ color: accent }}>&gt;&gt;&gt;</span> {line}
              </Motion.p>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default TerminalConsole
