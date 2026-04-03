import { motion as Motion } from 'framer-motion'
import RiskBadge from './RiskBadge'

function formatList(values) {
  if (!values || values.length === 0) {
    return 'None detected'
  }

  return values.join(', ')
}

function flattenPatterns(patterns = {}) {
  return Object.entries(patterns)
    .filter(([, values]) => Array.isArray(values) && values.length > 0)
    .map(([key, values]) => `${key}: ${values.join(', ')}`)
}

function ThreatCard({ title = 'Threat Result', item, compact = false }) {
  const threatType = item?.threat_type ?? item?.results?.threat_type ?? 'Unknown'
  const riskLevel = item?.risk_level ?? item?.results?.risk_level ?? 'LOW'
  const confidence = item?.confidence_score ?? item?.results?.confidence_score
  const timestamp = item?.timestamp ?? item?.results?.timestamp
  const entities = item?.entities ?? item?.results?.entities ?? []
  const patterns = item?.patterns ?? item?.results?.patterns ?? {}
  const explanation = item?.explanation ?? item?.results?.explanation ?? []

  return (
    <Motion.article
      whileHover={{ y: -5 }}
      transition={{ duration: 0.2 }}
      className="glass-card neon-panel scan-lines relative overflow-hidden rounded-[28px] p-5"
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">{title}</p>
            <h3 className="mt-2 text-xl font-semibold text-white">{threatType}</h3>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <RiskBadge level={riskLevel} />
            {typeof confidence === 'number' && (
              <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                Confidence {(confidence * 100).toFixed(1)}%
              </div>
            )}
          </div>
        </div>

        {timestamp && (
          <p className="terminal-text text-xs uppercase tracking-[0.22em] text-slate-500">
            Timestamp {new Date(timestamp).toLocaleString()}
          </p>
        )}

        {!compact && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Entities</p>
              <p className="mt-2 text-sm text-slate-200">
                {formatList(entities.map((entity) => `${entity.text} (${entity.label})`))}
              </p>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Patterns</p>
              <p className="mt-2 text-sm text-slate-200">{formatList(flattenPatterns(patterns))}</p>
            </div>
          </div>
        )}

        {!compact && explanation.length > 0 && (
          <div className="rounded-[22px] border border-[#00FF9F]/12 bg-[#00FF9F]/6 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-[#00FF9F]">Why it was flagged</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-200">
              {explanation.map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Motion.article>
  )
}

export default ThreatCard
