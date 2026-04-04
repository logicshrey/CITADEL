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

function formatBreakdown(entries = []) {
  if (!entries.length) {
    return 'No extracted leak data'
  }

  return entries
    .map((entry) => {
      const label = entry?.label || 'undetermined'
      const count = typeof entry?.count === 'number' ? ` (${entry.count})` : ''
      const samples = Array.isArray(entry?.samples) && entry.samples.length ? `: ${entry.samples.join(', ')}` : ''
      return `${label}${count}${samples}`
    })
    .join(' | ')
}

function formatRelations(relations = []) {
  if (!relations.length) {
    return 'No corroborating source links'
  }

  return relations
    .map((relation) => `${relation.source} (${relation.strength_score})`)
    .join(', ')
}

function ThreatCard({ title = 'Threat Result', item, compact = false }) {
  const threatType = item?.threat_type ?? item?.results?.threat_type ?? 'Unknown'
  const riskLevel = item?.risk_level ?? item?.results?.risk_level ?? 'LOW'
  const confidence = item?.confidence_score ?? item?.results?.confidence_score
  const timestamp = item?.timestamp ?? item?.results?.timestamp
  const entities = item?.entities ?? item?.results?.entities ?? []
  const patterns = item?.patterns ?? item?.results?.patterns ?? {}
  const explanation = item?.explanation ?? item?.results?.explanation ?? []
  const multilingual = item?.multilingual_analysis ?? item?.results?.multilingual_analysis ?? {}
  const slang = item?.slang_decoder ?? item?.results?.slang_decoder ?? {}
  const correlation = item?.correlation ?? item?.results?.correlation ?? {}
  const impact = item?.impact_assessment ?? item?.results?.impact_assessment ?? {}
  const priority = item?.alert_priority ?? item?.results?.alert_priority ?? {}
  const source = item?.source ?? item?.results?.source ?? item?.results?.external_intelligence?.source
  const riskScore = item?.risk_score ?? item?.results?.risk_score ?? item?.results?.external_intelligence?.risk_score
  const externalIntel = item?.external_intelligence ?? item?.results?.external_intelligence ?? {}
  const hasExternalIntel = Boolean(externalIntel?.source)

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
            {priority?.priority ? (
              <div className="terminal-text rounded-full border border-[#00E5FF]/20 bg-[#00E5FF]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]">
                Priority {priority.priority}
              </div>
            ) : null}
            {source ? (
              <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                Source {source}
              </div>
            ) : null}
            {typeof riskScore === 'number' ? (
              <div className="terminal-text rounded-full border border-[#00FF9F]/20 bg-[#00FF9F]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#B8FFE0]">
                Intel Score {(riskScore * 100).toFixed(0)}
              </div>
            ) : null}
          </div>
        </div>

        {timestamp && (
          <p className="terminal-text text-xs uppercase tracking-[0.22em] text-slate-500">
            Timestamp {new Date(timestamp).toLocaleString()}
          </p>
        )}

        {!compact && !hasExternalIntel && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
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

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Correlation</p>
              <p className="mt-2 text-sm text-slate-200">
                {correlation?.correlated_alerts_count
                  ? `${correlation.correlated_alerts_count} linked alerts, score ${correlation.campaign_score}`
                  : 'No strong historical links'}
              </p>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Impact</p>
              <p className="mt-2 text-sm text-slate-200">
                {impact?.business_risk ? `${impact.business_risk} (${impact.estimated_records})` : 'Impact not estimated'}
              </p>
            </div>
          </div>
        )}

        {!compact && hasExternalIntel && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Leak Data</p>
                <p className="mt-2 text-sm text-slate-200">{formatBreakdown(externalIntel.data_breakdown || [])}</p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Exposure Size</p>
                <p className="mt-2 text-sm text-slate-200">
                  {externalIntel.estimated_records || 'Amount not disclosed by the source'}
                </p>
                <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                  Evidence items {externalIntel.volume || 0}
                </p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Affected Assets</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.affected_assets || [], 'No affected assets extracted')}
                </p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Cross-source Links</p>
                <p className="mt-2 text-sm text-slate-200">{formatRelations(externalIntel.related_sources || [])}</p>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Leak Surface</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.source_locations || [], 'No source location metadata')}
                </p>
              </div>
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Matched Indicators</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.matched_indicators || [], 'No stable indicators extracted')}
                </p>
              </div>
            </div>
          </div>
        )}

        {!compact && (slang?.decoded_terms?.length || multilingual?.translated_terms?.length) ? (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-[22px] border border-[#00E5FF]/10 bg-[#00E5FF]/5 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-[#00E5FF]">Slang Decoder</p>
              <p className="mt-2 text-sm text-slate-200">
                {slang?.decoded_terms?.length
                  ? slang.decoded_terms.map((term) => `${term.phrase} -> ${term.meaning}`).join(', ')
                  : 'No coded language detected'}
              </p>
            </div>
            <div className="rounded-[22px] border border-[#FFC857]/10 bg-[#FFC857]/5 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-[#FFC857]">Language Normalization</p>
              <p className="mt-2 text-sm text-slate-200">
                {multilingual?.translated_terms?.length
                  ? `${multilingual.language}: ${multilingual.translated_terms.map((term) => `${term.source} -> ${term.normalized}`).join(', ')}`
                  : 'English or unknown; no translation needed'}
              </p>
            </div>
          </div>
        ) : null}

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
