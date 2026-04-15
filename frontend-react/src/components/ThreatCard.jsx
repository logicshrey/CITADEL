import { motion as Motion } from 'framer-motion'
import RiskBadge from './RiskBadge'

function formatList(values, fallback = 'None detected') {
  if (!values || values.length === 0) {
    return fallback
  }

  return values.join(', ')
}

function toPercent(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null
  }
  return value <= 1 ? Math.round(value * 100) : Math.round(value)
}

function toScore(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null
  }
  return value <= 1 ? Math.round(value * 100) : Math.round(value)
}

function formatBreakdown(entries = []) {
  if (!entries.length) {
    return 'No confirmed exposed data types yet'
  }

  return entries
    .map((entry) => {
      const label = entry?.label || 'undetermined'
      const count = typeof entry?.count === 'number' ? ` (${entry.count})` : ''
      return `${label}${count}`
    })
    .join(', ')
}

function formatRelations(relations = []) {
  if (!relations.length) {
    return 'No supporting source agreement yet'
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
  const confidencePercent = toPercent(confidence)
  const intelScore = toScore(riskScore)
  const affectedAssets = externalIntel.affected_assets || entities.filter((entity) => ['EMAIL', 'DOMAIN', 'IP', 'TOKEN', 'WALLET'].includes(entity.label)).map((entity) => entity.text)
  const businessImpact =
    impact?.business_risk ||
    'This signal needs analyst review before it can be treated as a confirmed organizational exposure.'
  const recommendedAction =
    threatType === 'Credential Leak'
      ? 'Verify ownership of the exposed accounts, then reset credentials and review MFA coverage.'
      : threatType === 'Database Dump'
        ? 'Confirm whether the data belongs to the organization and assess whether regulated records are involved.'
        : threatType === 'Phishing'
          ? 'Verify whether the lure targets the organization and warn affected users if the evidence is confirmed.'
          : 'Review the evidence, confirm the affected asset, and decide whether the finding requires escalation.'
  const shortSummary =
    externalIntel.summary ||
    impact?.summary ||
    explanation?.[0] ||
    `${threatType} signal detected and queued for analyst review.`
  const whyItMatters =
    hasExternalIntel
      ? `${businessImpact} Estimated exposure: ${externalIntel.estimated_records || 'amount not yet confirmed'}.`
      : businessImpact
  const analystDetails = [
    explanation.length ? `Detection notes: ${explanation.join(' ')}` : null,
    entities.length ? `Extracted entities: ${formatList(entities.map((entity) => entity.text))}` : null,
    correlation?.correlated_alerts_count
      ? `Historical matches: ${correlation.correlated_alerts_count} linked alert(s), score ${correlation.campaign_score}.`
      : 'Historical matches: no strong previous links.',
    Object.keys(patterns || {}).length ? `Pattern buckets: ${Object.keys(patterns).filter((key) => patterns[key]?.length).join(', ')}` : null,
    slang?.decoded_terms?.length
      ? `Decoded slang: ${slang.decoded_terms.map((term) => `${term.phrase} = ${term.meaning}`).join(', ')}`
      : null,
    multilingual?.translated_terms?.length
      ? `Language normalization: ${multilingual.translated_terms.map((term) => `${term.source} = ${term.normalized}`).join(', ')}`
      : null,
  ].filter(Boolean)

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
            <p className="mt-3 max-w-3xl text-sm text-slate-300">{shortSummary}</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <RiskBadge level={riskLevel} />
            {confidencePercent !== null && (
              <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                Confidence {confidencePercent}%
              </div>
            )}
            {priority?.priority ? (
              <div className="terminal-text rounded-full border border-[#00E5FF]/20 bg-[#00E5FF]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#A8F3FF]">
                Response priority {priority.priority}
              </div>
            ) : null}
            {source ? (
              <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                Source {source}
              </div>
            ) : null}
            {intelScore !== null ? (
              <div className="terminal-text rounded-full border border-[#00FF9F]/20 bg-[#00FF9F]/10 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-[#B8FFE0]">
                Evidence score {intelScore}
              </div>
            ) : null}
          </div>
        </div>

        {timestamp && (
          <p className="terminal-text text-xs uppercase tracking-[0.22em] text-slate-500">
            Timestamp {new Date(timestamp).toLocaleString()}
          </p>
        )}

        {!compact && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">What happened</p>
              <p className="mt-2 text-sm text-slate-200">
                {hasExternalIntel
                  ? `${source || 'A monitored source'} reported ${threatType.toLowerCase()} activity connected to ${externalIntel.organization || 'the requested organization'}.`
                  : `${threatType} indicators were found in the submitted text.`}
              </p>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Why it matters</p>
              <p className="mt-2 text-sm text-slate-200">{whyItMatters}</p>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Affected assets</p>
              <p className="mt-2 text-sm text-slate-200">{formatList(affectedAssets, 'No confirmed organization assets yet')}</p>
            </div>

            <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Recommended next step</p>
              <p className="mt-2 text-sm text-slate-200">
                {recommendedAction}
              </p>
            </div>
          </div>
        )}

        {!compact && hasExternalIntel && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Confirmed exposed data</p>
                <p className="mt-2 text-sm text-slate-200">{formatBreakdown(externalIntel.data_breakdown || [])}</p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Estimated size</p>
                <p className="mt-2 text-sm text-slate-200">
                  {externalIntel.estimated_records || 'Amount not disclosed by the source'}
                </p>
                <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                  Supporting evidence items {externalIntel.volume || 0}
                </p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Confirmed organization assets</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.affected_assets || [], 'No affected assets extracted')}
                </p>
              </div>

              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Supporting source agreement</p>
                <p className="mt-2 text-sm text-slate-200">{formatRelations(externalIntel.related_sources || [])}</p>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Where it was observed</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.source_locations || [], 'No source location metadata')}
                </p>
              </div>
              <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Matched organization indicators</p>
                <p className="mt-2 text-sm text-slate-200">
                  {formatList(externalIntel.matched_indicators || [], 'No stable indicators extracted')}
                </p>
              </div>
            </div>
          </div>
        )}

        {!compact && explanation.length > 0 && (
          <div className="rounded-[22px] border border-[#00FF9F]/12 bg-[#00FF9F]/6 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-[#00FF9F]">Why this result needs attention</p>
            <ul className="mt-3 space-y-2 text-sm text-slate-200">
              {explanation.slice(0, 5).map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </div>
        )}

        {!compact && analystDetails.length > 0 ? (
          <details className="rounded-[22px] border border-white/8 bg-black/10 p-4">
            <summary className="cursor-pointer text-xs uppercase tracking-[0.3em] text-slate-400">Analyst details</summary>
            <ul className="mt-3 space-y-2 text-sm text-slate-300">
              {analystDetails.map((line) => (
                <li key={line}>• {line}</li>
              ))}
            </ul>
          </details>
        ) : null}
      </div>
    </Motion.article>
  )
}

export default ThreatCard
