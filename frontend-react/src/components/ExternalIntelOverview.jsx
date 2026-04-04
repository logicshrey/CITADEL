import { motion as Motion } from 'framer-motion'

function formatList(values, fallback = 'No confirmed signals') {
  if (!Array.isArray(values) || values.length === 0) {
    return fallback
  }

  return values.join(', ')
}

function formatBreakdown(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
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

function priorityClasses(priority) {
  if (priority === 'CRITICAL') {
    return 'border-[#FF3B3B]/60 bg-[#FF3B3B]/12 text-[#FF9A9A]'
  }
  if (priority === 'HIGH') {
    return 'border-[#FFC857]/50 bg-[#FFC857]/10 text-[#FFD98C]'
  }
  if (priority === 'MEDIUM') {
    return 'border-[#00E5FF]/40 bg-[#00E5FF]/10 text-[#A8F3FF]'
  }
  return 'border-[#00FF9F]/40 bg-[#00FF9F]/10 text-[#B8FFE0]'
}

function MetricCard({ label, value, accent, helper }) {
  return (
    <div className="glass-card rounded-[24px] p-4">
      <p className="text-xs uppercase tracking-[0.28em] text-slate-500">{label}</p>
      <p className="mt-3 text-2xl font-semibold text-white">{value}</p>
      {helper ? <p className={`mt-2 text-sm ${accent}`}>{helper}</p> : null}
    </div>
  )
}

function ExternalIntelOverview({ summary }) {
  if (!summary) {
    return null
  }

  const combinedPriority = summary.combined_priority || {}
  const sourceBreakdown = summary.source_breakdown || []
  const crossSourceRelations = summary.cross_source_relations || []

  return (
    <Motion.section
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card neon-panel rounded-[32px] p-6"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.38em] text-[#00E5FF]">Exposure Command Center</p>
          <h3 className="mt-3 text-3xl font-semibold text-white">Centralized leak picture for {summary.organization}</h3>
          <p className="mt-4 max-w-4xl text-sm text-slate-300">
            This rollup consolidates where the data appeared, what was exposed, how large the leak looks, and
            which sources corroborate each other.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div
            className={`terminal-text rounded-full border px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.28em] ${priorityClasses(
              combinedPriority.priority,
            )}`}
          >
            Combined Priority {combinedPriority.priority || 'LOW'}
          </div>
          <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-slate-300">
            Score {combinedPriority.priority_score ?? 0}
          </div>
          <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-slate-300">
            Sources {summary.source_count ?? 0}
          </div>
        </div>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Leak Sources"
          value={summary.source_count ?? 0}
          helper={formatList(summary.platforms, 'No confirmed leak surfaces yet')}
          accent="text-[#FFC857]"
        />
        <MetricCard
          label="Estimated Exposure"
          value={summary.estimated_total_records_label || 'Unknown'}
          helper={`${summary.total_evidence_items ?? 0} evidence item(s) processed`}
          accent="text-[#00E5FF]"
        />
        <MetricCard
          label="Affected Assets"
          value={summary.affected_assets?.length ?? 0}
          helper={formatList(summary.affected_assets, 'No explicit assets extracted')}
          accent="text-[#00FF9F]"
        />
        <MetricCard
          label="Cross-source Links"
          value={crossSourceRelations.length}
          helper={
            crossSourceRelations.length
              ? formatList(crossSourceRelations[0]?.sources, 'No corroborated source links')
              : 'No corroborated source links'
          }
          accent="text-[#FFB4B4]"
        />
      </div>

      <div className="mt-6 rounded-[24px] border border-[#00FF9F]/12 bg-[#00FF9F]/6 p-4">
        <p className="text-xs uppercase tracking-[0.3em] text-[#00FF9F]">Priority Rationale</p>
        <p className="mt-3 text-sm text-slate-200">{formatList(combinedPriority.rationale, 'No rationale available')}</p>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="space-y-4">
          <div className="rounded-[24px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Leak Data Breakdown</p>
            <p className="mt-3 text-sm text-slate-200">{formatBreakdown(summary.data_type_breakdown)}</p>
          </div>

          <div className="rounded-[24px] border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Recurring Indicators</p>
            <p className="mt-3 text-sm text-slate-200">
              {formatList(summary.recurring_indicators, 'No recurring indicators extracted across sources')}
            </p>
          </div>
        </div>

        <div className="rounded-[24px] border border-white/8 bg-black/10 p-4">
          <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Cross-source Correlation</p>
          <div className="mt-3 space-y-3">
            {crossSourceRelations.length ? (
              crossSourceRelations.map((relation) => (
                <div key={`${relation.sources.join('-')}-${relation.strength_score}`} className="rounded-[18px] border border-white/8 bg-white/5 p-3">
                  <p className="text-sm font-semibold text-white">
                    {relation.sources.join(' <-> ')} | strength {relation.strength_score}
                  </p>
                  <p className="mt-2 text-sm text-slate-300">{relation.summary}</p>
                  <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                    Shared indicators: {formatList(relation.shared_indicators, 'none')}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-sm text-slate-400">
                No strong cross-source relationships have been extracted yet.
              </p>
            )}
          </div>
        </div>
      </div>

      <div className="mt-6">
        <p className="text-xs uppercase tracking-[0.34em] text-[#FFC857]">Where The Data Is Exposed</p>
        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          {sourceBreakdown.map((entry) => (
            <div key={`${entry.source}-${entry.timestamp || entry.summary}`} className="rounded-[24px] border border-white/8 bg-black/10 p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <p className="text-lg font-semibold text-white">{entry.source}</p>
                  <p className="mt-1 text-sm text-slate-300">{entry.summary}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <div className={`terminal-text rounded-full border px-3 py-1 text-[11px] uppercase tracking-[0.24em] ${priorityClasses(entry.priority)}`}>
                    {entry.priority}
                  </div>
                  <div className="terminal-text rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                    {entry.threat_type}
                  </div>
                </div>
              </div>

              <div className="mt-4 grid gap-3 md:grid-cols-2">
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Data Leaked</p>
                  <p className="mt-2 text-sm text-slate-200">{formatBreakdown(entry.data_breakdown)}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Amount</p>
                  <p className="mt-2 text-sm text-slate-200">{entry.estimated_records}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Affected Assets</p>
                  <p className="mt-2 text-sm text-slate-200">{formatList(entry.affected_assets, 'No assets extracted')}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Observed Locations</p>
                  <p className="mt-2 text-sm text-slate-200">{formatList(entry.source_locations, 'No location metadata')}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Motion.section>
  )
}

export default ExternalIntelOverview
