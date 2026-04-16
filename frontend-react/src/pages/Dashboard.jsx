import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import Loader from '../components/Loader'
import StatCard from '../components/StatCard'
import TerminalConsole from '../components/TerminalConsole'
import Toast from '../components/Toast'
import CyberCellReportModal from '../components/CyberCellReportModal'
import { exportPdfReport, getMonitoringStats } from '../services/api'

const pieColors = ['#00CFFF', '#FF3B3B', '#00FF9F', '#8B5CF6', '#FACC15']

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')
  const [exporting, setExporting] = useState(false)
  const [downloadProgress, setDownloadProgress] = useState(0)
  const [reportingOpen, setReportingOpen] = useState(false)
  const [lastExportVerification, setLastExportVerification] = useState(null)
  const [exportFilters, setExportFilters] = useState({
    orgId: '',
    startDate: '',
    endDate: '',
    severity: '',
    category: '',
  })

  useEffect(() => {
    const loadStats = async () => {
      setLoading(true)
      setToast('')

      try {
        const response = await getMonitoringStats()
        setStats(response)
      } catch (apiError) {
        setToast(
          apiError?.response?.data?.detail ||
            'Unable to reach the monitoring statistics endpoint. Ensure FastAPI is running.',
        )
      } finally {
        setLoading(false)
      }
    }

    loadStats()
  }, [])

  useEffect(() => {
    if (!toast) {
      return undefined
    }
    const timeoutId = window.setTimeout(() => setToast(''), 3500)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const severityData = useMemo(
    () => Object.entries(stats?.severity_distribution || stats?.priority_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const statusData = useMemo(
    () => Object.entries(stats?.status_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const sourceData = useMemo(
    () => Object.entries(stats?.source_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const categoryData = useMemo(
    () => Object.entries(stats?.category_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const confidenceData = useMemo(
    () => Object.entries(stats?.confidence_distribution || {}).map(([name, value]) => ({ name, value })),
    [stats],
  )
  const organizationOptions = useMemo(
    () =>
      Object.entries(stats?.organization_distribution || {})
        .sort((left, right) => right[1] - left[1])
        .map(([name, value]) => ({ name, value })),
    [stats],
  )
  const activeCases = stats?.active_cases ?? 0
  const criticalCases = stats?.critical_cases ?? 0
  const corroboratedCases = stats?.corroborated_cases ?? 0
  const watchlistHealth = stats?.watchlist_health || []
  const timelineData = (stats?.timeline || []).map((item) => ({
    bucket: item.bucket.slice(5),
    cases: item.cases,
  }))
  const consoleLines = [
    'Executive command view synchronized with the monitoring scheduler.',
    `Active cases ${activeCases}; critical cases ${criticalCases}; corroborated cases ${corroboratedCases}.`,
    `Enabled watchlists ${stats?.enabled_watchlists ?? 0}; new cases in the last 24h ${stats?.new_cases_24h ?? 0}.`,
    `Mean time to review ${stats?.mean_time_to_review_hours ?? 0} hours.`,
    `Last scheduler cycle: ${stats?.scheduler?.last_cycle_summary?.watchlists_executed ?? 0} watchlists executed.`,
  ]

  const handleExportPdf = async () => {
    if (!exportFilters.orgId) {
      setToast('Select an organization before exporting a PDF report.')
      return
    }

    setExporting(true)
    setDownloadProgress(0)

    try {
      const response = await exportPdfReport({
        orgId: exportFilters.orgId,
        startDate: exportFilters.startDate || undefined,
        endDate: exportFilters.endDate || undefined,
        severity: exportFilters.severity ? [exportFilters.severity] : [],
        category: exportFilters.category ? [exportFilters.category] : [],
        onDownloadProgress: (event) => {
          if (!event.total) {
            return
          }
          setDownloadProgress(Math.round((event.loaded / event.total) * 100))
        },
      })
      const url = URL.createObjectURL(response.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = response.filename
      anchor.click()
      URL.revokeObjectURL(url)
      setLastExportVerification({
        reportId: response.reportId,
        verificationUrl: response.verificationUrl,
        signatureStatus: response.signatureStatus,
        orgId: exportFilters.orgId,
      })
      setToast('PDF report exported successfully. CVRP verification details are available below.')
    } catch (apiError) {
      setToast(apiError?.response?.data?.detail || 'PDF report export failed.')
    } finally {
      setExporting(false)
      setDownloadProgress(0)
    }
  }

  const handleOpenCyberCellReport = () => {
    if (!exportFilters.orgId) {
      setToast('Select an organization before preparing a cyber cell report.')
      return
    }
    setReportingOpen(true)
  }

  const cyberCellDefaultRequest = {
    org_id: exportFilters.orgId || undefined,
    date_range:
      exportFilters.startDate || exportFilters.endDate
        ? {
            start_date: exportFilters.startDate || undefined,
            end_date: exportFilters.endDate || undefined,
          }
        : undefined,
    severity: exportFilters.severity ? [exportFilters.severity] : [],
    organization_details: {
      organization_name: exportFilters.orgId || '',
    },
  }

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <CyberCellReportModal
        isOpen={reportingOpen}
        onClose={() => setReportingOpen(false)}
        defaultRequest={cyberCellDefaultRequest}
        onSuccess={setToast}
        onError={setToast}
      />
      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid gap-4 md:grid-cols-2 xl:grid-cols-4"
      >
        <StatCard label="Active Cases" value={stats?.active_cases ?? '--'} accent="#00E5FF" icon="AC" />
        <StatCard label="Critical Cases" value={criticalCases} accent="#FF3B3B" icon="CC" pulse />
        <StatCard label="Corroborated" value={corroboratedCases} accent="#00FF9F" icon="CO" />
        <StatCard label="New In 24h" value={stats?.new_cases_24h ?? '--'} accent="#FFC857" icon="24" />
      </Motion.section>

      <Motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="glass-card neon-panel rounded-[32px] p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Executive Report Export</p>
            <h2 className="mt-2 text-3xl font-semibold text-white">Generate a PDF briefing</h2>
            <p className="mt-3 max-w-3xl text-sm text-slate-300">
              Export a professional CITADEL exposure intelligence report for one selected organization. Date,
              severity, and category filters are optional refinements.
            </p>
            <div className="mt-4 inline-flex items-center rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1.5 text-[11px] uppercase tracking-[0.26em] text-[#B8FFE3]">
              CVRP verified reporting enabled
            </div>
          </div>
          <div className="w-full xl:max-w-5xl">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[1.2fr_1fr_1fr]">
              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.24em] text-slate-400">Organization</span>
                <select
                  value={exportFilters.orgId}
                  onChange={(event) => setExportFilters((current) => ({ ...current, orgId: event.target.value }))}
                  className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                  style={{ color: exportFilters.orgId ? '#F8FAFC' : '#94A3B8' }}
                >
                  <option value="" style={{ color: '#0F172A', backgroundColor: '#F8FAFC' }}>
                    Select organization
                  </option>
                  {organizationOptions.map((organization) => (
                    <option
                      key={organization.name}
                      value={organization.name}
                      style={{ color: '#0F172A', backgroundColor: '#F8FAFC' }}
                    >
                      {organization.name} ({organization.value} case{organization.value === 1 ? '' : 's'})
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.24em] text-slate-400">Start date</span>
                <input
                  type="datetime-local"
                  value={exportFilters.startDate}
                  onChange={(event) => setExportFilters((current) => ({ ...current, startDate: event.target.value }))}
                  className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.24em] text-slate-400">End date</span>
                <input
                  type="datetime-local"
                  value={exportFilters.endDate}
                  onChange={(event) => setExportFilters((current) => ({ ...current, endDate: event.target.value }))}
                  className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                />
              </label>
            </div>

            <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-[1fr_1fr_auto_auto]">
              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.24em] text-slate-400">Severity filter</span>
                <select
                  value={exportFilters.severity}
                  onChange={(event) => setExportFilters((current) => ({ ...current, severity: event.target.value }))}
                  className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                >
                  <option value="">All severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </label>

              <label className="block">
                <span className="mb-2 block text-xs uppercase tracking-[0.24em] text-slate-400">Category filter</span>
                <select
                  value={exportFilters.category}
                  onChange={(event) => setExportFilters((current) => ({ ...current, category: event.target.value }))}
                  className="w-full rounded-[16px] border border-white/8 bg-black/10 px-4 py-3 text-sm text-slate-100 outline-none"
                >
                  <option value="">All categories</option>
                  {Object.keys(stats?.category_distribution || {}).map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
              </label>

              <div className="flex items-end">
                <button
                  type="button"
                  onClick={handleExportPdf}
                  disabled={exporting || !exportFilters.orgId}
                  className="terminal-text w-full rounded-[18px] bg-[linear-gradient(135deg,#00E5FF,#00FF9F)] px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-slate-950 disabled:opacity-60 xl:min-w-[220px]"
                >
                  {exporting ? `Exporting ${downloadProgress || 0}%` : 'Export PDF Report'}
                </button>
              </div>
              <div className="flex items-end">
                <button
                  type="button"
                  onClick={handleOpenCyberCellReport}
                  disabled={!exportFilters.orgId}
                  className="terminal-text w-full rounded-[18px] border border-[#FF3B3B]/30 bg-[#FF3B3B]/10 px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-[#FFD0D0] disabled:opacity-60 xl:min-w-[220px]"
                >
                  Report To Cyber Cell
                </button>
              </div>
            </div>

            <p className="mt-3 text-xs uppercase tracking-[0.2em] text-slate-500">
              Reports are exported for the selected organization only.
            </p>
            <p className="mt-2 text-sm text-slate-400">
              After each export, CITADEL creates a verification record with a report ID and public verification link.
            </p>
          </div>
        </div>
        {exporting ? (
          <div className="mt-5 h-3 overflow-hidden rounded-full bg-white/6">
            <Motion.div
              className="h-full rounded-full bg-[linear-gradient(90deg,#00E5FF,#00FF9F)]"
              initial={{ width: '0%' }}
              animate={{ width: `${Math.max(8, downloadProgress)}%` }}
            />
          </div>
        ) : null}
        {lastExportVerification ? (
          <div className="mt-5 rounded-[24px] border border-[#00E5FF]/20 bg-[rgba(2,6,23,0.82)] p-5">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-[#00E5FF]">Last exported CVRP record</p>
                <h3 className="mt-2 text-xl font-semibold text-white">Verification metadata ready</h3>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <p>Organization: <span className="text-white">{lastExportVerification.orgId}</span></p>
                  <p>Report ID: <span className="break-all text-white">{lastExportVerification.reportId || 'Unavailable'}</span></p>
                  <p>Signature status: <span className="text-white">{lastExportVerification.signatureStatus || 'unsigned'}</span></p>
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                {lastExportVerification.verificationUrl ? (
                  <a
                    href={lastExportVerification.verificationUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="terminal-text inline-flex rounded-[18px] border border-[#00E5FF]/35 bg-[#00E5FF]/10 px-5 py-3 text-sm font-bold uppercase tracking-[0.24em] text-[#CFFAFE]"
                  >
                    Open Verify Portal
                  </a>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}
      </Motion.section>

      {loading ? (
        <div className="glass-card rounded-[32px] p-8">
          <Loader label="Loading executive exposure dashboard..." />
        </div>
      ) : (
        <>
          <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
            <Motion.section
              initial={{ opacity: 0, x: -18 }}
              animate={{ opacity: 1, x: 0 }}
              className="glass-card neon-panel rounded-[32px] p-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Executive Exposure Overview</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">Case volume over time</h2>
                </div>
                <div className="terminal-text rounded-full border border-white/8 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-slate-400">
                  real monitoring data
                </div>
              </div>

              <div className="mt-6 h-[26rem] rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(2,6,23,0.95),rgba(15,23,42,0.75))] p-4">
                {timelineData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="caseTimelineFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.45} />
                          <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.04} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="bucket" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 16 }} />
                      <Area type="monotone" dataKey="cases" stroke="#00E5FF" fill="url(#caseTimelineFill)" strokeWidth={3} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No timeline data available yet.</div>
                )}
              </div>
            </Motion.section>

            <Motion.section
              initial={{ opacity: 0, x: 18 }}
              animate={{ opacity: 1, x: 0 }}
              className="grid gap-4"
            >
              {[
                { label: 'Enabled Watchlists', value: stats?.enabled_watchlists ?? 0, accent: '#00FF9F' },
                { label: 'Mean Time To Review', value: stats?.mean_time_to_review_hours ?? 0, accent: '#FFC857' },
                { label: 'Case Backlog', value: activeCases, accent: '#00E5FF' },
                { label: 'Scheduler Runs', value: stats?.scheduler?.last_cycle_summary?.watchlists_executed ?? 0, accent: '#FF3B3B' },
              ].map((metric) => (
                <div key={metric.label} className="glass-card neon-panel rounded-[28px] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs uppercase tracking-[0.34em] text-slate-400">{metric.label}</p>
                    <p className="terminal-text text-sm" style={{ color: metric.accent }}>
                      {metric.value}
                    </p>
                  </div>
                  <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/6">
                    <Motion.div
                      className="h-full rounded-full"
                      style={{ background: `linear-gradient(90deg, ${metric.accent}, transparent)` }}
                      initial={{ width: '0%' }}
                      animate={{ width: `${Math.min(100, Math.max(10, Number(metric.value) || 0))}%` }}
                      transition={{ duration: 1 }}
                    />
                  </div>
                </div>
              ))}
            </Motion.section>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr_0.8fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Priority Distribution</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Exposure case severity</h3>
              <div className="mt-6 h-80">
                {severityData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={severityData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {severityData.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.name === 'Critical' ? '#FF3B3B' : entry.name === 'High' ? '#FF7A7A' : entry.name === 'Medium' ? '#FFC857' : '#00FF9F'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No priority data yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Workflow States</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Case triage progress</h3>
              <div className="mt-6 h-80">
                {statusData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={statusData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={92} paddingAngle={4}>
                        {statusData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,200,87,0.2)', borderRadius: 16 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No workflow data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Case Categories</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Most common exposure categories</h3>
              <div className="mt-6 h-80">
                {categoryData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={categoryData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,255,159,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[12, 12, 0, 0]}>
                        {categoryData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No exposure breakdown available yet.</div>
                )}
              </div>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-[0.9fr_0.9fr_1.2fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FF3B3B]">Source Coverage</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Cases by monitored source</h3>
              <div className="mt-6 h-72">
                {sourceData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sourceData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {sourceData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No source data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Confidence Distribution</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">How certain the findings are</h3>
              <div className="mt-6 h-72">
                {confidenceData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={confidenceData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,200,87,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {confidenceData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No confidence distribution available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Watchlist Health</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Collector performance</h3>
              <div className="mt-6 space-y-4">
                {watchlistHealth.length ? (
                  watchlistHealth.map((watchlist) => (
                    <div key={watchlist.id} className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-semibold text-white">{watchlist.name}</p>
                        <p className={`terminal-text text-[11px] uppercase tracking-[0.24em] ${watchlist.last_error ? 'text-[#FFB4B4]' : 'text-[#B8FFE0]'}`}>
                          {watchlist.last_error ? 'Attention' : 'Healthy'}
                        </p>
                      </div>
                      <p className="mt-2 text-sm text-slate-300">
                        {watchlist.last_error
                          ? watchlist.last_error
                          : `Last run ${watchlist.last_duration_ms || 0} ms, ${watchlist.last_case_count || 0} cases touched.`}
                      </p>
                      <p className="mt-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                        {watchlist.last_success_at ? `Success ${new Date(watchlist.last_success_at).toLocaleString()}` : 'No successful run yet'}
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[22px] border border-white/8 bg-black/10 p-4 text-slate-400">
                    No watchlists configured yet.
                  </div>
                )}
              </div>
            </div>
          </div>

          <TerminalConsole
            key={consoleLines.join('|')}
            title="Executive Console"
            lines={consoleLines}
            accent="#00FF9F"
            minHeight="min-h-[240px]"
          />
        </>
      )}
    </div>
  )
}

export default Dashboard
