import { useEffect, useState } from 'react'
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
import { getStats } from '../services/api'

const pieColors = ['#00CFFF', '#FF3B3B', '#00FF9F', '#8B5CF6', '#FACC15']

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')

  useEffect(() => {
    const loadStats = async () => {
      setLoading(true)
      setToast('')

      try {
        const response = await getStats()
        setStats(response)
      } catch (apiError) {
        setToast(
          apiError?.response?.data?.detail ||
            'Unable to reach backend statistics endpoint. Ensure FastAPI is running.',
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

  const threatData = Object.entries(stats?.threat_distribution || {}).map(([name, value]) => ({ name, value }))
  const riskData = Object.entries(stats?.risk_levels || {}).map(([name, value]) => ({ name, value }))
  const priorityData = Object.entries(stats?.priority_distribution || {}).map(([name, value]) => ({ name, value }))
  const languageData = Object.entries(stats?.language_distribution || {}).map(([name, value]) => ({ name, value }))
  const highRisk = stats?.risk_levels?.HIGH ?? 0
  const mediumRisk = stats?.risk_levels?.MEDIUM ?? 0
  const lowRisk = stats?.risk_levels?.LOW ?? 0
  const correlationOverview = stats?.correlation_overview || {}
  const activityData = [
    { time: '00:00', scans: Math.max(6, Math.round((stats?.total_alerts ?? 0) * 0.12)) },
    { time: '04:00', scans: Math.max(12, Math.round((stats?.total_alerts ?? 0) * 0.18)) },
    { time: '08:00', scans: Math.max(18, Math.round((stats?.total_alerts ?? 0) * 0.26)) },
    { time: '12:00', scans: Math.max(24, Math.round((stats?.total_alerts ?? 0) * 0.33)) },
    { time: '16:00', scans: Math.max(16, Math.round((stats?.total_alerts ?? 0) * 0.29)) },
    { time: '20:00', scans: Math.max(20, Math.round((stats?.total_alerts ?? 0) * 0.4)) },
  ]
  const sideMetrics = [
    { label: 'Neural Engine', value: Math.min(99, 65 + Math.round((stats?.model_metrics?.accuracy || 0) * 30)), accent: '#00E5FF' },
    { label: 'Database Load', value: stats?.mongo_connected ? 74 : 33, accent: '#00FF9F' },
    { label: 'Scan Rate', value: Math.min(98, Math.max(18, Math.round((stats?.total_alerts ?? 0) * 1.5))), accent: '#FFC857' },
    { label: 'Active Nodes', value: Math.min(95, Math.max(12, correlationOverview.correlated_alerts || 12)), accent: '#FF3B3B' },
  ]
  const consoleLines = [
    'Command center synchronized with FastAPI telemetry.',
    `Monitoring ${stats?.total_alerts ?? 0} total persisted alerts.`,
    `Risk distribution HIGH:${highRisk} MEDIUM:${mediumRisk} LOW:${lowRisk}.`,
    `Average campaign score ${correlationOverview.average_campaign_score || 0}; average impact ${correlationOverview.average_impact_score || 0}.`,
    `Secondary model status: ${stats?.secondary_status || 'unknown'}.`,
  ]
  const mapNodes = [
    { top: '18%', left: '22%', color: '#00FF9F', scale: 1.1 },
    { top: '30%', left: '61%', color: '#FF3B3B', scale: 1.35 },
    { top: '44%', left: '35%', color: '#00E5FF', scale: 1 },
    { top: '58%', left: '72%', color: '#FFC857', scale: 1.2 },
    { top: '66%', left: '18%', color: '#FF3B3B', scale: 1.1 },
    { top: '24%', left: '82%', color: '#00FF9F', scale: 0.9 },
  ]

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid gap-4 md:grid-cols-2 xl:grid-cols-4"
      >
        <StatCard label="Total Threats" value={stats?.total_alerts ?? '--'} accent="#00E5FF" icon="01" />
        <StatCard label="High Risk" value={highRisk} accent="#FF3B3B" icon="HR" pulse />
        <StatCard label="Medium Risk" value={mediumRisk} accent="#FFC857" icon="MR" />
        <StatCard label="Low Risk" value={lowRisk} accent="#00FF9F" icon="LR" />
      </Motion.section>

      {loading ? (
        <div className="glass-card rounded-[32px] p-8">
          <Loader label="Loading dashboard telemetry..." />
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
                  <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Command Center</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">Global Threat Map</h2>
                </div>
                <div className="terminal-text rounded-full border border-white/8 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-slate-400">
                  live topology
                </div>
              </div>

              <div className="relative mt-6 h-[26rem] overflow-hidden rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(2,6,23,0.95),rgba(15,23,42,0.75))]">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,229,255,0.08),transparent_35%)]" />
                <div className="absolute inset-0 opacity-45 [background-image:linear-gradient(rgba(0,229,255,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(0,229,255,0.08)_1px,transparent_1px)] [background-size:36px_36px]" />
                {mapNodes.map((node, index) => (
                  <Motion.div
                    key={`${node.top}-${node.left}-${index}`}
                    className="absolute rounded-full"
                    style={{
                      top: node.top,
                      left: node.left,
                      width: `${18 * node.scale}px`,
                      height: `${18 * node.scale}px`,
                      backgroundColor: node.color,
                      boxShadow: `0 0 18px ${node.color}`,
                    }}
                    animate={{ y: [0, -10, 0], opacity: [0.55, 1, 0.55] }}
                    transition={{ duration: 2.8 + index * 0.2, repeat: Infinity, ease: 'easeInOut' }}
                  />
                ))}
                <svg className="absolute inset-0 h-full w-full opacity-35" viewBox="0 0 100 100" preserveAspectRatio="none">
                  <path d="M20,22 L35,44 L61,30 L72,58" stroke="#00E5FF" strokeWidth="0.35" fill="none" />
                  <path d="M18,66 L35,44 L58,72 L82,24" stroke="#00FF9F" strokeWidth="0.35" fill="none" />
                </svg>
              </div>
            </Motion.section>

            <Motion.section
              initial={{ opacity: 0, x: 18 }}
              animate={{ opacity: 1, x: 0 }}
              className="grid gap-4"
            >
              {sideMetrics.map((metric) => (
                <div key={metric.label} className="glass-card neon-panel rounded-[28px] p-5">
                  <div className="flex items-center justify-between">
                    <p className="text-xs uppercase tracking-[0.34em] text-slate-400">{metric.label}</p>
                    <p className="terminal-text text-sm" style={{ color: metric.accent }}>
                      {metric.value}%
                    </p>
                  </div>
                  <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/6">
                    <Motion.div
                      className="h-full rounded-full"
                      style={{ background: `linear-gradient(90deg, ${metric.accent}, transparent)` }}
                      initial={{ width: '0%' }}
                      animate={{ width: `${metric.value}%` }}
                      transition={{ duration: 1 }}
                    />
                  </div>
                </div>
              ))}
            </Motion.section>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr_0.8fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Activity</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Threat activity timeline</h3>
              <div className="mt-6 h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={activityData}>
                    <defs>
                      <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="#94A3B8" />
                    <YAxis stroke="#94A3B8" />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 16 }} />
                    <Area type="monotone" dataKey="scans" stroke="#00E5FF" fill="url(#activityFill)" strokeWidth={3} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Risk Matrix</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Risk levels</h3>
              <div className="mt-6 h-80">
                {riskData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={riskData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,200,87,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[12, 12, 0, 0]}>
                        {riskData.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.name === 'HIGH' ? '#FF3B3B' : entry.name === 'MEDIUM' ? '#FFC857' : '#00FF9F'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No risk data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Threat Types</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Distribution</h3>
              <div className="mt-6 h-80">
                {threatData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={threatData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={92} paddingAngle={4}>
                        {threatData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(0,255,159,0.2)', borderRadius: 16 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No threat data available yet.</div>
                )}
              </div>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-[0.9fr_0.9fr_1.2fr]">
            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FF3B3B]">Priority Tiers</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Alert priority</h3>
              <div className="mt-6 h-72">
                {priorityData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={priorityData}>
                      <XAxis dataKey="name" stroke="#94A3B8" />
                      <YAxis stroke="#94A3B8" allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 16 }} />
                      <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                        {priorityData.map((entry) => (
                          <Cell
                            key={entry.name}
                            fill={entry.name === 'CRITICAL' ? '#FF3B3B' : entry.name === 'HIGH' ? '#FF7A7A' : entry.name === 'MEDIUM' ? '#FFC857' : '#00FF9F'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No priority data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#FFC857]">Language Coverage</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Normalized sources</h3>
              <div className="mt-6 h-72">
                {languageData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={languageData} dataKey="value" nameKey="name" innerRadius={42} outerRadius={82} paddingAngle={4}>
                        {languageData.map((entry, index) => (
                          <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,200,87,0.2)', borderRadius: 16 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">No multilingual data available yet.</div>
                )}
              </div>
            </div>

            <div className="glass-card neon-panel rounded-[32px] p-6">
              <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Correlation & Impact</p>
              <h3 className="mt-2 text-2xl font-semibold text-white">Intelligence quality</h3>
              <div className="mt-6 grid gap-4 md:grid-cols-3">
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Correlated Alerts</p>
                  <p className="mt-3 text-3xl font-semibold text-white">{correlationOverview.correlated_alerts ?? 0}</p>
                </div>
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Avg Campaign Score</p>
                  <p className="mt-3 text-3xl font-semibold text-[#00E5FF]">{correlationOverview.average_campaign_score ?? 0}</p>
                </div>
                <div className="rounded-[22px] border border-white/8 bg-black/10 p-4">
                  <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Avg Impact Score</p>
                  <p className="mt-3 text-3xl font-semibold text-[#FFC857]">{correlationOverview.average_impact_score ?? 0}</p>
                </div>
              </div>
            </div>
          </div>

          <TerminalConsole
            key={consoleLines.join('|')}
            title="System Console"
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
