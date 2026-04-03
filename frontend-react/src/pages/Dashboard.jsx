import { useEffect, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import {
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
import { getStats } from '../services/api'

const pieColors = ['#00CFFF', '#FF3B3B', '#00FF9F', '#8B5CF6', '#FACC15']

function StatCard({ label, value, accent }) {
  return (
    <div className="glass-card rounded-3xl p-5">
      <p className="text-xs uppercase tracking-[0.32em] text-slate-400">{label}</p>
      <p className="mt-4 text-3xl font-semibold text-white" style={{ color: accent || '#FFFFFF' }}>
        {value}
      </p>
    </div>
  )
}

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const loadStats = async () => {
      setLoading(true)
      setError('')

      try {
        const response = await getStats()
        setStats(response)
      } catch (apiError) {
        setError(
          apiError?.response?.data?.detail ||
            'Unable to reach backend statistics endpoint. Ensure FastAPI is running.',
        )
      } finally {
        setLoading(false)
      }
    }

    loadStats()
  }, [])

  const threatData = Object.entries(stats?.threat_distribution || {}).map(([name, value]) => ({ name, value }))
  const riskData = Object.entries(stats?.risk_levels || {}).map(([name, value]) => ({ name, value }))

  return (
    <div className="space-y-6">
      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid gap-4 md:grid-cols-3"
      >
        <StatCard label="Total Alerts" value={stats?.total_alerts ?? '--'} accent="#00CFFF" />
        <StatCard label="MongoDB" value={stats?.mongo_connected ? 'Connected' : 'Fallback'} accent="#00FF9F" />
        <StatCard label="Secondary Model" value={stats?.secondary_status || 'Loading'} accent="#FACC15" />
      </Motion.section>

      {loading ? (
        <div className="glass-card rounded-3xl p-8">
          <Loader label="Loading dashboard telemetry..." />
        </div>
      ) : error ? (
        <div className="glass-card rounded-3xl border border-[#FF3B3B]/35 p-6 text-[#FFB4B4]">{error}</div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-2">
          <Motion.section
            initial={{ opacity: 0, x: -18 }}
            animate={{ opacity: 1, x: 0 }}
            className="glass-card rounded-3xl p-6"
          >
            <p className="text-xs uppercase tracking-[0.35em] text-[#00CFFF]">Threat Distribution</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Class breakdown</h2>
            <div className="mt-6 h-80">
              {threatData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={72}
                      outerRadius={110}
                      paddingAngle={4}
                    >
                      {threatData.map((entry, index) => (
                        <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid rgba(0, 207, 255, 0.25)',
                        borderRadius: 16,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-slate-400">No threat data available yet.</div>
              )}
            </div>
          </Motion.section>

          <Motion.section
            initial={{ opacity: 0, x: 18 }}
            animate={{ opacity: 1, x: 0 }}
            className="glass-card rounded-3xl p-6"
          >
            <p className="text-xs uppercase tracking-[0.35em] text-[#00FF9F]">Risk Levels</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Operational severity</h2>
            <div className="mt-6 h-80">
              {riskData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={riskData}>
                    <XAxis dataKey="name" stroke="#CBD5E1" />
                    <YAxis stroke="#CBD5E1" allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        border: '1px solid rgba(0, 255, 159, 0.25)',
                        borderRadius: 16,
                      }}
                    />
                    <Bar dataKey="value" radius={[12, 12, 0, 0]}>
                      {riskData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={
                            entry.name === 'HIGH' ? '#FF3B3B' : entry.name === 'MEDIUM' ? '#FACC15' : '#00FF9F'
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-slate-400">No risk data available yet.</div>
              )}
            </div>
          </Motion.section>
        </div>
      )}
    </div>
  )
}

export default Dashboard
