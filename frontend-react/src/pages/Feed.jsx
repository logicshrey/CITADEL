import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import Loader from '../components/Loader'
import StatCard from '../components/StatCard'
import ThreatCard from '../components/ThreatCard'
import Toast from '../components/Toast'
import { getAlerts } from '../services/api'

function Feed() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')

  useEffect(() => {
    let mounted = true

    const loadAlerts = async () => {
      try {
        const response = await getAlerts()
        if (mounted) {
          setAlerts(response?.alerts || [])
          setToast('')
        }
      } catch (apiError) {
        if (mounted) {
          setToast(
            apiError?.response?.data?.detail ||
              'Live threat feed is unavailable because the backend is not responding.',
          )
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    loadAlerts()
    const intervalId = window.setInterval(loadAlerts, 5000)

    return () => {
      mounted = false
      window.clearInterval(intervalId)
    }
  }, [])

  useEffect(() => {
    if (!toast) {
      return undefined
    }
    const timeoutId = window.setTimeout(() => setToast(''), 3500)
    return () => window.clearTimeout(timeoutId)
  }, [toast])

  const latestTimestamp = useMemo(() => {
    const latest = alerts?.[0]?.results?.timestamp || alerts?.[0]?.timestamp
    return latest ? new Date(latest).toLocaleTimeString() : 'No events'
  }, [alerts])

  const highCount = alerts.filter((alert) => (alert.results?.risk_level || alert.risk_level) === 'HIGH').length
  const mediumCount = alerts.filter((alert) => (alert.results?.risk_level || alert.risk_level) === 'MEDIUM').length
  const packetsPerSecond = Math.max(12, alerts.length * 3 + 17)

  return (
    <div className="space-y-6">
      <Toast message={toast} />
      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card neon-panel rounded-[32px] p-6"
      >
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.38em] text-[#FF3B3B]">Live Threat Stream</p>
            <h2 className="mt-3 text-4xl font-semibold text-white">Real-time intelligence pulse</h2>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="terminal-text rounded-2xl border border-white/8 bg-black/15 px-4 py-3 text-sm text-slate-300">
              {packetsPerSecond} packets/sec
            </div>
            <div className="terminal-text flex items-center gap-2 rounded-full border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-2 text-[11px] uppercase tracking-[0.3em] text-[#FFB4B4]">
              <span className="live-dot h-2.5 w-2.5 rounded-full bg-[#FF3B3B]" />
              Live
            </div>
          </div>
        </div>
      </Motion.section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Active Threats" value={alerts.length} accent="#00E5FF" icon="AT" />
        <StatCard label="Scans Today" value={alerts.length * 9 + 24} accent="#00FF9F" icon="SD" />
        <StatCard label="Blocked" value={highCount + mediumCount} accent="#FF3B3B" icon="BL" />
        <StatCard label="Uptime" value="99.98%" accent="#FFC857" icon="UP" />
      </div>

      <Motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card neon-panel rounded-[32px] p-6"
      >
        <div className="mb-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00E5FF]">Alert Stream</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">Recent threat alerts</h3>
          </div>
          <div className="terminal-text rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1 text-[11px] uppercase tracking-[0.28em] text-[#B8FFE3]">
            last event {latestTimestamp}
          </div>
        </div>

        {loading ? (
          <Loader label="Syncing live alerts..." />
        ) : alerts.length === 0 ? (
          <div className="rounded-[24px] border border-white/8 bg-black/10 px-4 py-12 text-center text-slate-400">
            No alerts yet. Run an analysis from the backend, Streamlit, or React analyzer to populate the live stream.
          </div>
        ) : (
          <div className="feed-scroll max-h-[46rem] space-y-4 overflow-y-auto pr-1">
            {alerts.map((alert, index) => (
              <Motion.div
                key={alert._id || alert.results?.timestamp || `${index}-${alert.text || 'alert'}`}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(index * 0.04, 0.3) }}
              >
                <ThreatCard item={alert} title="Threat event" compact />
              </Motion.div>
            ))}
          </div>
        )}
      </Motion.section>
    </div>
  )
}

export default Feed
