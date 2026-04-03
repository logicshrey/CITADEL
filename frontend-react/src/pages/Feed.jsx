import { useEffect, useMemo, useState } from 'react'
import { motion as Motion } from 'framer-motion'
import Loader from '../components/Loader'
import ThreatCard from '../components/ThreatCard'
import { getAlerts } from '../services/api'

function Feed() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let mounted = true

    const loadAlerts = async () => {
      try {
        const response = await getAlerts()
        if (mounted) {
          setAlerts(response?.alerts || [])
          setError('')
        }
      } catch (apiError) {
        if (mounted) {
          setError(
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

  const latestTimestamp = useMemo(() => {
    const latest = alerts?.[0]?.results?.timestamp || alerts?.[0]?.timestamp
    return latest ? new Date(latest).toLocaleTimeString() : 'No events'
  }, [alerts])

  return (
    <div className="grid gap-6 xl:grid-cols-[0.75fr_1.25fr]">
      <Motion.section
        initial={{ opacity: 0, x: -16 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card rounded-3xl p-6"
      >
        <p className="text-xs uppercase tracking-[0.35em] text-[#FF3B3B]">Live Feed</p>
        <h2 className="mt-2 text-3xl font-semibold text-white">Threat activity stream</h2>
        <p className="mt-4 text-sm text-slate-300">
          The feed refreshes every 5 seconds and shows the latest intelligence events persisted by the backend.
        </p>

        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
          <div className="rounded-2xl border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Refresh cadence</p>
            <p className="mt-3 text-2xl font-semibold text-[#00CFFF]">5 sec</p>
          </div>
          <div className="rounded-2xl border border-white/8 bg-black/10 p-4">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Last event</p>
            <p className="mt-3 text-2xl font-semibold text-[#00FF9F]">{latestTimestamp}</p>
          </div>
        </div>
      </Motion.section>

      <Motion.section
        initial={{ opacity: 0, x: 16 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-card rounded-3xl p-6"
      >
        <div className="mb-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-[#00CFFF]">Scrolling List</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">Recent alerts</h3>
          </div>
          <div className="rounded-full border border-[#00FF9F]/25 bg-[#00FF9F]/8 px-3 py-1 text-xs text-[#B8FFE3]">
            Auto-refresh active
          </div>
        </div>

        {loading ? (
          <Loader label="Syncing live alerts..." />
        ) : error ? (
          <div className="rounded-2xl border border-[#FF3B3B]/35 bg-[#FF3B3B]/10 px-4 py-3 text-sm text-[#FFB4B4]">
            {error}
          </div>
        ) : alerts.length === 0 ? (
          <div className="rounded-2xl border border-white/8 bg-black/10 px-4 py-10 text-center text-slate-400">
            No alerts yet. Run an analysis from the backend or Streamlit to populate the feed.
          </div>
        ) : (
          <div className="feed-scroll max-h-[36rem] space-y-4 overflow-y-auto pr-1">
            {alerts.map((alert, index) => (
              <Motion.div
                key={alert._id || alert.results?.timestamp || `${index}-${alert.text || 'alert'}`}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.04 }}
              >
                <ThreatCard item={alert} title="Threat Event" compact />
              </Motion.div>
            ))}
          </div>
        )}
      </Motion.section>
    </div>
  )
}

export default Feed
