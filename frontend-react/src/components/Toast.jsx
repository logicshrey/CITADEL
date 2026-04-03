import { AnimatePresence, motion as Motion } from 'framer-motion'

function Toast({ message, tone = 'error' }) {
  const styles =
    tone === 'success'
      ? 'border-[#00FF9F]/35 bg-[#00FF9F]/12 text-[#B8FFE3]'
      : 'border-[#FF3B3B]/35 bg-[#FF3B3B]/12 text-[#FECACA]'

  return (
    <AnimatePresence>
      {message ? (
        <Motion.div
          initial={{ opacity: 0, y: -14 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -14 }}
          className={`fixed right-4 top-24 z-50 max-w-sm rounded-2xl border px-4 py-3 text-sm shadow-[0_18px_45px_rgba(2,6,23,0.45)] ${styles}`}
        >
          {message}
        </Motion.div>
      ) : null}
    </AnimatePresence>
  )
}

export default Toast
