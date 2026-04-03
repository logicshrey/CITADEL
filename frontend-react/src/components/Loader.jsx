import { motion as Motion } from 'framer-motion'

function Loader({ label = 'Processing threat intelligence...' }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-8 text-sm text-slate-300">
      <div className="relative flex h-14 w-14 items-center justify-center">
        <Motion.div
          className="absolute h-14 w-14 rounded-full border border-[#00CFFF]/35"
          animate={{ scale: [1, 1.25, 1], opacity: [0.3, 0.8, 0.3] }}
          transition={{ repeat: Infinity, duration: 1.8, ease: 'easeInOut' }}
        />
        <Motion.div
          className="h-9 w-9 rounded-full border-2 border-transparent border-t-[#00CFFF] border-r-[#00FF9F]"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
        />
      </div>
      <Motion.p
        animate={{ opacity: [0.45, 1, 0.45] }}
        transition={{ repeat: Infinity, duration: 1.6, ease: 'easeInOut' }}
      >
        {label}
      </Motion.p>
    </div>
  )
}

export default Loader
