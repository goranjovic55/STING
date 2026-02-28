import { useState, useEffect } from 'react'
import { Shield, Activity, AlertTriangle, CheckCircle, Clock, Server, Zap } from 'lucide-react'

interface Stats {
  totalSessions: number
  hostileSessions: number
  pendingSessions: number
  clearedSessions: number
  canariesTriggered: number
  samplesAnalyzed: number
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalSessions: 0,
    hostileSessions: 0,
    pendingSessions: 0,
    clearedSessions: 0,
    canariesTriggered: 0,
    samplesAnalyzed: 0,
  })
  const [proxyStatus, setProxyStatus] = useState({ ssh: { running: false, port: 2222 } })

  useEffect(() => {
    fetchStats()
    fetchProxyStatus()
    const interval = setInterval(fetchStats, 5000)
    return () => clearInterval(interval)
  }, [])

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/sessions')
      if (res.ok) {
        const data = await res.json()
        setStats({
          totalSessions: data.total || 0,
          hostileSessions: data.hostile || 0,
          pendingSessions: data.pending || 0,
          clearedSessions: data.cleared || 0,
          canariesTriggered: data.canaries_triggered || 0,
          samplesAnalyzed: data.samples_analyzed || 0,
        })
      }
    } catch (e) {
      console.error('Failed to fetch stats:', e)
    }
  }

  const fetchProxyStatus = async () => {
    try {
      const res = await fetch('/api/v1/proxy/status')
      if (res.ok) {
        const data = await res.json()
        setProxyStatus(data)
      }
    } catch (e) {
      console.error('Failed to fetch proxy status:', e)
    }
  }

  const startSSHProxy = async () => {
    try {
      await fetch('/api/v1/proxy/ssh/start', { method: 'POST' })
      fetchProxyStatus()
    } catch (e) {
      console.error('Failed to start SSH proxy:', e)
    }
  }

  const stopSSHProxy = async () => {
    try {
      await fetch('/api/v1/proxy/ssh/stop', { method: 'POST' })
      fetchProxyStatus()
    } catch (e) {
      console.error('Failed to stop SSH proxy:', e)
    }
  }

  const statCards = [
    { label: 'Total Sessions', value: stats.totalSessions, icon: Activity, color: 'text-blue-400' },
    { label: 'Hostile', value: stats.hostileSessions, icon: AlertTriangle, color: 'text-red-400' },
    { label: 'Pending', value: stats.pendingSessions, icon: Clock, color: 'text-yellow-400' },
    { label: 'Cleared', value: stats.clearedSessions, icon: CheckCircle, color: 'text-green-400' },
    { label: 'Canaries Hit', value: stats.canariesTriggered, icon: Zap, color: 'text-purple-400' },
    { label: 'Samples', value: stats.samplesAnalyzed, icon: Server, color: 'text-cyan-400' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-sting-accent" />
          <span className="text-sm text-gray-400">Deception Active</span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map((stat) => (
          <div key={stat.label} className="bg-sting-panel border border-sting-border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">{stat.label}</span>
              <stat.icon className={`w-5 h-5 ${stat.color}`} />
            </div>
            <p className="text-2xl font-bold mt-2">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-sting-panel border border-sting-border rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Proxy Control</h2>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${proxyStatus.ssh.running ? 'bg-sting-accent' : 'bg-gray-500'}`} />
            <span>SSH Proxy (Port 2222)</span>
          </div>
          {proxyStatus.ssh.running ? (
            <button
              onClick={stopSSHProxy}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium transition-colors"
            >
              Stop
            </button>
          ) : (
            <button
              onClick={startSSHProxy}
              className="px-4 py-2 bg-sting-accent hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors"
            >
              Start
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-sting-panel border border-sting-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Session States</h2>
          <div className="space-y-3">
            {['Hostile', 'Pending', 'Cleared'].map((state) => {
              const count = state === 'Hostile' ? stats.hostileSessions
                : state === 'Pending' ? stats.pendingSessions
                : stats.clearedSessions
              const total = stats.totalSessions || 1
              const pct = Math.round((count / total) * 100)
              return (
                <div key={state}>
                  <div className="flex justify-between text-sm mb-1">
                    <span>{state}</span>
                    <span className="text-gray-400">{count} ({pct}%)</span>
                  </div>
                  <div className="h-2 bg-sting-border rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        state === 'Hostile' ? 'bg-red-500' : state === 'Pending' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="bg-sting-panel border border-sting-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
          <div className="grid grid-cols-2 gap-3">
            <button className="p-3 bg-sting-border hover:bg-gray-700 rounded-lg text-left transition-colors">
              <div className="font-medium">View Sessions</div>
              <div className="text-xs text-gray-400">See all active sessions</div>
            </button>
            <button className="p-3 bg-sting-border hover:bg-gray-700 rounded-lg text-left transition-colors">
              <div className="font-medium">Manage Canaries</div>
              <div className="text-xs text-gray-400">Configure decoys</div>
            </button>
            <button className="p-3 bg-sting-border hover:bg-gray-700 rounded-lg text-left transition-colors">
              <div className="font-medium">Analyze Samples</div>
              <div className="text-xs text-gray-400">Review malware</div>
            </button>
            <button className="p-3 bg-sting-border hover:bg-gray-700 rounded-lg text-left transition-colors">
              <div className="font-medium">Launch Lab</div>
              <div className="text-xs text-gray-400">Isolated analysis</div>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
