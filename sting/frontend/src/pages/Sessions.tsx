import { useState, useEffect } from 'react'
import { format } from 'date-fns'
import { Search, Filter, CheckCircle, Trash2, Eye } from 'lucide-react'

interface Session {
  id: string
  ip: string
  protocol: string
  state: string
  score: number
  created_at: string
  reads: number
  writes: number
  captures: number
}

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 3000)
    return () => clearInterval(interval)
  }, [])

  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/v1/sessions')
      if (res.ok) {
        const data = await res.json()
        setSessions(data.sessions || [])
      }
    } catch (e) {
      console.error('Failed to fetch sessions:', e)
    } finally {
      setLoading(false)
    }
  }

  const handleNuke = async (sessionId: string) => {
    try {
      await fetch(`/api/v1/sessions/${sessionId}/nuke`, { method: 'POST' })
      fetchSessions()
    } catch (e) {
      console.error('Failed to nuke session:', e)
    }
  }

  const handleCommit = async (sessionId: string) => {
    try {
      await fetch(`/api/v1/sessions/${sessionId}/commit`, { method: 'POST' })
      fetchSessions()
    } catch (e) {
      console.error('Failed to commit session:', e)
    }
  }

  const handleLab = async (sessionId: string) => {
    try {
      await fetch(`/api/v1/lab/detonate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      })
    } catch (e) {
      console.error('Failed to send to lab:', e)
    }
  }

  const filteredSessions = sessions.filter((s) => {
    const matchesSearch = s.ip.includes(search) || s.id.includes(search)
    const matchesFilter = filter === 'all' || s.state.toLowerCase() === filter
    return matchesSearch && matchesFilter
  })

  const getStateColor = (state: string) => {
    switch (state.toLowerCase()) {
      case 'hostile':
        return 'text-red-400 bg-red-400/10'
      case 'pending':
        return 'text-yellow-400 bg-yellow-400/10'
      case 'cleared':
        return 'text-green-400 bg-green-400/10'
      default:
        return 'text-gray-400 bg-gray-400/10'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 50) return 'text-red-400'
    if (score >= 30) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Sessions</h1>
        <span className="text-gray-400">{filteredSessions.length} sessions</span>
      </div>

      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by IP or session ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-sting-panel border border-sting-border rounded-lg text-sm"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-2 bg-sting-panel border border-sting-border rounded-lg text-sm"
          >
            <option value="all">All States</option>
            <option value="hostile">Hostile</option>
            <option value="pending">Pending</option>
            <option value="cleared">Cleared</option>
          </select>
        </div>
      </div>

      <div className="bg-sting-panel border border-sting-border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="border-b border-sting-border">
            <tr className="text-left text-sm text-gray-400">
              <th className="p-4">IP Address</th>
              <th className="p-4">Protocol</th>
              <th className="p-4">State</th>
              <th className="p-4">Score</th>
              <th className="p-4">Reads/Writes</th>
              <th className="p-4">Captures</th>
              <th className="p-4">Time</th>
              <th className="p-4">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-gray-400">
                  Loading...
                </td>
              </tr>
            ) : filteredSessions.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-gray-400">
                  No sessions found
                </td>
              </tr>
            ) : (
              filteredSessions.map((session) => (
                <tr key={session.id} className="border-b border-sting-border hover:bg-sting-border/30">
                  <td className="p-4 font-mono text-sm">{session.ip}</td>
                  <td className="p-4 uppercase text-xs">{session.protocol}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs ${getStateColor(session.state)}`}>
                      {session.state}
                    </span>
                  </td>
                  <td className={`p-4 font-bold ${getScoreColor(session.score)}`}>{session.score}</td>
                  <td className="p-4 text-sm text-gray-400">
                    {session.reads}/{session.writes}
                  </td>
                  <td className="p-4">
                    {session.captures > 0 ? (
                      <span className="text-purple-400">{session.captures} hit(s)</span>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="p-4 text-sm text-gray-400">
                    {format(new Date(session.created_at), 'HH:mm:ss')}
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleLab(session.id)}
                        className="p-1.5 hover:bg-sting-border rounded"
                        title="Send to Lab"
                      >
                        <Eye className="w-4 h-4 text-cyan-400" />
                      </button>
                      <button
                        onClick={() => handleCommit(session.id)}
                        className="p-1.5 hover:bg-sting-border rounded"
                        title="Commit"
                      >
                        <CheckCircle className="w-4 h-4 text-green-400" />
                      </button>
                      <button
                        onClick={() => handleNuke(session.id)}
                        className="p-1.5 hover:bg-sting-border rounded"
                        title="Nuke"
                      >
                        <Trash2 className="w-4 h-4 text-red-400" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
