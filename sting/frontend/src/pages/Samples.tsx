import { useState, useEffect } from 'react'
import { format } from 'date-fns'
import { Upload, Search, Play, Pause, Trash2, FileCode } from 'lucide-react'

interface Sample {
  id: string
  filename: string
  hash: string
  size: number
  type: string
  created_at: string
  analysis_status: string
  verdict: string
  mitre_tactics: string[]
}

export default function Samples() {
  const [samples, setSamples] = useState<Sample[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetchSamples()
    const interval = setInterval(fetchSamples, 5000)
    return () => clearInterval(interval)
  }, [])

  const fetchSamples = async () => {
    try {
      const res = await fetch('/api/v1/samples')
      if (res.ok) {
        const data = await res.json()
        setSamples(data.samples || [])
      }
    } catch (e) {
      console.error('Failed to fetch samples:', e)
    } finally {
      setLoading(false)
    }
  }

  const analyzeSample = async (id: string) => {
    try {
      await fetch(`/api/v1/samples/${id}/analyze`, { method: 'POST' })
      fetchSamples()
    } catch (e) {
      console.error('Failed to analyze sample:', e)
    }
  }

  const deleteSample = async (id: string) => {
    try {
      await fetch(`/api/v1/samples/${id}`, { method: 'DELETE' })
      fetchSamples()
    } catch (e) {
      console.error('Failed to delete sample:', e)
    }
  }

  const filteredSamples = samples.filter(
    (s) => s.filename.includes(search) || s.hash.includes(search)
  )

  const getVerdictColor = (verdict: string) => {
    switch (verdict?.toLowerCase()) {
      case 'malicious':
        return 'text-red-400 bg-red-400/10'
      case 'suspicious':
        return 'text-yellow-400 bg-yellow-400/10'
      case 'benign':
        return 'text-green-400 bg-green-400/10'
      default:
        return 'text-gray-400 bg-gray-400/10'
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Samples</h1>
        <button className="flex items-center gap-2 px-4 py-2 bg-sting-accent hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors">
          <Upload className="w-4 h-4" />
          Upload Sample
        </button>
      </div>

      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by filename or hash..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-sting-panel border border-sting-border rounded-lg text-sm"
          />
        </div>
      </div>

      <div className="bg-sting-panel border border-sting-border rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="border-b border-sting-border">
            <tr className="text-left text-sm text-gray-400">
              <th className="p-4">File</th>
              <th className="p-4">Hash</th>
              <th className="p-4">Size</th>
              <th className="p-4">Type</th>
              <th className="p-4">Verdict</th>
              <th className="p-4">MITRE</th>
              <th className="p-4">Submitted</th>
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
            ) : filteredSamples.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-gray-400">
                  No samples uploaded yet
                </td>
              </tr>
            ) : (
              filteredSamples.map((sample) => (
                <tr key={sample.id} className="border-b border-sting-border hover:bg-sting-border/30">
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-cyan-400" />
                      <span className="font-medium text-sm">{sample.filename}</span>
                    </div>
                  </td>
                  <td className="p-4 font-mono text-xs text-gray-400">{sample.hash.slice(0, 16)}...</td>
                  <td className="p-4 text-sm">{formatSize(sample.size)}</td>
                  <td className="p-4 text-sm text-gray-400">{sample.type}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs ${getVerdictColor(sample.verdict)}`}>
                      {sample.verdict || 'pending'}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="flex flex-wrap gap-1">
                      {sample.mitre_tactics?.slice(0, 3).map((tactic) => (
                        <span
                          key={tactic}
                          className="px-1.5 py-0.5 bg-sting-border rounded text-xs"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-4 text-sm text-gray-400">
                    {format(new Date(sample.created_at), 'MMM d, HH:mm')}
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      {sample.analysis_status === 'pending' ? (
                        <button
                          onClick={() => analyzeSample(sample.id)}
                          className="p-1.5 hover:bg-sting-border rounded"
                          title="Analyze"
                        >
                          <Play className="w-4 h-4 text-sting-accent" />
                        </button>
                      ) : (
                        <button
                          className="p-1.5 hover:bg-sting-border rounded"
                          title="Analyzing..."
                        >
                          <Pause className="w-4 h-4 text-yellow-400" />
                        </button>
                      )}
                      <button
                        onClick={() => deleteSample(sample.id)}
                        className="p-1.5 hover:bg-sting-border rounded"
                        title="Delete"
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
