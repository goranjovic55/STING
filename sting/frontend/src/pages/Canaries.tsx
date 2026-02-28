import { useState, useEffect } from 'react'
import { Plus, Trash2, Copy, Check, Wifi, FileText, Key, Globe } from 'lucide-react'

interface Canary {
  id: string
  type: string
  value: string
  created_at: string
  hits: number
  active: boolean
}

export default function Canaries() {
  const [canaries, setCanaries] = useState<Canary[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [newCanary, setNewCanary] = useState({ type: 'file', value: '' })
  const [copied, setCopied] = useState('')

  useEffect(() => {
    fetchCanaries()
  }, [])

  const fetchCanaries = async () => {
    try {
      const res = await fetch('/api/v1/canary')
      if (res.ok) {
        const data = await res.json()
        setCanaries(data.canaries || [])
      }
    } catch (e) {
      console.error('Failed to fetch canaries:', e)
    } finally {
      setLoading(false)
    }
  }

  const addCanary = async () => {
    if (!newCanary.value) return
    try {
      await fetch('/api/v1/canary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newCanary),
      })
      setNewCanary({ type: 'file', value: '' })
      setShowAdd(false)
      fetchCanaries()
    } catch (e) {
      console.error('Failed to add canary:', e)
    }
  }

  const toggleCanary = async (id: string, active: boolean) => {
    try {
      await fetch(`/api/v1/canary/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !active }),
      })
      fetchCanaries()
    } catch (e) {
      console.error('Failed to toggle canary:', e)
    }
  }

  const deleteCanary = async (id: string) => {
    try {
      await fetch(`/api/v1/canary/${id}`, { method: 'DELETE' })
      fetchCanaries()
    } catch (e) {
      console.error('Failed to delete canary:', e)
    }
  }

  const copyToClipboard = (value: string) => {
    navigator.clipboard.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(''), 2000)
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'file':
        return FileText
      case 'credential':
        return Key
      case 'url':
        return Globe
      case 'dns':
        return Wifi
      default:
        return FileText
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Canaries</h1>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-2 px-4 py-2 bg-sting-accent hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Canary
        </button>
      </div>

      {showAdd && (
        <div className="bg-sting-panel border border-sting-border rounded-lg p-4">
          <h3 className="font-medium mb-4">Add New Canary</h3>
          <div className="flex gap-4">
            <select
              value={newCanary.type}
              onChange={(e) => setNewCanary({ ...newCanary, type: e.target.value })}
              className="px-3 py-2 bg-sting-dark border border-sting-border rounded-lg text-sm"
            >
              <option value="file">File Path</option>
              <option value="credential">Credential</option>
              <option value="url">URL</option>
              <option value="dns">DNS</option>
            </select>
            <input
              type="text"
              placeholder="Value (e.g., /root/secrets.txt)"
              value={newCanary.value}
              onChange={(e) => setNewCanary({ ...newCanary, value: e.target.value })}
              className="flex-1 px-3 py-2 bg-sting-dark border border-sting-border rounded-lg text-sm"
            />
            <button
              onClick={addCanary}
              className="px-4 py-2 bg-sting-accent hover:bg-emerald-600 rounded-lg text-sm font-medium"
            >
              Add
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          <div className="col-span-full text-center text-gray-400 py-8">Loading...</div>
        ) : canaries.length === 0 ? (
          <div className="col-span-full text-center text-gray-400 py-8">
            No canaries configured. Add some decoys to detect intruders!
          </div>
        ) : (
          canaries.map((canary) => {
            const Icon = getTypeIcon(canary.type)
            return (
              <div
                key={canary.id}
                className={`bg-sting-panel border rounded-lg p-4 ${
                  canary.active ? 'border-sting-border' : 'border-sting-border opacity-50'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${canary.active ? 'bg-purple-500/20' : 'bg-gray-500/20'}`}>
                      <Icon className={`w-5 h-5 ${canary.active ? 'text-purple-400' : 'text-gray-400'}`} />
                    </div>
                    <div>
                      <p className="font-medium text-sm">{canary.type}</p>
                      <p className="text-xs text-gray-400 mt-1 font-mono truncate max-w-[200px]">{canary.value}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => copyToClipboard(canary.value)}
                      className="p-1 hover:bg-sting-border rounded"
                    >
                      {copied === canary.value ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4 text-gray-400" />
                      )}
                    </button>
                    <button
                      onClick={() => deleteCanary(canary.id)}
                      className="p-1 hover:bg-sting-border rounded"
                    >
                      <Trash2 className="w-4 h-4 text-red-400" />
                    </button>
                  </div>
                </div>
                <div className="mt-4 pt-3 border-t border-sting-border flex items-center justify-between">
                  <span className="text-xs text-gray-400">
                    {canary.hits} hit{canary.hits !== 1 ? 's' : ''}
                  </span>
                  <button
                    onClick={() => toggleCanary(canary.id, canary.active)}
                    className={`text-xs px-2 py-1 rounded ${
                      canary.active
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-gray-500/20 text-gray-400'
                    }`}
                  >
                    {canary.active ? 'Active' : 'Inactive'}
                  </button>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
