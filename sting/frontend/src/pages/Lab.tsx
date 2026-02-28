import { useState, useEffect } from 'react'
import { format } from 'date-fns'
import { Play, Square, Terminal, Network, FileCode, Cpu, AlertCircle, CheckCircle, Clock } from 'lucide-react'

interface LabJob {
  id: string
  session_id: string
  status: string
  created_at: string
  completed_at: string | null
  streams: {
    syscalls: number
    network: number
    filesystem: number
    processes: number
  }
}

export default function Lab() {
  const [jobs, setJobs] = useState<LabJob[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [activeStream, setActiveStream] = useState<'syscalls' | 'network' | 'filesystem' | 'processes'>('syscalls')

  useEffect(() => {
    fetchJobs()
    const interval = setInterval(fetchJobs, 3000)
    return () => clearInterval(interval)
  }, [])

  const fetchJobs = async () => {
    try {
      const res = await fetch('/api/v1/lab')
      if (res.ok) {
        const data = await res.json()
        setJobs(data.jobs || [])
      }
    } catch (e) {
      console.error('Failed to fetch jobs:', e)
    } finally {
      setLoading(false)
    }
  }

  const launchJob = async (sessionId: string) => {
    try {
      await fetch('/api/v1/lab/detonate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      })
      fetchJobs()
    } catch (e) {
      console.error('Failed to launch job:', e)
    }
  }

  const stopJob = async (jobId: string) => {
    try {
      await fetch(`/api/v1/lab/${jobId}/stop`, { method: 'POST' })
      fetchJobs()
    } catch (e) {
      console.error('Failed to stop job:', e)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <Clock className="w-4 h-4 text-yellow-400 animate-pulse" />
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-400" />
      default:
        return <Clock className="w-4 h-4 text-gray-400" />
    }
  }

  const streamIcons = {
    syscalls: Terminal,
    network: Network,
    filesystem: FileCode,
    processes: Cpu,
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Malware Lab</h1>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <div className="w-2 h-2 rounded-full bg-sting-accent animate-pulse" />
          Isolated Network Active
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-sting-panel border border-sting-border rounded-lg p-4">
            <h2 className="font-semibold mb-4">Analysis Jobs</h2>
            {loading ? (
              <p className="text-gray-400 text-sm">Loading...</p>
            ) : jobs.length === 0 ? (
              <p className="text-gray-400 text-sm">No analysis jobs yet</p>
            ) : (
              <div className="space-y-2">
                {jobs.map((job) => (
                  <div
                    key={job.id}
                    onClick={() => setSelectedJob(job.id)}
                    className={`p-3 rounded-lg cursor-pointer transition-colors ${
                      selectedJob === job.id
                        ? 'bg-sting-accent/20 border border-sting-accent'
                        : 'bg-sting-dark hover:bg-sting-border'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-mono">{job.session_id.slice(0, 8)}...</span>
                      {getStatusIcon(job.status)}
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                      {format(new Date(job.created_at), 'MMM d, HH:mm')}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-sting-panel border border-sting-border rounded-lg p-4">
            <h2 className="font-semibold mb-4">Lab Configuration</h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Network Isolation</span>
                <span className="text-sting-accent">Docker Net</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Monitoring</span>
                <span>strace, tshark, inotify</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">TTL</span>
                <span>30 minutes</span>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          <div className="bg-st-sting-border roundeding-panel border border-lg h-full">
            {selectedJob ? (
              <>
                <div className="border-b border-sting-border p-4">
                  <div className="flex items-center justify-between">
                    <h2 className="font-semibold">Live Stream</h2>
                    <div className="flex gap-2">
                      {Object.entries(streamIcons).map(([key, Icon]) => (
                        <button
                          key={key}
                          onClick={() => setActiveStream(key as typeof activeStream)}
                          className={`p-2 rounded-lg transition-colors ${
                            activeStream === key
                              ? 'bg-sting-accent/20 text-sting-accent'
                              : 'hover:bg-sting-border text-gray-400'
                          }`}
                          title={key}
                        >
                          <Icon className="w-4 h-4" />
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="p-4 h-[400px] overflow-auto">
                  <pre className="font-mono text-xs text-gray-300">
                    {`[${format(new Date(), 'HH:mm:ss')}] Initializing isolated environment...
[${format(new Date(), 'HH:mm:ss')}] Mounting container filesystem...
[${format(new Date(), 'HH:mm:ss')}] Starting strace on PID 1...
[${format(new Date(), 'HH:mm:ss')}] Network monitoring enabled (tshark)...
[${format(new Date(), 'HH:mm:ss')}] Filesystem watch active (inotify)...
[${format(new Date(), 'HH:mm:ss')}] Process monitor active (pspy64)...

> Sample execution started
> Reading /etc/passwd
> Attempting network connection to 192.168.1.1
> Writing to /tmp/malware.sh
> Executing shell script
`}
                  </pre>
                </div>
                <div className="border-t border-sting-border p-4">
                  <button
                    onClick={() => selectedJob && stopJob(selectedJob)}
                    className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium"
                  >
                    <Square className="w-4 h-4" />
                    Stop Analysis
                  </button>
                </div>
              </>
            ) : (
              <div className="h-full flex items-center justify-center text-gray-400">
                <div className="text-center">
                  <Terminal className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>Select a job to view live stream</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
