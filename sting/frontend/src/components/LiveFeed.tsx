import { useState, useEffect, useRef } from 'react'
import { Zap, AlertTriangle, CheckCircle, Clock, X, ChevronUp, ChevronDown } from 'lucide-react'

interface Event {
  id: string
  type: string
  session_id: string
  ip: string
  message: string
  timestamp: string
  score_delta: number
}

export default function LiveFeed() {
  const [events, setEvents] = useState<Event[]>([])
  const [minimized] = useState(false)
  const [expanded, setExpanded] = useState(true)
  const wsRef = useRef<WebSocket | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    // Connect to WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/events`)

    ws.onopen = () => {
      console.log('[LiveFeed] Connected to WebSocket')
      ws.send(JSON.stringify({ type: 'subscribe', channel: 'events' }))
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'event') {
          setEvents((prev) => [data, ...prev].slice(0, 100))
        }
      } catch (e) {
        console.error('[LiveFeed] Parse error:', e)
      }
    }

    ws.onerror = (error) => {
      console.error('[LiveFeed] WebSocket error:', error)
    }

    ws.onclose = () => {
      console.log('[LiveFeed] WebSocket closed')
    }

    wsRef.current = ws

    return () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    if (scrollRef.current && expanded) {
      scrollRef.current.scrollTop = 0
    }
  }, [events, expanded])

  const clearEvents = () => {
    setEvents([])
  }

  const getEventIcon = (type: string) => {
    if (type.includes('CANARY') || type.includes('WGET') || type.includes('BAD')) {
      return <AlertTriangle className="w-3 h-3 text-red-400" />
    }
    if (type.includes('CLEAR') || type.includes('SUCCESS')) {
      return <CheckCircle className="w-3 h-3 text-green-400" />
    }
    if (type.includes('ATTEMPT') || type.includes('RECON')) {
      return <Clock className="w-3 h-3 text-yellow-400" />
    }
    return <Zap className="w-3 h-3 text-blue-400" />
  }

  const getScoreColor = (delta: number) => {
    if (delta > 0) return 'text-red-400'
    if (delta < 0) return 'text-green-400'
    return 'text-gray-400'
  }

  const formatTime = (timestamp: string) => {
    try {
      const date = new Date(timestamp)
      return date.toLocaleTimeString('en-US', { hour12: false })
    } catch {
      return '--:--:--'
    }
  }

  return (
    <div
      className={`bg-sting-panel border-t border-sting-border transition-all duration-300 ${
        minimized ? 'h-10' : expanded ? 'h-64' : 'h-10'
      }`}
    >
      <div
        className="flex items-center justify-between px-4 h-10 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-sting-accent" />
          <span className="text-sm font-medium">Live Events</span>
          <span className="text-xs text-gray-400">({events.length})</span>
        </div>
        <div className="flex items-center gap-2">
          {!minimized && (
            <button
              onClick={(e) => {
                e.stopPropagation()
                clearEvents()
              }}
              className="p-1 hover:bg-sting-border rounded"
              title="Clear"
            >
              <X className="w-3 h-3" />
            </button>
          )}
          <button className="p-1 hover:bg-sting-border rounded">
            {expanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronUp className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>

      {expanded && !minimized && (
        <div ref={scrollRef} className="h-[calc(100%-40px)] overflow-auto px-2 pb-2">
          {events.length === 0 ? (
            <div className="flex items-center justify-center h-full text-gray-500 text-sm">
              Waiting for events...
            </div>
          ) : (
            <div className="space-y-1">
              {events.map((event) => (
                <div
                  key={event.id}
                  className="flex items-center gap-2 px-2 py-1.5 bg-sting-dark rounded text-xs hover:bg-sting-border/50"
                >
                  <span className="text-gray-500 font-mono w-16">
                    {formatTime(event.timestamp)}
                  </span>
                  {getEventIcon(event.type)}
                  <span className="text-gray-300 flex-1 truncate">{event.message}</span>
                  <span className="text-gray-500 font-mono w-12">{event.ip}</span>
                  <span className={`font-mono w-12 text-right ${getScoreColor(event.score_delta)}`}>
                    {event.score_delta > 0 ? '+' : ''}{event.score_delta}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
