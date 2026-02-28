import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, Activity, Wifi, Bug, FlaskConical, LayoutDashboard } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Sessions from './pages/Sessions'
import Canaries from './pages/Canaries'
import Samples from './pages/Samples'
import Lab from './pages/Lab'
import LiveFeed from './components/LiveFeed'

function Sidebar() {
  const location = useLocation()

  const navItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/sessions', icon: Activity, label: 'Sessions' },
    { path: '/canaries', icon: Wifi, label: 'Canaries' },
    { path: '/samples', icon: Bug, label: 'Samples' },
    { path: '/lab', icon: FlaskConical, label: 'Lab' },
  ]

  return (
    <aside className="w-64 bg-sting-panel border-r border-sting-border min-h-screen flex flex-col">
      <div className="p-4 border-b border-sting-border">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-sting-accent" />
          <div>
            <h1 className="text-xl font-bold text-white">STING 2.0</h1>
            <p className="text-xs text-gray-500">Deception Platform</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-sting-accent/20 text-sting-accent'
                      : 'text-gray-400 hover:bg-sting-border hover:text-white'
                  }`}
                >
                  <item.icon className="w-5 h-5" />
                  {item.label}
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>

      <div className="p-4 border-t border-sting-border">
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <div className="w-2 h-2 rounded-full bg-sting-accent animate-pulse" />
          System Online
        </div>
      </div>
    </aside>
  )
}

function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-sting-dark">
        <Sidebar />
        <main className="flex-1 flex flex-col">
          <div className="flex-1 p-6 overflow-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/sessions" element={<Sessions />} />
              <Route path="/canaries" element={<Canaries />} />
              <Route path="/samples" element={<Samples />} />
              <Route path="/lab" element={<Lab />} />
            </Routes>
          </div>
          <LiveFeed />
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
