/*
 * OurSchool - Homeschool Management System
 * Copyright (C) 2025 Dustan Ashley
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { config } from '../config/env'

const OIDCCallback = () => {
  const started = useRef(false)
  const [authorization] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    return { code: params.get('code'), state: params.get('state'), denied: params.has('error') }
  })
  const [error, setError] = useState(!authorization.code || !authorization.state || authorization.denied)
  const { login } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (started.current) return
    started.current = true
    const { code, state, denied } = authorization
    // Remove the provider's authorization code from browser history immediately.
    window.history.replaceState(null, '', window.location.pathname)
    if (!code || !state || denied) return
    fetch(`${config.api.baseUrl}/auth/oidc/callback`, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, state }),
    }).then(async response => {
      if (!response.ok) throw new Error('Single sign-on failed')
      const data = await response.json()
      login(data.access_token, data.session.user, data.session)
      navigate('/', { replace: true })
    }).catch(() => setError(true))
  }, [authorization, login, navigate])

  return <div className="min-h-screen flex flex-col items-center justify-center bg-bg text-ink gap-4">
    {error ? <><p role="alert">Single sign-on failed. Please try again or contact your administrator.</p>
      <Link to="/login">Back to sign in</Link></> : <p role="status">Signing in…</p>}
  </div>
}

export default OIDCCallback
