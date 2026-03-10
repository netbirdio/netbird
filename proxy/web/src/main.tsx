import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ErrorPage } from './ErrorPage.tsx'
import { CertPendingPage } from './CertPendingPage.tsx'
import { getData } from '@/data'

const data = getData()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {data.page === 'error' && data.error ? (
      <ErrorPage {...data.error} />
    ) : data.page === 'cert-pending' && data.certPending ? (
      <CertPendingPage {...data.certPending} />
    ) : (
      <App />
    )}
  </StrictMode>,
)
