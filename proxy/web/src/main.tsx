import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ErrorPage } from './ErrorPage.tsx'
import { getData } from '@/data'

const data = getData()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {data.page === 'error' && data.error ? (
      <ErrorPage {...data.error} />
    ) : (
      <App />
    )}
  </StrictMode>,
)
