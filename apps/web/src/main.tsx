import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/app.css';
import { App } from './App.js';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found in document');
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
