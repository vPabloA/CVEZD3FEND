import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

// HashRouter: `CVEzD3FEND serve` (Python http.server) has no SPA fallback,
// so deep links (/#/route/ROUTE-...) must work without server-side rewrites
// (static-first / portable principle).
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>
);
