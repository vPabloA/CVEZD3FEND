import { Link, Outlet, useLocation } from "react-router-dom";

export default function Layout() {
  const location = useLocation();
  const onAnalyze = location.pathname.startsWith("/analyze");

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-200 bg-white/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3">
          <Link to="/" className="flex items-center gap-2 font-semibold text-slate-800">
            <span className="inline-block h-3 w-3 rounded-sm bg-link" aria-hidden="true" />
            CVEzD3FEND
          </Link>
          {!onAnalyze ? (
            <Link
              to="/analyze"
              className="rounded-full border border-link bg-link px-3 py-1.5 text-sm font-medium text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-link hover:bg-blue-700"
            >
              Analizar CVE
            </Link>
          ) : (
            <Link
              to="/"
              className="rounded-full border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-link hover:bg-slate-50"
            >
              Inicio
            </Link>
          )}
        </div>
      </header>
      <main className={onAnalyze ? "w-full flex-1 bg-slate-100" : "mx-auto w-full max-w-7xl flex-1 px-4 py-6"}>
        <Outlet />
      </main>
    </div>
  );
}
