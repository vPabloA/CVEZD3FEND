import { NavLink, Outlet } from "react-router-dom";

const NAV_LINKS = [
  { to: "/", label: "Search", end: true },
  { to: "/analyze", label: "Analyze" },
  { to: "/coverage", label: "Coverage" },
  { to: "/ai-review", label: "AI Review" },
];

export default function Layout() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3">
          <NavLink to="/" className="flex items-center gap-2 font-semibold text-slate-800">
            <span className="inline-block h-3 w-3 rounded-sm bg-link" aria-hidden="true" />
            CVEzD3FEND
          </NavLink>
          <nav className="flex gap-1" aria-label="Main navigation">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) =>
                  `rounded px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-link ${
                    isActive ? "bg-link text-white" : "text-slate-600 hover:bg-slate-100"
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 px-4 py-3 text-center text-xs text-slate-400">
        Static-first defensive intelligence navigator. Data: data/dist/knowledge-bundle.json — zero third-party API calls at runtime.
      </footer>
    </div>
  );
}
