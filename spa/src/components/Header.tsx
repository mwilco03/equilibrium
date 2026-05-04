import { Link, NavLink } from "react-router-dom";
import { Search, Github, Grid3x3, Database, ShieldCheck, BarChart3 } from "lucide-react";

const REPO_URL = "https://github.com/mwilco03/equilibrium";

export function Header() {
  return (
    <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur">
      <div className="mx-auto flex max-w-screen-2xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
        <Link to="/" className="flex items-center gap-2 text-lg font-semibold">
          <Grid3x3 className="h-5 w-5 text-cyan-400" aria-hidden />
          equilibrium
        </Link>
        <nav className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
          <NavItem to="/" label="Matrix" icon={Grid3x3} end />
          <NavItem to="/data-components" label="Data" icon={Database} />
          <NavItem to="/vendors" label="Vendors" icon={ShieldCheck} />
          <NavItem to="/coverage" label="Coverage" icon={BarChart3} />
          <NavItem to="/search" label="Search" icon={Search} />
        </nav>
        <div className="ml-auto">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-zinc-400 hover:text-zinc-100"
            aria-label="GitHub repository"
          >
            <Github className="h-4 w-4" aria-hidden />
            <span className="hidden sm:inline">repo</span>
          </a>
        </div>
      </div>
    </header>
  );
}

interface NavItemProps {
  to: string;
  label: string;
  icon: typeof Grid3x3;
  end?: boolean;
}

function NavItem({ to, label, icon: Icon, end }: NavItemProps) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        "flex items-center gap-1 " +
        (isActive ? "text-cyan-400" : "text-zinc-400 hover:text-zinc-100")
      }
    >
      <Icon className="h-4 w-4" aria-hidden />
      {label}
    </NavLink>
  );
}
