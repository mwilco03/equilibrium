import { Link, NavLink } from "react-router-dom";
import { Search, Github, Grid3x3 } from "lucide-react";

const REPO_URL = "https://github.com/mwilco03/equilibrium";

export function Header() {
  return (
    <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur">
      <div className="mx-auto flex max-w-screen-2xl items-center gap-6 px-4 py-3">
        <Link to="/" className="flex items-center gap-2 text-lg font-semibold">
          <Grid3x3 className="h-5 w-5 text-cyan-400" aria-hidden />
          equilibrium
        </Link>
        <nav className="flex items-center gap-4 text-sm">
          <NavLink
            to="/"
            end
            className={({ isActive }) =>
              isActive ? "text-cyan-400" : "text-zinc-400 hover:text-zinc-100"
            }
          >
            Matrix
          </NavLink>
          <NavLink
            to="/search"
            className={({ isActive }) =>
              "flex items-center gap-1 " +
              (isActive ? "text-cyan-400" : "text-zinc-400 hover:text-zinc-100")
            }
          >
            <Search className="h-4 w-4" aria-hidden />
            Search
          </NavLink>
        </nav>
        <div className="ml-auto">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-zinc-400 hover:text-zinc-100"
          >
            <Github className="h-4 w-4" aria-hidden />
            repo
          </a>
        </div>
      </div>
    </header>
  );
}
