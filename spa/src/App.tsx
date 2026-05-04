import { Outlet } from "react-router-dom";
import { Header } from "./components/Header";

export function App() {
  return (
    <div className="flex h-full flex-col bg-zinc-950 text-zinc-100">
      <Header />
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
