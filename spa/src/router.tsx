import { createBrowserRouter } from "react-router-dom";
import { App } from "./App";
import { MatrixPage } from "./pages/MatrixPage";
import { TechniquePage } from "./pages/TechniquePage";
import { SearchPage } from "./pages/SearchPage";

// Base path constant: must match vite.config.ts `base` and the
// `<base>` segment used by the 404.html SPA fallback.
const ROUTER_BASENAME = "/equilibrium";

export const router = createBrowserRouter(
  [
    {
      path: "/",
      element: <App />,
      children: [
        { index: true, element: <MatrixPage /> },
        { path: "techniques/:techniqueId", element: <TechniquePage /> },
        { path: "search", element: <SearchPage /> },
      ],
    },
  ],
  { basename: ROUTER_BASENAME },
);
