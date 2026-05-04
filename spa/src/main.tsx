import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";
import "./index.css";

// 404.html fallback re-entry point: if the static 404 redirected us with ?p=,
// rewrite the URL back to the original path before React Router boots.
(function rebootstrapFromFallback() {
  const params = new URLSearchParams(window.location.search);
  const originalPath = params.get("p");
  if (!originalPath) return;
  const originalQuery = params.get("q");
  const url =
    "/equilibrium" +
    originalPath +
    (originalQuery ? "?" + originalQuery : "") +
    window.location.hash;
  window.history.replaceState(null, "", url);
})();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
