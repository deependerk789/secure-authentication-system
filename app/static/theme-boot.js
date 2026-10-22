/* SecureAuth — theme bootstrap.
 *
 * This file is loaded in <head> without `defer` so it runs before the first
 * paint.  It applies the stored colour scheme and marks the document as
 * script-enabled, which is what enables the scroll-reveal animation.  If
 * JavaScript never runs, nothing is hidden and the page stays readable.
 *
 * It is a separate file on purpose: a strict Content-Security-Policy with
 * `script-src 'self'` blocks inline scripts, so this cannot be a <script>
 * block in the template.
 */
(() => {
  "use strict";

  const root = document.documentElement;
  root.classList.add("js");

  const stored = window.localStorage ? window.localStorage.getItem("secureauth-theme") : null;
  if (stored === "light" || stored === "dark") {
    root.setAttribute("data-theme", stored);
  }
})();
