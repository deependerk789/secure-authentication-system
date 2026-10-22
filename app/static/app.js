/* SecureAuth — front-end behaviour.
 *
 * The password is only ever measured inside the browser; nothing is sent to
 * a third-party analyser.  The score below mirrors the server-side rule in
 * app/security.py so the meter and the stored value agree.
 *
 * No inline handlers and no inline style attributes are used, so the page
 * keeps working under a strict Content-Security-Policy.
 */
(() => {
  "use strict";

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------- show / hide password */
  document.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      button.textContent = showing ? "Show" : "Hide";
      button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    });
  });

  /* ------------------------------------------------------------ copy to clipboard */
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(button.dataset.copy);
      if (!target) return;
      const text = target.textContent.trim();
      const original = button.textContent;
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
      } catch (_error) {
        button.textContent = "Copy failed";
      }
      window.setTimeout(() => {
        button.textContent = original;
      }, 1600);
    });
  });

  /* --------------------------------------------------------------- score bars */
  /* The width is applied here instead of with an inline style attribute so the
   * Content-Security-Policy can stay free of 'unsafe-inline'. */
  document.querySelectorAll("[data-score]").forEach((element) => {
    const value = Math.max(0, Math.min(100, Number(element.dataset.score) || 0));
    element.style.width = value + "%";
  });

  /* ------------------------------------------------------------- password meter */
  const meterInput = document.querySelector('input[aria-describedby*="strength-text"]');
  const fill = document.getElementById("strength-fill");
  const label = document.getElementById("strength-text");
  const scoreLabel = document.getElementById("strength-score");

  function scorePassword(value) {
    if (!value) return 0;
    let score = 0;
    if (value.length >= 10) score += 35;
    if (value.length >= 14) score += 15;
    if (value.length >= 20) score += 10;
    if (/[a-z]/.test(value)) score += 10;
    if (/[A-Z]/.test(value)) score += 10;
    if (/\d/.test(value)) score += 10;
    if (/[^A-Za-z0-9]/.test(value)) score += 10;
    if (new Set(value).size <= 3 || /^(password123|qwerty12345|1234567890|letmein1234)$/i.test(value)) {
      score = Math.min(score, 25);
    }
    return Math.min(score, 100);
  }

  function strengthOf(score) {
    if (score >= 80) return "Strong";
    if (score >= 55) return "Good";
    if (score >= 30) return "Fair";
    return "Weak";
  }

  function colourFor(score) {
    if (score >= 80) return "var(--good)";
    if (score >= 55) return "var(--teal)";
    if (score >= 30) return "var(--amber)";
    return "var(--danger)";
  }

  if (meterInput && fill && label && scoreLabel) {
    const render = () => {
      const score = scorePassword(meterInput.value);
      fill.style.width = score + "%";
      fill.style.background = colourFor(score);
      label.textContent = "Password strength: " + (meterInput.value ? strengthOf(score) : "not checked");
      scoreLabel.textContent = score + "%";
    };
    meterInput.addEventListener("input", render);
    render();
  }

  /* ------------------------------------------------------- one-time code input */
  document.querySelectorAll(".code-input").forEach((input) => {
    input.addEventListener("input", () => {
      const digits = input.value.replace(/\D/g, "").slice(0, 6);
      if (digits !== input.value) input.value = digits;
    });
  });

  /* ------------------------------------------------------------- colour scheme */
  const themeButtons = document.querySelectorAll("[data-theme-toggle]");
  if (themeButtons.length) {
    const apply = (theme) => {
      document.documentElement.setAttribute("data-theme", theme);
      try {
        window.localStorage.setItem("secureauth-theme", theme);
      } catch (_error) {
        /* storage is optional, the theme still works for this page */
      }
      themeButtons.forEach((button) => {
        button.setAttribute(
          "aria-label",
          theme === "light" ? "Switch to the dark theme" : "Switch to the light theme"
        );
      });
    };
    const current = () => document.documentElement.getAttribute("data-theme") || "dark";
    apply(current());
    themeButtons.forEach((button) => {
      button.addEventListener("click", () => {
        apply(current() === "light" ? "dark" : "light");
      });
    });
  }

  /* ------------------------------------------------------------------ score ring */
  /* The ring is plain SVG.  The dash offset is written as an SVG attribute
   * rather than a style attribute, so the page keeps zero inline styles and
   * the CSS transition still animates. */
  const ring = document.querySelector("[data-ring]");
  const ringFill = ring ? ring.querySelector(".ring-fill") : null;
  const ringNumber = ring ? ring.querySelector("[data-count]") : null;

  if (ring && ringFill) {
    const radius = Number(ringFill.getAttribute("r")) || 52;
    const circumference = 2 * Math.PI * radius;
    const target = Math.max(0, Math.min(100, Number(ring.dataset.ring) || 0));

    ringFill.setAttribute("stroke-dasharray", String(circumference));
    ringFill.setAttribute("stroke-dashoffset", String(circumference));

    const paint = () => {
      ringFill.setAttribute("stroke-dashoffset", String(circumference * (1 - target / 100)));
      if (ringNumber) ringNumber.textContent = String(target);
    };

    if (reducedMotion) {
      paint();
    } else {
      window.requestAnimationFrame(() => window.requestAnimationFrame(paint));
    }
  }

  /* ------------------------------------------------------------- count-up numbers */
  if (!reducedMotion) {
    document.querySelectorAll("[data-count]").forEach((element) => {
      if (element.closest("[data-ring]")) return; /* the ring handles its own */
      const target = Number(element.dataset.count) || 0;
      const duration = 900;
      const start = performance.now();
      const step = (now) => {
        const progress = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = String(Math.round(target * eased));
        if (progress < 1) window.requestAnimationFrame(step);
      };
      window.requestAnimationFrame(step);
    });
  }

  /* ------------------------------------------------------------- scroll reveal */
  const revealables = document.querySelectorAll(".reveal");
  if (revealables.length) {
    if (reducedMotion || !("IntersectionObserver" in window)) {
      revealables.forEach((element) => element.classList.add("is-visible"));
    } else {
      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          });
        },
        { threshold: 0.12, rootMargin: "0px 0px -6% 0px" }
      );
      revealables.forEach((element) => observer.observe(element));
    }
  }

  /* ------------------------------------------------------------------- 3D tilt */
  /* Panels lean towards the pointer.  The rotation is written through custom
   * properties, which keeps the markup free of inline style attributes. */
  const tiltables = document.querySelectorAll(".tilt");
  if (tiltables.length && !reducedMotion && window.matchMedia("(hover: hover)").matches) {
    tiltables.forEach((panel) => {
      let frame = 0;
      let queued = null;

      const render = () => {
        frame = 0;
        if (!queued) return;
        const { rx, ry, mx, my } = queued;
        panel.style.setProperty("--rx", rx.toFixed(2) + "deg");
        panel.style.setProperty("--ry", ry.toFixed(2) + "deg");
        panel.style.setProperty("--mx", mx.toFixed(1) + "px");
        panel.style.setProperty("--my", my.toFixed(1) + "px");
      };

      const schedule = (next) => {
        queued = next;
        if (!frame) frame = window.requestAnimationFrame(render);
      };

      panel.addEventListener("pointermove", (event) => {
        const box = panel.getBoundingClientRect();
        const px = (event.clientX - box.left) / box.width;
        const py = (event.clientY - box.top) / box.height;
        schedule({
          rx: (0.5 - py) * 7,
          ry: (px - 0.5) * 9,
          mx: event.clientX - box.left,
          my: event.clientY - box.top,
        });
      });

      panel.addEventListener("pointerenter", () => panel.classList.add("is-tilting"));

      panel.addEventListener("pointerleave", () => {
        panel.classList.remove("is-tilting");
        schedule({ rx: 0, ry: 0, mx: 0, my: 0 });
      });
    });
  }

  /* ---------------------------------------------------- pointer spotlight only */
  if (!reducedMotion) {
    document.querySelectorAll(".glass:not(.tilt)").forEach((panel) => {
      let frame = 0;
      let point = null;
      const render = () => {
        frame = 0;
        if (!point) return;
        panel.style.setProperty("--mx", point.x.toFixed(1) + "px");
        panel.style.setProperty("--my", point.y.toFixed(1) + "px");
      };
      panel.addEventListener("pointermove", (event) => {
        const box = panel.getBoundingClientRect();
        point = { x: event.clientX - box.left, y: event.clientY - box.top };
        if (!frame) frame = window.requestAnimationFrame(render);
      });
    });
  }
})();
