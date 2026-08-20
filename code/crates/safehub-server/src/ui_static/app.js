// SafeHub local UI helpers (minimal, no dependencies).
document.addEventListener("DOMContentLoaded", () => {
  document.documentElement.dataset.ready = "1";

  // "Copy token" buttons.
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sel = btn.getAttribute("data-copy");
      const el = sel ? document.querySelector(sel) : null;
      if (!el) return;
      const text = el.textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied!";
        setTimeout(() => {
          btn.textContent = "Copy";
        }, 1500);
      } catch (_) {
        btn.textContent = "Select & copy";
      }
    });
  });

  // GitHub's "/" shortcut focuses the header search box.
  const search = document.getElementById("q");
  if (search) {
    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "/" || ev.metaKey || ev.ctrlKey || ev.altKey) return;
      const tag = (ev.target && ev.target.tagName) || "";
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) return;
      ev.preventDefault();
      search.focus();
    });
  }

  // Keep the active repo tab visible when the tab strip scrolls horizontally.
  const active = document.querySelector(".repo-tabs li.active a");
  if (active && typeof active.scrollIntoView === "function") {
    active.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
});
