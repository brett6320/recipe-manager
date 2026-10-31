// Small progressive enhancements. No inline scripts (strict CSP).
(function () {
  "use strict";
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (ev) => {
      if (!window.confirm(f.getAttribute("data-confirm"))) ev.preventDefault();
    });
  });
  document.querySelectorAll("[data-toggle-grantee]").forEach((sel) => {
    const form = sel.closest("form");
    const update = () => {
      form.querySelectorAll("[data-grantee]").forEach((el) => {
        el.hidden = el.getAttribute("data-grantee") !== sel.value;
      });
    };
    sel.addEventListener("change", update);
    update();
  });
  document.querySelectorAll("[data-print]").forEach((b) => b.addEventListener("click", () => window.print()));
})();
