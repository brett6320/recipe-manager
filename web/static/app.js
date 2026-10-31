// Small progressive enhancements. No inline scripts (strict CSP).
(function () {
  "use strict";
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (ev) => {
      if (!window.confirm(f.getAttribute("data-confirm"))) ev.preventDefault();
    });
  });
})();
