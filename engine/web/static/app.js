/* Small helpers, written by hand so the page needs nothing from a CDN.
   Both are progressive: the form submits and the lists read fine without them. */

(function () {
  "use strict";

  // Drag-and-drop wired to the plain file input, so the form still works without JS.
  function setupDropzone() {
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("file-input");
    var chosen = document.getElementById("chosen");
    if (!zone || !input || !chosen) return;

    function show() {
      if (input.files.length) {
        chosen.textContent = input.files[0].name;
        chosen.classList.add("shown");
      } else {
        chosen.classList.remove("shown");
      }
    }

    input.addEventListener("change", show);

    ["dragenter", "dragover"].forEach(function (name) {
      zone.addEventListener(name, function (event) {
        event.preventDefault();
        zone.classList.add("over");
      });
    });

    ["dragleave", "drop"].forEach(function (name) {
      zone.addEventListener(name, function (event) {
        event.preventDefault();
        zone.classList.remove("over");
      });
    });

    zone.addEventListener("drop", function (event) {
      if (event.dataTransfer.files.length) {
        input.files = event.dataTransfer.files;
        show();
      }
    });
  }

  // Type-to-filter over any container of rows or cards. A Windows Security
  // sample produces 146 candidates; scrolling is not a way to find one.
  function setupFilters() {
    var inputs = document.querySelectorAll("[data-filter-target]");
    Array.prototype.forEach.call(inputs, function (input) {
      var container = document.querySelector(input.getAttribute("data-filter-target"));
      var counter = input.getAttribute("data-filter-count")
        ? document.querySelector(input.getAttribute("data-filter-count"))
        : null;
      if (!container) return;

      var items = container.querySelectorAll("[data-filter-text]");

      input.addEventListener("input", function () {
        var needle = input.value.trim().toLowerCase();
        var shown = 0;
        Array.prototype.forEach.call(items, function (item) {
          var hit = !needle || item.getAttribute("data-filter-text").indexOf(needle) !== -1;
          item.classList.toggle("is-hidden", !hit);
          if (hit) shown += 1;
        });
        if (counter) counter.textContent = shown;
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupDropzone();
    setupFilters();
  });
})();
