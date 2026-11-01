// Keeps the ticked ports when a link on the Ports page (the colour tabs, the
// filters, Read again) reloads it. Served from NXray, no inline code.
(function () {
  "use strict";
  document.addEventListener("click", function (event) {
    var link = event.target.closest && event.target.closest("a[data-keep-ticks]");
    if (!link || event.defaultPrevented || event.button !== 0) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    var boxes = document.querySelectorAll('input[type="checkbox"][name="names"]:checked');
    if (!boxes.length) return;
    var url = new URL(link.href, window.location.href);
    url.searchParams.delete("tick");
    for (var i = 0; i < boxes.length; i++) url.searchParams.append("tick", boxes[i].value);
    event.preventDefault();
    window.location.href = url.toString();
  });
})();
