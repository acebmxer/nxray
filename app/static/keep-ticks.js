// The ticked ports on the Ports page. Served from NXray, no inline code.
// - Keeps them when a link on the page (the colour tabs, the filters, Read
//   again) reloads it.
// - Keeps the list of ticked ports at the top of the "Change several ports"
//   panel in step with the table: each name in it is a label for its port's
//   box, so pressing it unticks the port.
// Without this file the page still works; the list then shows the ports that
// were ticked when the page was drawn.
(function () {
  "use strict";
  var BOXES = 'input[type="checkbox"][name="names"]';

  document.addEventListener("click", function (event) {
    var link = event.target.closest && event.target.closest("a[data-keep-ticks]");
    if (!link || event.defaultPrevented || event.button !== 0) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    var boxes = document.querySelectorAll(BOXES + ":checked");
    if (!boxes.length) return;
    var url = new URL(link.href, window.location.href);
    url.searchParams.delete("tick");
    for (var i = 0; i < boxes.length; i++) url.searchParams.append("tick", boxes[i].value);
    event.preventDefault();
    window.location.href = url.toString();
  });

  function drawTickedList() {
    var list = document.querySelector("[data-ticked-list]");
    if (!list) return;
    var boxes = document.querySelectorAll(BOXES + ":checked");
    while (list.firstChild) list.removeChild(list.firstChild);
    for (var i = 0; i < boxes.length; i++) {
      var box = boxes[i];
      if (!box.id) continue;
      var item = document.createElement("li");
      var label = document.createElement("label");
      label.className = "pill pill-untick";
      label.htmlFor = box.id;
      label.title = "Untick " + box.value;
      label.appendChild(document.createTextNode(box.value));
      var mark = document.createElement("span");
      mark.className = "untick-x";
      mark.setAttribute("aria-hidden", "true");
      mark.textContent = "×";
      label.appendChild(mark);
      item.appendChild(label);
      list.appendChild(item);
    }
  }

  document.addEventListener("change", function (event) {
    if (event.target.matches && event.target.matches(BOXES)) drawTickedList();
  });
  // The browser may bring back ticks on going back to the page.
  window.addEventListener("pageshow", drawTickedList);
  drawTickedList();
})();
