// Refreshes the figures of a page by itself (docs/live.md). Served from
// NXray, no inline code. Without this file the page works as it always did.
(function () {
  "use strict";
  var form = document.querySelector("[data-live-picker]");
  if (!form) return;
  var select = form.querySelector("select");
  var pauseButton = form.querySelector("[data-live-pause]");
  var stamp = form.querySelector("[data-live-stamp]");
  var url = form.getAttribute("data-live-url");
  // A page with no figures of its own to refresh (Settings, Users, a result),
  // and a page that refreshes whole: its own address is fetched and <main> swapped.
  var none = form.hasAttribute("data-live-none");
  var whole = form.hasAttribute("data-live-whole");
  // The page was just read when it was opened.
  var lastRead = new Date();
  var floor = parseInt(form.getAttribute("data-live-floor"), 10) || 2;
  var timer = null;
  var paused = false;
  var stopped = false;
  var failures = 0;

  form.classList.add("live-js");

  function seconds() {
    var choice = select.value;
    if (choice === "off") return 0;
    if (choice === "live") return floor;
    return Math.max(parseInt(choice, 10) || 0, floor);
  }

  // The element that says when the figures were read and whether that failed.
  function stampSource() {
    return document.querySelector("[data-live-at]");
  }

  // The address to ask: for live, ports also want rates from the counters.
  function address() {
    if (select.value !== "live" || url.indexOf("/live/port") !== 0) return url;
    return url + (url.indexOf("?") === -1 ? "?" : "&") + "rates=live";
  }

  // A drop-down is changed when it is not on the option the page chose. A
  // single-choice one with no option marked selected starts on its first.
  function selectChanged(f) {
    var marked = false;
    for (var j = 0; j < f.options.length; j++) {
      if (f.options[j].defaultSelected) marked = true;
    }
    for (var k = 0; k < f.options.length; k++) {
      var expected = f.options[k].defaultSelected || (!marked && !f.multiple && k === 0);
      if (f.options[k].selected !== expected) return true;
    }
    return false;
  }

  // True while someone is typing, has changed a field or has text selected:
  // refreshing then leaves them reading figures that move or drops the selection.
  function userBusy() {
    // Text selected in the page (to copy it): swapping <main> would drop it.
    var picked = window.getSelection && window.getSelection();
    if (picked && !picked.isCollapsed && picked.toString() !== "") {
      var main = document.querySelector("main");
      if (main && (main.contains(picked.anchorNode) || main.contains(picked.focusNode))) return true;
    }
    var active = document.activeElement;
    if (active && !form.contains(active) && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) {
      return true;
    }
    var fields = document.querySelectorAll("main input, main select, main textarea");
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      if (f.type === "hidden" || f.type === "submit" || f.type === "button") continue;
      if (f.type === "checkbox" || f.type === "radio") {
        if (f.checked !== f.defaultChecked) return true;
      } else if (f.tagName === "SELECT") {
        if (selectChanged(f)) return true;
      } else if (f.value !== f.defaultValue) {
        return true;
      }
    }
    return false;
  }

  function showStamp(text, warn) {
    stamp.textContent = text;
    stamp.classList.toggle("live-warn", !!warn);
  }

  function describe() {
    var r = stampSource();
    if (stopped) return;
    if (none) {
      pauseButton.hidden = true;
      showStamp(seconds() ? "Nothing on this page refreshes" : "", false);
      return;
    }
    if (whole) {
      if (!seconds()) {
        showStamp("", false);
        pauseButton.hidden = true;
        return;
      }
      pauseButton.hidden = false;
      pauseButton.textContent = paused ? "Resume" : "Pause";
      if (lastRead) showStamp("Updated " + lastRead.toLocaleTimeString() + (paused ? " (paused)" : ""), false);
      else showStamp(paused ? "(paused)" : "", false);
      return;
    }
    if (!seconds()) {
      showStamp("", false);
      pauseButton.hidden = true;
      return;
    }
    pauseButton.hidden = false;
    pauseButton.textContent = paused ? "Resume" : "Pause";
    if (r && r.getAttribute("data-live-at")) {
      var at = new Date(parseInt(r.getAttribute("data-live-at"), 10) * 1000);
      var text = "Updated " + at.toLocaleTimeString();
      if (paused) text += " (paused)";
      showStamp(text, r.hasAttribute("data-live-problem"));
    }
  }

  function schedule(extra) {
    clearTimeout(timer);
    describe();
    var s = seconds();
    if (none || !s || paused || stopped) return;
    var wait = s * 1000;
    if (extra) wait = Math.min(60000, wait * Math.pow(2, failures));
    timer = setTimeout(tick, wait);
  }

  // A whole page: the new <main> replaces the old one. Which <details> are
  // open, and how far each wide table is scrolled, are carried over.
  function applyWhole(html) {
    var parsed = new DOMParser().parseFromString(html, "text/html");
    var fresh = parsed.querySelector("main");
    var old = document.querySelector("main");
    if (!fresh || !old) return;
    var open = [];
    old.querySelectorAll("details").forEach(function (d) { open.push(d.open); });
    var scrolls = [];
    old.querySelectorAll(".card-flush, .table-wrap").forEach(function (e) { scrolls.push(e.scrollLeft); });
    var imported = document.importNode(fresh, true);
    imported.querySelectorAll("details").forEach(function (d, i) { if (i < open.length) d.open = open[i]; });
    old.replaceWith(imported);
    imported.querySelectorAll(".card-flush, .table-wrap").forEach(function (e, i) {
      if (i < scrolls.length) e.scrollLeft = scrolls[i];
    });
    lastRead = new Date();
  }

  function apply(html) {
    if (whole) return applyWhole(html);
    var parsed = new DOMParser().parseFromString(html, "text/html");
    var fresh = parsed.querySelectorAll("[data-live-region]");
    // Each region the answer carries replaces the one of that name; a region
    // the answer leaves out is left as it is.
    for (var i = 0; i < fresh.length; i++) {
      var name = fresh[i].getAttribute("data-live-region");
      var old = document.querySelector('[data-live-region="' + name + '"]');
      if (old) old.replaceWith(document.importNode(fresh[i], true));
    }
  }

  function tick() {
    if (document.hidden || userBusy()) {
      schedule(false);
      return;
    }
    fetch(address(), {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "X-Requested-With": "nxray-live" },
    })
      .then(function (response) {
        // Signed out: the server sent us to the sign-in page.
        if (response.redirected && (!whole || /\/login/.test(response.url))) {
          stopped = true;
          showStamp("Signed out. Reload the page to sign in again.", true);
          pauseButton.hidden = true;
          return null;
        }
        if (response.redirected) throw new Error("moved");
        if (response.status === 204) return null;
        if (!response.ok) throw new Error("status " + response.status);
        return response.text();
      })
      .then(function (html) {
        // Someone may have ticked a box while the answer was on its way; the
        // answer cannot know that, so drop it and wait for the next round.
        if (html && !userBusy()) apply(html);
        failures = 0;
        schedule(false);
      })
      .catch(function () {
        failures += 1;
        showStamp("NXray did not answer. Trying again.", true);
        if (!stopped) timer = setTimeout(tick, Math.min(60000, seconds() * 1000 * Math.pow(2, failures)));
      });
  }

  select.addEventListener("change", function () {
    failures = 0;
    paused = false;
    // Keep the choice in the cookie without leaving the page.
    fetch(form.action, {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
      body: new URLSearchParams(new FormData(form)),
    }).catch(function () {});
    clearTimeout(timer);
    if (none) schedule(false);
    else if (seconds()) tick();
    else schedule(false);
  });

  pauseButton.addEventListener("click", function () {
    paused = !paused;
    if (paused) schedule(false);
    else tick();
  });

  document.addEventListener("visibilitychange", function () {
    if (!none && !document.hidden && seconds() && !paused && !stopped) {
      clearTimeout(timer);
      tick();
    }
  });

  schedule(false);
})();
