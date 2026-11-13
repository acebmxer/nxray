// Folds the menu's groups (Monitor, Configure, Switch, Admin) shut and open
// when their heading is pressed. Which groups are shut is kept in this
// browser (localStorage); the group holding the open page always starts open.
// Loaded right after the menu, not deferred, so a shut group is never drawn
// open first. Without this file every group stays open.
(function () {
  "use strict";
  var KEY = "nxray-nav-shut";
  var NAME = /^[A-Za-z0-9-]+$/;

  // The names of the shut groups; nothing when storage is off or holds junk.
  function readShut() {
    try {
      var list = JSON.parse(window.localStorage.getItem(KEY) || "[]");
      if (!Array.isArray(list)) return [];
      return list.filter(function (name) {
        return typeof name === "string" && NAME.test(name);
      });
    } catch (e) {
      return [];
    }
  }

  function writeShut(list) {
    try {
      window.localStorage.setItem(KEY, JSON.stringify(list));
    } catch (e) {
      // Storage off (private window, blocked): the fold lasts for this page.
    }
  }

  function setShut(group, shut) {
    group.classList.toggle("nav-group-shut", shut);
    var toggle = group.querySelector("[data-nav-toggle]");
    if (toggle) toggle.setAttribute("aria-expanded", shut ? "false" : "true");
  }

  var shutNames = readShut();
  var groups = document.querySelectorAll("[data-nav-group]");
  Array.prototype.forEach.call(groups, function (group) {
    var name = group.getAttribute("data-nav-group");
    var here = group.classList.contains("nav-group-here");
    setShut(group, !here && shutNames.indexOf(name) !== -1);
    var toggle = group.querySelector("[data-nav-toggle]");
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var shut = !group.classList.contains("nav-group-shut");
      setShut(group, shut);
      // Read again: another tab may have folded other groups meanwhile.
      var names = readShut().filter(function (n) {
        return n !== name;
      });
      if (shut) names.push(name);
      writeShut(names);
    });
  });
})();
