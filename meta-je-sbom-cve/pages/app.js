/* Evidence viewer. Reads a static store published under ./store/:
     store/index.json                 { machines: [{machine, latest, ...}] }
     store/<machine>/index.json       { runs: [{id, generated, previous, ...}] }
     store/<machine>/<run>/...        run.json, parsed/, diff-*.md, inventory.md, ...
   Route: #<machine>/<run>/<tab>   (tab = diff | full | inventory) */
(function () {
  var app = document.getElementById("app");
  var STORE = "store";

  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    for (var k in (attrs || {})) {
      if (k === "text") el.textContent = attrs[k];
      else if (k === "html") el.innerHTML = attrs[k];
      else if (k === "onclick") el.onclick = attrs[k];
      else el.setAttribute(k, attrs[k]);
    }
    (kids || []).forEach(function (c) { if (c) el.appendChild(c); });
    return el;
  }
  function getJSON(url) {
    return fetch(url).then(function (r) { if (!r.ok) throw new Error(url + " " + r.status); return r.json(); });
  }
  function getText(url) {
    return fetch(url).then(function (r) { return r.ok ? r.text() : null; });
  }

  function parseHash() {
    var p = (location.hash || "").replace(/^#/, "").split("/").filter(Boolean);
    return { machine: p[0] || null, run: p[1] || null, tab: p[2] || "diff" };
  }

  function render() {
    var route = parseHash();
    if (!route.machine) return renderHome();
    return renderRun(route);
  }

  function renderHome() {
    app.textContent = "loading…";
    getJSON(STORE + "/index.json").then(function (idx) {
      var machines = idx.machines || [];
      if (!machines.length) { app.textContent = "No runs published yet."; return; }
      app.innerHTML = "";
      machines.forEach(function (m) {
        var head = h("h2", { text: m.machine + " " });
        head.appendChild(h("span", { class: "muted", text: "(" + m.runs + " runs, latest " + m.latest + ")" }));
        app.appendChild(head);
        var ul = h("ul", { class: "timeline" });
        getJSON(STORE + "/" + m.machine + "/index.json").then(function (mi) {
          (mi.runs || []).forEach(function (r) {
            var li = h("li", { onclick: function () { location.hash = m.machine + "/" + r.id + "/diff"; } }, [
              h("span", { class: "id", text: r.id }),
              h("div", { class: "meta", text: (r.generated || "") + " · " + (r.commit || "").slice(0, 8) +
                         (r.previous && r.previous !== "null" ? " · vs " + r.previous : " · baseline") }),
            ]);
            ul.appendChild(li);
          });
        });
        app.appendChild(ul);
      });
    }).catch(function (e) { app.textContent = "Failed to load store: " + e.message; });
  }

  function tabBtn(label, key, route) {
    return h("button", {
      class: route.tab === key ? "active" : "",
      text: label,
      onclick: function () { location.hash = route.machine + "/" + route.run + "/" + key; },
    });
  }

  function renderRun(route) {
    var base = STORE + "/" + route.machine + "/" + route.run + "/";
    app.textContent = "loading…";
    getJSON(base + "run.json").then(function (run) {
      app.innerHTML = "";
      app.appendChild(h("p", {}, [
        h("a", { href: "#", text: "← all runs" }),
      ]));
      var head = h("h2", { text: route.machine + " / " + route.run + " " });
      head.appendChild(h("span", { class: "muted", text: (run.generated || "") + " · " + (run.commit || "").slice(0, 12) }));
      app.appendChild(head);

      app.appendChild(h("div", { class: "tabs row" }, [
        tabBtn("Diff", "diff", route),
        tabBtn("Full", "full", route),
        tabBtn("Layer inventory", "inventory", route),
      ]));
      var body = h("div", {});
      app.appendChild(body);

      var dl = h("div", { class: "downloads" });
      [["cve.json", "CVE manifest (JSON)"], ["sbom.spdx.json", "SBOM (SPDX)"],
       ["components.tsv", "components.tsv"], ["packages.manifest", "package manifest"],
       ["license.manifest", "license manifest"], ["build-meta.json", "build metadata"],
       ["parsed/unpatched.csv", "unpatched.csv"]].forEach(function (d) {
        fetch(base + d[0], { method: "HEAD" }).then(function (r) {
          if (r.ok) dl.appendChild(h("a", { href: base + d[0], text: d[1] }));
        });
      });
      app.appendChild(dl);

      if (route.tab === "full") return renderFull(base, body);
      if (route.tab === "inventory") return renderMd(base + "inventory.md", body, "No layer inventory for this run.");
      return renderDiff(base, run, body);
    }).catch(function (e) { app.textContent = "Run not found: " + e.message; });
  }

  function renderMd(url, body, empty) {
    getText(url).then(function (t) {
      body.innerHTML = t ? window.md.render(t) : "<p class='muted'>" + empty + "</p>";
    });
  }

  function renderDiff(base, run, body) {
    if (!run.previous || run.previous === "null") {
      body.innerHTML = "<p class='muted'>Baseline run — no previous run to diff against. See the Full tab.</p>";
      return;
    }
    Promise.all([getText(base + "diff-cve.md"), getText(base + "diff-sbom.md")]).then(function (r) {
      body.innerHTML =
        (r[0] ? window.md.render(r[0]) : "<p class='muted'>No CVE diff.</p>") +
        "<hr>" +
        (r[1] ? window.md.render(r[1]) : "<p class='muted'>No SBOM diff.</p>");
    });
  }

  function renderFull(base, body) {
    body.textContent = "loading…";
    Promise.all([
      getJSON(base + "parsed/cve_summary.json").catch(function () { return null; }),
      getText(base + "parsed/unpatched_by_package.csv"),
      getText(base + "components.tsv"),
    ]).then(function (r) {
      var sum = r[0], byPkg = r[1], comps = r[2];
      body.innerHTML = "";
      if (sum) {
        var sev = sum.by_severity || {};
        var cards = h("div", { class: "cards" });
        [["critical", "crit"], ["high", "high"], ["medium", "med"], ["low", "low"], ["unknown", ""]].forEach(function (s) {
          cards.appendChild(h("div", { class: "card " + s[1] }, [
            h("div", { class: "n", text: String(sev[s[0]] || 0) }),
            h("div", { text: s[0] }),
          ]));
        });
        body.appendChild(h("h2", { text: "Unpatched CVEs by severity" }));
        body.appendChild(cards);
        body.appendChild(h("p", { class: "muted", text:
          sum.packages + " packages scanned · " + sum.packages_with_unpatched + " with unpatched CVEs" }));
      }
      if (byPkg) { body.appendChild(h("h2", { text: "Unpatched by package" })); body.appendChild(csvTable(byPkg)); }
      if (comps) {
        body.appendChild(h("h2", { text: "SBOM components" }));
        var rows = comps.trim().split("\n").map(function (l) { return l.split("\t"); });
        body.appendChild(tableFrom(["component", "version", "license"], rows.map(function (c) { return c.slice(0, 3); })));
      }
    });
  }

  function csvTable(text) {
    var lines = text.trim().split("\n");
    var head = lines[0].split(",");
    return tableFrom(head, lines.slice(1).map(function (l) { return splitCsv(l); }));
  }
  function splitCsv(line) {
    var out = [], cur = "", q = false;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
      else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c;
    }
    out.push(cur); return out;
  }
  function tableFrom(head, rows) {
    var sortState = { col: -1, dir: 1 };
    var table = h("table");
    function draw() {
      var body = rows.slice();
      if (sortState.col >= 0) {
        body.sort(function (a, b) {
          var x = a[sortState.col] || "", y = b[sortState.col] || "";
          var nx = parseFloat(x), ny = parseFloat(y);
          if (!isNaN(nx) && !isNaN(ny)) return (nx - ny) * sortState.dir;
          return x.localeCompare(y) * sortState.dir;
        });
      }
      table.innerHTML = "";
      var tr = h("tr");
      head.forEach(function (hcol, ci) {
        tr.appendChild(h("th", { text: hcol, onclick: function () {
          sortState.dir = sortState.col === ci ? -sortState.dir : 1;
          sortState.col = ci; draw();
        } }));
      });
      table.appendChild(h("thead", {}, [tr]));
      var tb = h("tbody");
      body.forEach(function (row) {
        tb.appendChild(h("tr", {}, head.map(function (_, ci) { return h("td", { text: row[ci] || "" }); })));
      });
      table.appendChild(tb);
    }
    draw();
    return table;
  }

  window.addEventListener("hashchange", render);
  render();
})();
