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
    return { machine: p[0] || null, run: p[1] || null, tab: p[2] || "triage" };
  }

  function render() {
    var route = parseHash();
    if (!route.machine) return renderHome();
    return renderRun(route);
  }

  // Minimal inline SVG line chart -- no charting dependency for what's
  // 5-20 points. Returns an HTML string; caller sets it via innerHTML.
  function sparkline(points) {
    var w = 320, hgt = 56, pad = 6;
    if (points.length < 2) return "";
    var vals = points.map(function (p) { return p.v; });
    var max = Math.max.apply(null, vals), min = Math.min.apply(null, vals);
    var range = max - min || 1;
    var stepX = w / (points.length - 1);
    var coords = points.map(function (p, i) {
      var x = i * stepX;
      var y = hgt - pad - ((p.v - min) / range) * (hgt - 2 * pad);
      return x.toFixed(1) + "," + y.toFixed(1);
    });
    var circles = points.map(function (p, i) {
      var xy = coords[i].split(",");
      return '<circle cx="' + xy[0] + '" cy="' + xy[1] + '" r="3" fill="var(--accent)">' +
        "<title>" + p.id + ": " + p.v + "</title></circle>";
    }).join("");
    var latest = points[points.length - 1];
    return '<svg viewBox="0 0 ' + w + " " + hgt + '" width="' + w + '" height="' + hgt + '">' +
      '<polyline points="' + coords.join(" ") + '" fill="none" stroke="var(--accent)" stroke-width="2"/>' +
      circles + "</svg>" +
      '<p class="muted">unpatched after noise reduction, oldest → newest -- min ' + min + ", max " + max +
      ", latest " + latest.v + "</p>";
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
        var trend = h("div", {});
        app.appendChild(trend);
        var ul = h("ul", { class: "timeline" });
        getJSON(STORE + "/" + m.machine + "/index.json").then(function (mi) {
          var runs = mi.runs || [];
          runs.forEach(function (r) {
            var li = h("li", { onclick: function () { location.hash = m.machine + "/" + r.id + "/triage"; } }, [
              h("span", { class: "id", text: r.id }),
              h("div", { class: "meta", text: (r.generated || "") + " · " + (r.commit || "").slice(0, 8) +
                         (r.previous && r.previous !== "null" ? " · vs " + r.previous : " · baseline") }),
            ]);
            ul.appendChild(li);
          });
          // Best-effort: older runs (before the upstream triage wrapper
          // landed) may not have a triage.json at all -- points with no
          // data are silently dropped rather than shown as a gap/zero.
          Promise.all(runs.map(function (r) {
            return getJSON(STORE + "/" + m.machine + "/" + r.id + "/triage.json")
              .then(function (t) { return { id: r.id, generated: r.generated, v: t.total_cves }; })
              .catch(function () { return null; });
          })).then(function (points) {
            points = points.filter(Boolean).sort(function (a, b) { return (a.generated || "").localeCompare(b.generated || ""); });
            if (points.length >= 2) trend.innerHTML = sparkline(points);
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
        tabBtn("Triage", "triage", route),
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
      if (route.tab === "triage") return renderTriage(base, body);
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
    body.textContent = "loading…";
    Promise.all([getText(base + "diff-triage.md"), getText(base + "diff-cve.md"), getText(base + "diff-sbom.md")])
      .then(function (r) {
        var diffTriage = r[0], diffCve = r[1], diffSbom = r[2];
        var html = "";
        if (diffTriage) {
          html += "<p class='muted'>What actually changed in the noise-reduced list -- i.e. did the pile a " +
                  "human needs to look at actually get bigger or smaller.</p>" +
                  window.md.render(diffTriage) + "<hr>" +
                  "<h2>Raw CVE-database diff (for reference)</h2>" +
                  "<p class='muted'>Every unpatched CVE, before any noise reduction -- includes routine " +
                  "CVE-database churn (new disclosures, version-bump fixes) unrelated to triage.</p>";
        }
        html += diffCve ? window.md.render(diffCve) : "<p class='muted'>No CVE diff.</p>";
        html += "<hr>" + (diffSbom ? window.md.render(diffSbom) : "<p class='muted'>No SBOM diff.</p>");
        body.innerHTML = html;
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

  var TRIAGE_BUCKETS = [
    ["config_inapplicable_candidates", "config-inapplicable"],
    ["fixed_version_candidates", "fixed-version"],
    ["cpe_mismatch_candidates", "CPE mismatch"],
    ["needs_human_review", "needs human review"],
  ];

  // Entry shape varies by bucket/source (kernel_cve_triage.py and
  // kernel_cve_upstream_triage.py each use their own field names) --
  // pick whichever of these is present as the human-readable "why".
  function bucketEntryDetail(entry) {
    return entry.reason || entry.subject || entry.file ||
      (entry.config_symbol ? "CONFIG_" + entry.config_symbol : "") ||
      entry.commit || entry.detail || "";
  }

  // triage-kernel*.json (thousands of per-CVE entries, 100s of KB) are
  // evidence for an auditor, not a summary for this page -- cards show
  // counts only; clicking one expands a filterable CVE+reason table
  // built from the JSON already fetched (no extra request), instead of
  // sending the reader to the raw report to find out what's in it.
  function bucketSummary(title, report, mdPath) {
    var wrap = h("div", {});
    wrap.appendChild(h("h3", { text: title }));
    if (!report) { wrap.appendChild(h("p", { class: "muted", text: "Not run for this package." })); return wrap; }
    var cards = h("div", { class: "cards" });
    var expanded = h("div", {});
    TRIAGE_BUCKETS.forEach(function (b) {
      var entries = report[b[0]] || [];
      var card = h("div", { class: "card" + (b[0] === "needs_human_review" ? " high" : "") }, [
        h("div", { class: "n", text: String(entries.length) }), h("div", { text: b[1] }),
      ]);
      if (entries.length) {
        card.style.cursor = "pointer";
        card.title = "Click to show the CVE list";
        card.onclick = function () {
          expanded.innerHTML = "";
          expanded.appendChild(h("h4", { text: b[1] + " (" + entries.length + ")" }));
          var rows = entries.map(function (e) { return [e.cve, bucketEntryDetail(e)]; });
          expanded.appendChild(tableFrom(["cve", "why"], rows, { filterable: true }));
        };
      }
      cards.appendChild(card);
    });
    wrap.appendChild(cards);
    wrap.appendChild(expanded);
    wrap.appendChild(h("p", { class: "muted" }, [
      h("a", { href: mdPath, text: "full per-CVE report" }),
    ]));
    return wrap;
  }

  // CVSS3/3.1 vector strings only -- CVSS2's AV letters mean the same
  // thing (N/A/L) but a v2 string ("AV:N/AC:L/Au:N/...") also matches
  // this regex harmlessly, so no separate v2 path is needed.
  function attackVector(vector) {
    var m = /AV:([NLAP])/.exec(vector || "");
    var names = { N: "network", A: "adjacent", L: "local", P: "physical" };
    return m ? names[m[1]] : "unknown";
  }

  function remainingTable(csvText) {
    var records = parseCsvRecords(csvText.replace(/﻿/, ""));
    if (!records.length) return h("p", { class: "muted", text: "No rows." });
    var head = records[0];
    var summaryCol = head.indexOf("summary");
    var severityCol = head.indexOf("severity");
    var vectorCol = head.indexOf("vector");
    var dataRows = records.slice(1).filter(function (r) { return r.length === head.length; });

    // Derived "attack vector" column, inserted right after severity --
    // real signal for prioritization (network-reachable vs. needs local
    // access already) that the raw CVSS vector string buries.
    if (vectorCol >= 0) {
      head = head.slice();
      head.splice(severityCol >= 0 ? severityCol + 1 : head.length, 0, "attack vector");
      dataRows = dataRows.map(function (r) {
        r = r.slice();
        r.splice(severityCol >= 0 ? severityCol + 1 : r.length, 0, attackVector(r[vectorCol]));
        return r;
      });
    }
    var avCol = head.indexOf("attack vector");

    var wrap = h("div", {});
    if (severityCol >= 0 || avCol >= 0) {
      var cards = h("div", { class: "cards" });
      if (severityCol >= 0) {
        var sevCounts = {};
        dataRows.forEach(function (r) {
          var s = (r[severityCol] || "unknown").toLowerCase();
          sevCounts[s] = (sevCounts[s] || 0) + 1;
        });
        [["critical", "crit"], ["high", "high"], ["medium", "med"], ["low", "low"], ["unknown", ""]].forEach(function (s) {
          if (!sevCounts[s[0]]) return;
          cards.appendChild(h("div", { class: "card " + s[1] }, [
            h("div", { class: "n", text: String(sevCounts[s[0]]) }), h("div", { text: s[0] }),
          ]));
        });
      }
      if (avCol >= 0) {
        var avCounts = {};
        dataRows.forEach(function (r) {
          var v = r[avCol] || "unknown";
          avCounts[v] = (avCounts[v] || 0) + 1;
        });
        // network first -- the one that matters most for prioritization.
        [["network", "crit"], ["adjacent", "high"], ["local", ""], ["physical", ""], ["unknown", ""]].forEach(function (s) {
          if (!avCounts[s[0]]) return;
          cards.appendChild(h("div", { class: "card " + s[1] }, [
            h("div", { class: "n", text: String(avCounts[s[0]]) }), h("div", { text: s[0] + " reachable" }),
          ]));
        });
      }
      wrap.appendChild(cards);
    }

    var rows = dataRows.map(function (r) {
      if (summaryCol >= 0 && r[summaryCol] && r[summaryCol].length > 160) {
        r = r.slice();
        r[summaryCol] = r[summaryCol].replace(/\s+/g, " ").slice(0, 160) + "…";
      }
      return r;
    });
    wrap.appendChild(tableFrom(head, rows, { filterable: true }));
    return wrap;
  }

  function renderTriage(base, body) {
    body.textContent = "loading…";
    Promise.all([
      getJSON(base + "parsed/cve_summary.json").catch(function () { return null; }),
      getJSON(base + "triage.json").catch(function () { return null; }),
      getText(base + "triage.md"),
      getJSON(base + "triage-kernel.json").catch(function () { return null; }),
      getJSON(base + "triage-kernel-upstream.json").catch(function () { return null; }),
      getJSON(base + "triage-uboot.json").catch(function () { return null; }),
      getText(base + "triage.filtered.csv"),
      getJSON(base + "triage-kernel-backport.json").catch(function () { return null; }),
    ]).then(function (r) {
      var sum = r[0], triage = r[1], triageMd = r[2], kernelReport = r[3], kernelUpstreamReport = r[4],
          ubootReport = r[5], filteredCsv = r[6], backportReport = r[7];
      body.innerHTML = "";
      if (!triage && !kernelReport && !kernelUpstreamReport) {
        body.innerHTML = "<p class='muted'>No triage/noise-reduction data for this run.</p>";
        return;
      }
      if (sum && triage) {
        var raw = (sum.by_status || {}).Unpatched || 0;
        var after = triage.total_cves;
        var pct = raw > 0 ? Math.round((1 - after / raw) * 100) : 0;
        body.appendChild(h("h2", { text: "Unpatched CVEs: before vs. after noise reduction (all packages)" }));
        var cards = h("div", { class: "cards" });
        cards.appendChild(h("div", { class: "card" }, [
          h("div", { class: "n", text: String(raw) }), h("div", { text: "raw unpatched" }),
        ]));
        cards.appendChild(h("div", { class: "card" }, [
          h("div", { class: "n", text: String(after) }), h("div", { text: "after noise reduction" }),
        ]));
        cards.appendChild(h("div", { class: "card" }, [
          h("div", { class: "n", text: pct + "%" }), h("div", { text: "reduction" }),
        ]));
        cards.appendChild(h("div", { class: "card crit" }, [
          h("div", { class: "n", text: String(triage.kev_hits || 0) }), h("div", { text: "confirmed exploited (KEV)" }),
        ]));
        body.appendChild(cards);
      }
      if (triageMd) {
        body.appendChild(h("h2", { text: "KEV / EPSS priority (confirmed or likely exploited)" }));
        body.appendChild(h("p", { class: "muted", text:
          "The most urgent items in the remaining list -- start here." }));
        body.appendChild(h("div", { html: window.md.render(triageMd) }));
      }
      if (filteredCsv) {
        body.appendChild(h("h2", { text: "Everything left for human review (" + (triage ? triage.total_cves : "?") + ")" }));
        body.appendChild(h("p", { class: "muted", text:
          "The actual remaining list, all packages -- click a column to sort. This is what the \"after noise reduction\" count above refers to." }));
        body.appendChild(remainingTable(filteredCsv));
      }
      body.appendChild(h("h2", { text: "Kernel triage, by source (standalone breakdown)" }));
      body.appendChild(h("p", { class: "muted", text:
        "Not the combined result above -- each source's own bucket counts if it ran alone. The two sources catch different, overlapping cases, so neither one's \"needs human review\" count matches the real combined total." }));
      body.appendChild(bucketSummary("Local (git-ancestor check)", kernelReport, base + "triage-kernel.md"));
      body.appendChild(bucketSummary("Upstream (kernel.org CNA data + compiled-sources)", kernelUpstreamReport, base + "triage-kernel-upstream.md"));
      if (backportReport) {
        body.appendChild(h("h3", { text: "Real source verification (git apply --check)" }));
        body.appendChild(h("p", { class: "muted", text:
          "Not a heuristic -- for CVEs neither source above could resolve, checks the actual source against the real fix commit. \"needs human review\" here splits into confirmed-vulnerable and genuinely-unknown; click the card to see which is which." }));
        body.appendChild(bucketSummary("Backport check", backportReport, base + "triage-kernel-backport.md"));
      }
      if (ubootReport) body.appendChild(bucketSummary("U-Boot", ubootReport, base + "triage-uboot.md"));
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
  // RFC4180-aware: unlike splitCsv/csvTable above, handles quoted fields
  // that themselves contain newlines (real case: parse_cve.py's CVE
  // summary column spans multiple lines for most kernel CVEs -- a plain
  // line-split mangles those into broken rows).
  function parseCsvRecords(text) {
    var rows = [], row = [], cur = "", q = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
        else cur += c;
      } else if (c === '"') q = true;
      else if (c === ",") { row.push(cur); cur = ""; }
      else if (c === "\r") { /* skip */ }
      else if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
      else cur += c;
    }
    if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
    return rows;
  }
  // Risk order, not alphabetical -- plain string sort puts "critical"
  // before "high" before "low" before "medium", which reads as sorted
  // but isn't meaningful. Only kicks in for a column literally named
  // "severity"; every other column keeps the generic numeric/string sort.
  var SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

  // opts.filterable adds a live text filter box above the table
  // (substring match, case-insensitive, across all columns) -- for
  // tables with more rows than fit on screen (the remaining-CVE list,
  // per-bucket CVE lists). Omit opts for the old sort-only behavior.
  function tableFrom(head, rows, opts) {
    opts = opts || {};
    var sortState = { col: -1, dir: 1 };
    var filterText = "";
    var severityCol = head.indexOf("severity");
    var table = h("table");
    var countEl = null;

    function visibleRows() {
      var out = rows;
      if (filterText) {
        var needle = filterText.toLowerCase();
        out = out.filter(function (row) {
          return row.some(function (cell) { return (cell || "").toLowerCase().indexOf(needle) >= 0; });
        });
      }
      out = out.slice();
      if (sortState.col >= 0) {
        var col = sortState.col;
        out.sort(function (a, b) {
          var x = a[col] || "", y = b[col] || "";
          if (col === severityCol) {
            var rx = SEVERITY_RANK.hasOwnProperty(x.toLowerCase()) ? SEVERITY_RANK[x.toLowerCase()] : -1;
            var ry = SEVERITY_RANK.hasOwnProperty(y.toLowerCase()) ? SEVERITY_RANK[y.toLowerCase()] : -1;
            return (rx - ry) * sortState.dir;
          }
          var nx = parseFloat(x), ny = parseFloat(y);
          if (!isNaN(nx) && !isNaN(ny)) return (nx - ny) * sortState.dir;
          return x.localeCompare(y) * sortState.dir;
        });
      }
      return out;
    }

    function draw() {
      var body = visibleRows();
      if (countEl) countEl.textContent = body.length + " of " + rows.length + " rows";
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

    if (!opts.filterable) { draw(); return table; }

    var wrap = h("div", {});
    var input = h("input", { type: "text", placeholder: "Filter…" });
    input.oninput = function () { filterText = input.value; draw(); };
    countEl = h("span", { class: "muted" });
    wrap.appendChild(h("div", { class: "row", style: "margin-bottom:.5rem" }, [input, countEl]));
    wrap.appendChild(table);
    draw();
    return wrap;
  }

  window.addEventListener("hashchange", render);
  render();
})();
