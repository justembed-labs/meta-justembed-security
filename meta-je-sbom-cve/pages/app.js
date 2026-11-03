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
      if (route.tab === "triage") return renderTriage(base, run, body);
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
          // Real-source-verification entries (kernel_backport_check.py)
          // carry a confirmed true/false flag -- "confirmed vulnerable"
          // vs. "genuinely unknown" is the single most decision-relevant
          // split in this whole table, buried in free text otherwise
          // (a reader would have to read every row to spot it).
          var hasConfirmedFlag = entries.some(function (e) { return typeof e.confirmed === "boolean"; });
          if (hasConfirmedFlag) {
            var nConfirmed = entries.filter(function (e) { return e.confirmed; }).length;
            if (nConfirmed) {
              expanded.appendChild(h("p", {}, [
                h("strong", { text: nConfirmed + " confirmed still vulnerable" }),
                document.createTextNode(" -- real fix, not a maybe. Sort the status column or filter \"confirmed\" below."),
              ]));
            }
            // Status as its own sortable/filterable column, not a class
            // added after the fact -- tableFrom's own draw() rebuilds the
            // tbody from these row arrays on every sort/filter, so content
            // baked into the cell survives; a DOM class added afterward
            // would not.
            var rows = entries.map(function (e) {
              return [e.cve, e.confirmed ? "⬤ confirmed vulnerable" : "unknown", bucketEntryDetail(e)];
            });
            expanded.appendChild(tableFrom(["cve", "status", "why"], rows, { filterable: true }));
          } else {
            var plainRows = entries.map(function (e) { return [e.cve, bucketEntryDetail(e)]; });
            expanded.appendChild(tableFrom(["cve", "why"], plainRows, { filterable: true }));
          }
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

  // Ordered as the real backend actually runs them -- each stage's own
  // total_scanned is the previous stage's needs_human_review count by
  // construction (upstream_triage.py scans everything; backport_check
  // and the CIP wrapper are only ever invoked on the prior stage's
  // leftover), so chaining their real counts IS the real pipeline, not
  // a separate recomputation of it. kernel_cve_triage.py (ours) is
  // deliberately not a stage here -- its own verdicts are superseded by
  // the upstream wrapper; it still runs, feeding backport_check's
  // candidate commits, but has nothing of its own worth showing.
  var PIPELINE_STAGES = [
    { key: "upstream", title: "Upstream compiled-sources filter",
      file: "triage-kernel-upstream.json", mdFile: "triage-kernel-upstream.md",
      how: "improve_kernel_cve_report.py (OE-core) -- real SPDX compiled-file list vs. each CVE's affected files, real kernel.org CNA data.",
      explain: "For each CVE, checks whether the file it affects is actually in this build's real compiled-file list (from SPDX) and whether the real fix commit is a confirmed git ancestor of this kernel tree. Both are facts about this exact build, not heuristics." },
    { key: "backport", title: "Byte-level source verification",
      file: "triage-kernel-backport.json", mdFile: "triage-kernel-backport.md",
      how: "kernel_backport_check.py -- real git apply --check (forward/reverse) of the actual fix commit against this tree.",
      explain: "Only runs on CVEs the stage above couldn't resolve. For each, tries applying the real fix commit forward (still vulnerable if it applies) and in reverse (already patched if that applies). Neither applying means the source has genuinely diverged -- flagged unknown, not guessed." },
    { key: "cip", title: "CIP kmax Kconfig analysis",
      file: "triage-kernel-cip.json", mdFile: "triage-kernel-cip.md",
      how: "CIP kernel-cve-triage -- exhaustive SAT-solver reachability over the whole Kconfig/Makefile graph, run only on what's left above.",
      explain: "Builds a precise yes/no formula for \"is this file compiled in\" from every Kconfig/Makefile rule combined (not just a one-line regex match), evaluated at both the commit that introduced the bug and the one that fixed it." },
  ];

  function pipelineResolvedCount(report) {
    if (!report) return 0;
    return (report.config_inapplicable_candidates || []).length +
      (report.fixed_version_candidates || []).length +
      (report.cpe_mismatch_candidates || []).length;
  }

  // A later stage (backport_check, CIP) only ever examines a SUBSET of the
  // prior stage's leftover -- e.g. backport_check's own total_scanned is
  // 436, not the 725 upstream actually left in review, because only 436
  // of those 725 had an identifiable candidate commit to byte-check. Its
  // own scanned-resolved math silently drops the other 289. Carry the
  // true remaining count forward instead: first stage sets it from its
  // own total_scanned, every later stage only ever subtracts what IT
  // resolved from that running total, never recomputes from its own
  // (smaller, subset) total_scanned.
  function kernelPipelineCarry(reports) {
    var out = [];
    var carry = null;
    PIPELINE_STAGES.forEach(function (stage) {
      var report = reports[stage.key];
      if (!report) { out.push({ stage: stage, report: null, remaining: carry }); return; }
      var resolved = pipelineResolvedCount(report);
      if (carry == null) carry = report.total_scanned || 0;
      carry = Math.max(0, carry - resolved);
      out.push({ stage: stage, report: report, remaining: carry, resolved: resolved,
        scanned: report.total_scanned || 0 });
    });
    return out;
  }

  function arrow() {
    return h("div", { class: "muted", style: "display:flex;align-items:center;padding:0 .5rem;font-size:1.2rem", text: "→" });
  }

  // Shows every defined stage, not just the ones this run happens to have
  // data for -- a missing stage renders disabled with why, instead of
  // silently vanishing, so the viewer sees the whole intended pipeline
  // even on a run/board that hasn't wired every stage in yet. This is
  // the KERNEL-only sub-pipeline -- nested inside renderOverview's
  // "kernel CVE triage" step, not a top-level view on its own: the real
  // top-level overview is the whole image (renderOverview below).
  function renderKernelPipeline(base, reports, prevReports) {
    var wrap = h("div", {});
    var strip = h("div", { class: "row", style: "align-items:stretch;flex-wrap:wrap;gap:0" });
    var detail = h("div", {});
    var present = PIPELINE_STAGES.filter(function (s) { return reports[s.key]; });
    var firstPresentKey = present.length ? present[0].key : null;
    var lastCell = null;

    if (!present.length) {
      wrap.appendChild(h("p", { class: "muted", text: "No kernel triage data for this run." }));
      return wrap;
    }

    function showStage(stage, report) {
      detail.innerHTML = "";
      detail.appendChild(h("p", { class: "muted", text: stage.how }));
      detail.appendChild(h("p", {}, [h("strong", { text: "How it works: " }), document.createTextNode(stage.explain)]));
      detail.appendChild(bucketSummary(stage.title + " -- full breakdown", report, base + stage.mdFile));
    }

    var carried = kernelPipelineCarry(reports);
    var prevCarried = prevReports ? kernelPipelineCarry(prevReports) : null;

    carried.forEach(function (c, i) {
      var stage = c.stage, report = c.report;

      // The true entry point is whichever stage actually scans everything
      // (upstream, by design) -- if it's missing for this run, label the
      // first stage we DO have honestly instead of mislabeling its input
      // as "raw", since that count is really someone else's leftover.
      if (stage.key === firstPresentKey && report) {
        strip.appendChild(h("div", { class: "card", style: "flex:0 0 auto;min-width:140px" }, [
          h("div", { class: "n", text: String(c.scanned) }),
          h("div", { text: stage.key === "upstream" ? "raw kernel CVEs" : "input to this stage" }),
        ]));
        strip.appendChild(arrow());
      }

      if (!report) {
        strip.appendChild(h("div", {
          class: "card", style: "flex:1 1 160px;min-width:160px;opacity:.5",
          title: "Not run for this board/run yet.",
        }, [
          h("div", { class: "n", text: "—" }),
          h("div", { text: stage.title }),
        ]));
        if (i < carried.length - 1) strip.appendChild(arrow());
        return;
      }

      // Note: a stage's OWN resolved-count still shows in its detail
      // table correctly either way -- only the *running remaining* count
      // (shown on the card) needs the carry, not what each stage itself
      // found.
      var remaining = c.remaining;
      var prevRemaining = prevCarried ? prevCarried[i].remaining : null;

      var delta = "";
      if (prevRemaining != null) {
        var d = remaining - prevRemaining;
        delta = (d > 0 ? "+" : "") + d + " vs last run";
      }
      var cell = h("div", {
        class: "card", style: "flex:1 1 160px;min-width:160px;cursor:pointer",
      }, [
        h("div", { class: "n", text: String(remaining) }),
        h("div", { text: stage.title }),
        delta ? h("div", { class: "muted", text: delta, style: "font-size:.75rem" }) : null,
      ]);
      cell.title = "Click for the full breakdown and evidence";
      cell.onclick = function () {
        Array.prototype.forEach.call(strip.children, function (c) { c.classList && c.classList.remove("active"); });
        cell.classList.add("active");
        showStage(stage, report);
      };
      strip.appendChild(cell);
      lastCell = cell;
      if (i < carried.length - 1) strip.appendChild(arrow());
    });

    wrap.appendChild(strip);
    wrap.appendChild(detail);
    // Open the last real (most informative) stage by default -- a direct
    // reference, not DOM-child-index math (an arrow sits between cells).
    if (lastCell) lastCell.click();
    return wrap;
  }

  // The carried (not per-stage) remaining count from whichever stage ran
  // last -- same correct carry logic as the detail view, so the overview's
  // headline number and the expanded breakdown never disagree with each
  // other. E.g. if CIP hasn't run for this board, backport_check's carried
  // remainder is the real, honest number, not a guess at what CIP would
  // have found.
  function lastKernelRemaining(reports) {
    var carried = kernelPipelineCarry(reports);
    for (var i = carried.length - 1; i >= 0; i--) {
      if (carried[i].report) return carried[i].remaining;
    }
    return null;
  }

  // The real top-level view: the whole image's funnel, start to finish.
  // Kernel triage is ONE step in this, shown as a single card whose count
  // is the kernel sub-pipeline's own final remaining count -- clicking it
  // expands renderKernelPipeline (the upstream/backport/CIP breakdown)
  // in place, rather than showing kernel and "everything else" as two
  // disconnected, separately-scoped sections.
  function renderOverview(base, sum, triage, kernelReports, prevKernelReports) {
    var wrap = h("div", {});
    var strip = h("div", { class: "row", style: "align-items:stretch;flex-wrap:wrap;gap:0" });
    var detail = h("div", {});

    var raw = sum ? (sum.by_status || {}).Unpatched || 0 : null;
    var kernelRemaining = lastKernelRemaining(kernelReports);
    var prevKernelRemaining = prevKernelReports ? lastKernelRemaining(prevKernelReports) : null;
    var combined = triage ? triage.total_cves : null;

    if (raw != null) {
      strip.appendChild(h("div", { class: "card", style: "flex:0 0 auto;min-width:140px" }, [
        h("div", { class: "n", text: String(raw) }), h("div", { text: "raw unpatched, all packages" }),
      ]));
      strip.appendChild(arrow());
    }

    if (kernelRemaining != null) {
      var kDelta = "";
      if (prevKernelRemaining != null) {
        var kd = kernelRemaining - prevKernelRemaining;
        kDelta = (kd > 0 ? "+" : "") + kd + " vs last run";
      }
      var kernelCell = h("div", { class: "card", style: "flex:1 1 180px;min-width:180px;cursor:pointer" }, [
        h("div", { class: "n", text: String(kernelRemaining) }),
        h("div", { text: "kernel CVE triage" }),
        kDelta ? h("div", { class: "muted", text: kDelta, style: "font-size:.75rem" }) : null,
      ]);
      kernelCell.title = "Click to expand the kernel sub-pipeline";
      kernelCell.onclick = function () {
        detail.innerHTML = "";
        detail.appendChild(h("p", { class: "muted", text:
          "Kernel package only -- the rest of this build's packages don't go through these checks, they " +
          "combine with whatever's left here directly into the total below." }));
        detail.appendChild(renderKernelPipeline(base, kernelReports, prevKernelReports));
      };
      strip.appendChild(kernelCell);
      strip.appendChild(arrow());
    }

    if (combined != null) {
      strip.appendChild(h("div", { class: "card high", style: "flex:0 0 auto;min-width:160px" }, [
        h("div", { class: "n", text: String(combined) }), h("div", { text: "decision-ready, all packages" }),
      ]));
    }

    wrap.appendChild(strip);
    wrap.appendChild(detail);
    if (triage) {
      wrap.appendChild(h("p", { class: "muted", style: "margin-top:.5rem", text:
        (triage.kev_hits || 0) + " of those confirmed actively exploited (KEV) -- see \"Start here\" below." }));
    }
    return wrap;
  }

  function renderTriage(base, run, body) {
    body.textContent = "loading…";
    var prevBase = run.previous && run.previous !== "null" ? base.replace(/[^/]+\/$/, "") + run.previous + "/" : null;
    Promise.all([
      getJSON(base + "parsed/cve_summary.json").catch(function () { return null; }),
      getJSON(base + "triage.json").catch(function () { return null; }),
      getText(base + "triage.md"),
      getJSON(base + "triage-kernel-upstream.json").catch(function () { return null; }),
      getJSON(base + "triage-kernel-backport.json").catch(function () { return null; }),
      getJSON(base + "triage-kernel-cip.json").catch(function () { return null; }),
      getJSON(base + "triage-uboot.json").catch(function () { return null; }),
      getText(base + "triage.filtered.csv"),
      prevBase ? getJSON(prevBase + "triage-kernel-upstream.json").catch(function () { return null; }) : Promise.resolve(null),
      prevBase ? getJSON(prevBase + "triage-kernel-backport.json").catch(function () { return null; }) : Promise.resolve(null),
      prevBase ? getJSON(prevBase + "triage-kernel-cip.json").catch(function () { return null; }) : Promise.resolve(null),
    ]).then(function (r) {
      var sum = r[0], triage = r[1], triageMd = r[2], upstream = r[3], backport = r[4], cip = r[5],
          ubootReport = r[6], filteredCsv = r[7], prevUpstream = r[8], prevBackport = r[9], prevCip = r[10];
      body.innerHTML = "";
      if (!triage && !upstream) {
        body.innerHTML = "<p class='muted'>No triage/noise-reduction data for this run.</p>";
        return;
      }

      body.appendChild(h("h2", { text: "Evidence pipeline -- whole image" }));
      body.appendChild(h("p", { class: "muted", text:
        "Every unpatched CVE in this build, start to finish -- click a step for its explanation and full evidence." }));

      // Rendering can throw on real-but-unexpected data shapes (a
      // mismatched field, an older run missing a key a newer one
      // assumes) -- an uncaught throw here previously froze the page
      // silently right after this point, no error shown anywhere
      // (confirmed real: reported 2026-10-06, no console/page error at
      // all, just nothing rendering past this line). Surface it
      // visibly instead of failing silent.
      try {
        body.appendChild(renderOverview(base, sum, triage,
          { upstream: upstream, backport: backport, cip: cip },
          { upstream: prevUpstream, backport: prevBackport, cip: prevCip }));
      } catch (e) {
        body.appendChild(h("p", { style: "color:var(--crit)", text:
          "Pipeline overview failed to render: " + e.message + " (see browser console for the full stack)." }));
        if (window.console) console.error(e);
      }

      if (triageMd) {
        body.appendChild(h("h2", { text: "Start here -- KEV / EPSS priority" }));
        body.appendChild(h("p", { class: "muted", text:
          "Confirmed or likely exploited, cross-referenced against the decision-ready list above." }));
        body.appendChild(h("div", { html: window.md.render(triageMd) }));
      }
      if (filteredCsv) {
        body.appendChild(h("h2", { text: "Everything left for human review (" + (triage ? triage.total_cves : "?") + ")" }));
        body.appendChild(h("p", { class: "muted", text:
          "The full remaining list, all packages -- click a column to sort." }));
        body.appendChild(remainingTable(filteredCsv));
      }
      if (ubootReport) {
        body.appendChild(h("h2", { text: "U-Boot" }));
        body.appendChild(bucketSummary("U-Boot triage", ubootReport, base + "triage-uboot.md"));
      }
    }).catch(function (e) {
      body.appendChild(h("p", { style: "color:var(--crit)", text: "Failed to load triage data: " + e.message }));
      if (window.console) console.error(e);
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
