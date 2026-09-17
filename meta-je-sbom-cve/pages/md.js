/* Minimal markdown -> HTML. Handles what the *.md evidence files use:
   headings, bold, inline code, links, tables, blockquotes, hr, lists,
   paragraphs. No external deps. */
(function (global) {
  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function inline(s) {
    return esc(s)
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" rel="noopener">$1</a>')
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      // (^|[^\w]) / (?!\w) avoid matching inside snake_case identifiers,
      // e.g. "linux_ti_staging" -- only a standalone _like this_ counts.
      .replace(/(^|[^\w])_([^_\n]+)_(?!\w)/g, "$1<em>$2</em>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");
  }
  function render(md) {
    const lines = String(md).replace(/\r\n?/g, "\n").split("\n");
    const out = [];
    let i = 0, para = [], list = null;
    const flushPara = () => { if (para.length) { out.push("<p>" + inline(para.join(" ")) + "</p>"); para = []; } };
    const flushList = () => { if (list) { out.push("</" + list + ">"); list = null; } };
    while (i < lines.length) {
      const line = lines[i];
      if (/^\s*$/.test(line)) { flushPara(); flushList(); i++; continue; }
      let m;
      if ((m = line.match(/^(#{1,6})\s+(.*)$/))) {
        flushPara(); flushList();
        out.push("<h" + m[1].length + ">" + inline(m[2]) + "</h" + m[1].length + ">");
        i++; continue;
      }
      if (/^(-{3,}|\*{3,})\s*$/.test(line)) { flushPara(); flushList(); out.push("<hr>"); i++; continue; }
      if ((m = line.match(/^>\s?(.*)$/))) {
        flushPara(); flushList();
        out.push("<blockquote>" + inline(m[1]) + "</blockquote>"); i++; continue;
      }
      if (/^\s*\|(.+)\|\s*$/.test(line) && i + 1 < lines.length &&
          /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
        flushPara(); flushList();
        const cells = r => r.replace(/^\s*\|/, "").replace(/\|\s*$/, "").split("|").map(c => c.trim());
        const head = cells(line);
        i += 2;
        const rows = [];
        while (i < lines.length && /^\s*\|(.+)\|\s*$/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
        let t = "<table><thead><tr>" + head.map(h => "<th>" + inline(h) + "</th>").join("") + "</tr></thead><tbody>";
        for (const row of rows) t += "<tr>" + row.map(c => "<td>" + inline(c) + "</td>").join("") + "</tr>";
        out.push(t + "</tbody></table>");
        continue;
      }
      if ((m = line.match(/^(\s*)([-*])\s+(.*)$/))) {
        flushPara();
        if (list !== "ul") { flushList(); out.push("<ul>"); list = "ul"; }
        out.push("<li>" + inline(m[3]) + "</li>"); i++; continue;
      }
      if ((m = line.match(/^(\s*)\d+\.\s+(.*)$/))) {
        flushPara();
        if (list !== "ol") { flushList(); out.push("<ol>"); list = "ol"; }
        out.push("<li>" + inline(m[2]) + "</li>"); i++; continue;
      }
      para.push(line); i++;
    }
    flushPara(); flushList();
    return out.join("\n");
  }
  global.md = { render: render };
})(window);
