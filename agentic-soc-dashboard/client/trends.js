function makeBins({ start, end, binMs }) { // create time bins
  const bins = [];
  for (let t = start; t < end; t += binMs) {
    bins.push({ t, v: 0 });
  }
  return bins;
}

function binIndex(ts, start, binMs, nBins) { // get index of bin for timestamp ts
  const idx = Math.floor((ts - start) / binMs);
  return idx >= 0 && idx < nBins ? idx : -1;
}

function renderLineChart(svgId, points, opts = {}) { // render line chart in SVG
  const svg = d3.select(`#${svgId}`);
  const node = svg.node();

  const width = node?.clientWidth || 520;
  const height = 220;

  svg.attr("width", width).attr("height", height);
  svg.selectAll("*").remove();

  const padding = { left: 48, right: 16, top: 12, bottom: 28 };

  const x = d3
    .scaleTime()
    .domain([opts.start, opts.end])
    .range([padding.left, width - padding.right]);

  const maxY = Math.max(
    1,
    ...points.map((p) => p.v),
    opts.referenceLine ?? 0
  );

  const y = d3
    .scaleLinear()
    .domain([0, maxY])
    .nice()
    .range([height - padding.bottom, padding.top]);

  svg
    .append("g")
    .selectAll("line")
    .data(y.ticks(4))
    .enter()
    .append("line")
    .attr("class", "gridline")
    .attr("x1", padding.left)
    .attr("x2", width - padding.right)
    .attr("y1", (d) => y(d))
    .attr("y2", (d) => y(d));

  const fmt = d3.timeFormat("%H:%M:%S");

  svg
    .append("g")
    .attr("transform", `translate(0,${height - padding.bottom})`)
    .call(d3.axisBottom(x).ticks(5).tickFormat(fmt));

  svg
    .append("g")
    .attr("transform", `translate(${padding.left},0)`)
    .call(d3.axisLeft(y).ticks(4));

  if (opts.referenceLine !== undefined) {
    svg
      .append("line")
      .attr("x1", padding.left)
      .attr("x2", width - padding.right)
      .attr("y1", y(opts.referenceLine))
      .attr("y2", y(opts.referenceLine))
      .attr("stroke", "rgba(230,237,243,0.35)")
      .attr("stroke-dasharray", "4 4")
      .attr("stroke-width", 1);

    svg
      .append("text")
      .attr("x", width - padding.right - 4)
      .attr("y", y(opts.referenceLine) - 4)
      .attr("text-anchor", "end")
      .attr("font-size", 11)
      .attr("fill", "rgba(230,237,243,0.55)")
      .text("Baseline mean");
  }

  const line = d3
    .line()
    .x((d) => x(d.t))
    .y((d) => y(d.v))
    .curve(d3.curveMonotoneX);

  svg
    .append("path")
    .datum(points)
    .attr("fill", "none")
    .attr("stroke", "rgba(230,237,243,0.85)")
    .attr("stroke-width", 2)
    .attr("d", line);

  svg
    .selectAll("circle.pt")
    .data(points)
    .enter()
    .append("circle")
    .attr("class", "pt")
    .attr("cx", (d) => x(d.t))
    .attr("cy", (d) => y(d.v))
    .attr("r", 2.5)
    .attr("opacity", 0.8)
    .attr("fill", "rgba(230,237,243,0.85)");
}

function setThreatPressureLine({ threatNow, baseNow }) { // update threat pressure display
  const el = document.getElementById("threatPressure");
  if (!el) return;

  let ratio = "—";
  if (baseNow > 0) ratio = (threatNow / baseNow).toFixed(2) + "×";
  else if (threatNow > 0) ratio = "∞";

  el.textContent =
    `Threat pressure (latest full bin): ${ratio}` +
    ` · threat/bin ${threatNow} · baseline/bin ${baseNow}`;
}

export function renderTrends(events) {
  const now = Date.now();

  const BIN_MS = 20_000;
  const WINDOW_MS = 4 * 60_000;

  const start = now - WINDOW_MS;
  const end = now;

  const threatBins = makeBins({ start, end, binMs: BIN_MS });
  const baseBins = makeBins({ start, end, binMs: BIN_MS });

  for (const e of events) {
    if (!e.ts || e.ts < start) continue;

    if (e.meta?.attack) {
      const i = binIndex(e.ts, start, BIN_MS, threatBins.length);
      if (i !== -1) threatBins[i].v += 1;
    }

    if (e.meta?.home && e.type === "auth_success") {
      const i = binIndex(e.ts, start, BIN_MS, baseBins.length);
      if (i !== -1) baseBins[i].v += 1;
    }
  }

  const elapsed = (now - start) % BIN_MS;
  if (elapsed / BIN_MS < 0.5) {
    threatBins.pop();
    baseBins.pop();
  }

  const threatNow = threatBins.at(-1)?.v ?? 0;
  const baseNow = baseBins.at(-1)?.v ?? 0;
  setThreatPressureLine({ threatNow, baseNow });

  const baselineMean =
    baseBins.reduce((s, b) => s + b.v, 0) / Math.max(1, baseBins.length);

  renderLineChart("trendThreat", threatBins, {
    start,
    end,
    referenceLine: baselineMean,
  });

  renderLineChart("trendBaseline", baseBins, { start, end });
}
