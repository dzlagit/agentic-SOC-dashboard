// client/trends.js
// Two clean trend charts:
// - Threat Activity Trend: attack-tagged events per minute
// - Baseline Auth Activity: home-tagged auth_success per minute
// Adds:
// - Threat Pressure metric
// - Baseline mean reference line on Threat chart
// - Drops final partial bin (<50%) to avoid end-of-chart dip

function makeBins({ start, end, binMs }) {
  const n = Math.floor((end - start) / binMs) + 1;
  const bins = [];
  for (let i = 0; i < n; i++) {
    bins.push({ t: start + i * binMs, v: 0 });
  }
  return bins;
}

function binIndex(ts, start, binMs, nBins) {
  const idx = Math.floor((ts - start) / binMs);
  if (idx < 0 || idx >= nBins) return -1;
  return idx;
}

function renderLineChart(svgId, points, opts) {
  const svg = d3.select(`#${svgId}`);
  const node = svg.node();

  const width = node?.clientWidth ? node.clientWidth : 520;
  const height = 220;

  svg.attr("width", width).attr("height", height);
  svg.selectAll("*").remove();

  const padding = { left: 46, right: 14, top: 12, bottom: 26 };

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

  // gridlines
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

  // axes
  const fmt = d3.timeFormat("%H:%M");
  svg
    .append("g")
    .attr("transform", `translate(0,${height - padding.bottom})`)
    .call(d3.axisBottom(x).ticks(5).tickFormat(fmt));

  svg
    .append("g")
    .attr("transform", `translate(${padding.left},0)`)
    .call(d3.axisLeft(y).ticks(4));

  // reference line (baseline mean)
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

  // line
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

  // dots
  svg
    .selectAll("circle.pt")
    .data(points)
    .enter()
    .append("circle")
    .attr("class", "pt")
    .attr("cx", (d) => x(d.t))
    .attr("cy", (d) => y(d.v))
    .attr("r", 2.5)
    .attr("opacity", 0.75)
    .attr("fill", "rgba(230,237,243,0.85)");
}

function setThreatPressureLine({ threatNow, baseNow }) {
  const el = document.getElementById("threatPressure");
  if (!el) return;

  let ratioText = "—";
  if (baseNow > 0) ratioText = (threatNow / baseNow).toFixed(2) + "×";
  else if (threatNow > 0) ratioText = "∞";

  el.textContent =
    `Threat Pressure (latest full minute): ${ratioText}` +
    `  ·  threat/min ${threatNow}  ·  baseline/min ${baseNow}`;
}

export function renderTrends(events) {
  const now = Date.now();
  const minutes = 12;
  const start = now - minutes * 60_000;
  const end = now;
  const binMs = 60_000;

  const elapsedInLastBin = (now - start) % binMs;
  const lastBinCompleteness = elapsedInLastBin / binMs;

  const threatBins = makeBins({ start, end, binMs });
  const baseBins = makeBins({ start, end, binMs });

  for (const e of events) {
    if (!e.ts || e.ts < start) continue;

    if (e.meta?.attack) {
      const idx = binIndex(e.ts, start, binMs, threatBins.length);
      if (idx !== -1) threatBins[idx].v += 1;
    }

    if (e.meta?.home && e.type === "auth_success") {
      const idx = binIndex(e.ts, start, binMs, baseBins.length);
      if (idx !== -1) baseBins[idx].v += 1;
    }
  }

  if (lastBinCompleteness < 0.5) {
    threatBins.pop();
    baseBins.pop();
  }

  const threatNow = threatBins.at(-1)?.v ?? 0;
  const baseNow = baseBins.at(-1)?.v ?? 0;
  setThreatPressureLine({ threatNow, baseNow });

  const baselineMean =
    baseBins.reduce((sum, b) => sum + b.v, 0) / Math.max(1, baseBins.length);

  renderLineChart("trendThreat", threatBins, {
    start,
    end,
    referenceLine: baselineMean,
  });

  renderLineChart("trendBaseline", baseBins, { start, end });
}
