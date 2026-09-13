(() => {
  const pipelineCopy = [
    {
      title: "Approve request",
      body: "Cybersecurity receives a model ID (example: google/gemma-4-E2B-it) and opens SafeWeights on the Windows VE that can only reach Hugging Face.",
    },
    {
      title: "Sign in",
      body: "Click Login with Hugging Face. SafeWeights shows the same device URL / code flow as hf auth login. Authorize in the browser — no token pasted into the main UI.",
    },
    {
      title: "Pull",
      body: "Enter the model ID and destination folder, then Pull Model. Files land locally for offline scanning.",
    },
    {
      title: "Scan",
      body: "Run Scan & Generate Report. SafeWeights reads formats byte-by-byte / header-by-header. It never executes pickle or torch.load during the check.",
    },
    {
      title: "Report",
      body: "A plain-language Markdown report opens with PASS or FAIL, next steps, and specialist details. Analysts hand off the model + report manually.",
    },
  ];

  const steps = document.querySelectorAll(".step");
  const detail = document.getElementById("pipeline-detail");

  function setStep(index) {
    steps.forEach((el, i) => el.classList.toggle("active", i === index));
    const item = pipelineCopy[index];
    detail.innerHTML = `<h3>${item.title}</h3><p>${item.body}</p>`;
  }

  steps.forEach((btn) => {
    btn.addEventListener("click", () => setStep(Number(btn.dataset.step)));
  });

  // Radar nodes
  const nodes = document.getElementById("nodes");
  if (nodes) {
    const labels = ["PT", "ST", "GGUF", "ONNX", "H5"];
    labels.forEach((label, i) => {
      const angle = (Math.PI * 2 * i) / labels.length - Math.PI / 2;
      const r = 118;
      const x = 210 + Math.cos(angle) * r;
      const y = 210 + Math.sin(angle) * r;
      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      c.setAttribute("cx", x);
      c.setAttribute("cy", y);
      c.setAttribute("r", "7");
      c.setAttribute("fill", "#22D3EE");
      c.setAttribute("opacity", "0.85");
      const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
      t.setAttribute("x", x);
      t.setAttribute("y", y + 22);
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("fill", "#8fa3bf");
      t.setAttribute("font-size", "10");
      t.setAttribute("font-family", "IBM Plex Mono, monospace");
      t.textContent = label;
      g.append(c, t);
      nodes.appendChild(g);
    });
  }

  // Animated counters
  const nums = document.querySelectorAll("[data-count]");
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const el = entry.target;
        const target = Number(el.dataset.count);
        const start = performance.now();
        const dur = 900;
        function tick(now) {
          const p = Math.min(1, (now - start) / dur);
          el.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 3))));
          if (p < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
        io.unobserve(el);
      });
    },
    { threshold: 0.4 }
  );
  nums.forEach((n) => io.observe(n));

  // Severity bars animate in
  const bars = document.getElementById("severity-bars");
  if (bars) {
    const barIo = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            bars.classList.add("in");
            barIo.disconnect();
          }
        });
      },
      { threshold: 0.35 }
    );
    barIo.observe(bars);
  }

  // Flip verdict chip occasionally for visual life
  const chip = document.getElementById("live-verdict");
  if (chip) {
    setInterval(() => {
      const fail = chip.classList.contains("fail");
      chip.classList.toggle("fail", !fail);
      chip.classList.toggle("pass", fail);
      chip.textContent = fail ? "PASS" : "FAIL";
    }, 5200);
  }

  // Point GitHub link at this Pages origin's repo when possible
  const repoLink = document.getElementById("repo-link");
  if (repoLink && location.hostname.endsWith("github.io")) {
    const user = location.hostname.split(".")[0];
    const parts = location.pathname.split("/").filter(Boolean);
    const repo = parts[0] || "SafeWeights";
    repoLink.href = `https://github.com/${user}/${repo}`;
  }
})();
