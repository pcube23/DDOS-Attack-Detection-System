document.getElementById('year') && (document.getElementById('year').textContent = new Date().getFullYear());

// PWA
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-worker.js').catch(()=>{});
  });
}

// Chart.js global theme to match neon/cyber palette
if (window.Chart){
  Chart.defaults.color = '#9bb0d3';
  Chart.defaults.borderColor = 'rgba(99,121,180,0.3)';
  Chart.defaults.plugins.legend.labels.color = '#e6eefc';
}

// Theme toggle
(function(){
  const root = document.documentElement;
  const btn = document.getElementById('themeToggle');
  const key = 'ddosguard-theme';
  const saved = localStorage.getItem(key);
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  function apply(theme){
    if(theme === 'light'){ root.setAttribute('data-theme','light'); }
    else { root.removeAttribute('data-theme'); }
    localStorage.setItem(key, theme);
  }
  apply(saved || (prefersLight ? 'light' : 'dark'));
  if(btn){ btn.onclick = () => { const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light'; apply(next); }; }
})();

// Hero particles (simple, lightweight)
window.HomePage = function(){
  const canvas = document.getElementById('particles');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  function resize(){ canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight; }
  resize();
  window.addEventListener('resize', resize);
  const COUNT = Math.max(40, Math.floor(canvas.clientWidth/25));
  const particles = Array.from({length: COUNT}).map(()=>({
    x: Math.random()*canvas.width,
    y: Math.random()*canvas.height,
    r: Math.random()*2+0.8,
    vx: (Math.random()-0.5)*0.3,
    vy: (Math.random()-0.5)*0.3,
    c1: 'rgba(34,211,238,0.6)', c2: 'rgba(59,130,246,0.6)'
  }));
  function tick(){
    ctx.clearRect(0,0,canvas.width,canvas.height);
    for(const p of particles){
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0||p.x>canvas.width) p.vx*=-1;
      if(p.y<0||p.y>canvas.height) p.vy*=-1;
      const g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r*6);
      g.addColorStop(0, p.c1); g.addColorStop(1, 'transparent');
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fill();
    }
    // link lines
    for(let i=0;i<particles.length;i++){
      for(let j=i+1;j<particles.length;j++){
        const a=particles[i], b=particles[j];
        const dx=a.x-b.x, dy=a.y-b.y; const d=Math.hypot(dx,dy);
        if(d<90){ ctx.strokeStyle = 'rgba(34,211,238,'+(0.25*(1-d/90))+')'; ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); }
      }
    }
    requestAnimationFrame(tick);
  }
  tick();
}

window.UploadPage = function(){
  // Prevent multiple initializations on the same page
  if (window.UploadPage.initialized) {
    console.log('UploadPage already initialized, skipping...');
    return;
  }
  window.UploadPage.initialized = true;
  
  // Reset flag when page unloads (for navigation)
  window.addEventListener('beforeunload', () => {
    window.UploadPage.initialized = false;
  });

  const drop = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const list = document.getElementById('fileList');
  const progress = document.getElementById('progress');
  const bar = document.getElementById('bar');
  const analyze = document.getElementById('analyzeBtn');
  const reset = document.getElementById('resetBtn');
  const summary = document.getElementById('summary');
  const alertsBox = document.getElementById('alerts');
  const error = document.getElementById('error');
  const gotoDashboard = document.getElementById('gotoDashboard');

  if (!drop || !fileInput) return; // Safety check

  const files = [];

  const renderList = () => {
    if (!list) return;
    list.innerHTML = files.map(f => `<div>${f.name} - ${(f.size/1024).toFixed(1)} KB</div>`).join('');
  }

  // Helper to check if file already exists
  const fileExists = (file) => {
    return files.some(f => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified);
  };

  // Helper to add files without duplicates
  const addFiles = (fileList) => {
    let added = false;
    Array.from(fileList).forEach(f => {
      if (!fileExists(f)) {
        files.push(f);
        added = true;
      }
    });
    if (added) {
      renderList();
      // Clear input to allow selecting same files again if needed
      if (fileInput) fileInput.value = '';
    }
  };

  // Drag and drop handlers
  const preventDefault = (e) => { 
    e.preventDefault(); 
    e.stopPropagation(); 
  };

  const handleDrop = (e) => {
    preventDefault(e);
    if (e.dataTransfer && e.dataTransfer.files) {
      addFiles(e.dataTransfer.files);
    }
  };

  const handleClick = (e) => {
    // Only trigger file input if clicking on dropzone background, not on buttons/inputs inside
    const target = e.target;
    const isButton = target.tagName === 'BUTTON' || target.closest('button');
    const isInput = target.tagName === 'INPUT' || target.closest('input');
    const isLink = target.tagName === 'A' || target.closest('a');
    
    // Only open file chooser if clicking on dropzone text/background, not interactive elements
    if (!isButton && !isInput && !isLink && (target === drop || target.closest('.dropzone') === drop)) {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(e.target.files);
    }
  };

  // Attach event listeners once
  ['dragenter', 'dragover', 'dragleave'].forEach(ev => {
    drop.addEventListener(ev, preventDefault, false);
  });
  drop.addEventListener('drop', handleDrop, false);
  drop.addEventListener('click', handleClick, false);
  fileInput.addEventListener('change', handleFileChange, false);

  // Button handlers
  if (reset) {
    reset.onclick = () => { 
      files.length = 0; 
      if (list) list.innerHTML = ''; 
      if (bar) bar.style.width = '0%'; 
      if (summary) summary.innerHTML = ''; 
      if (alertsBox) alertsBox.innerHTML = ''; 
      if (error) error.textContent = ''; 
      if (gotoDashboard) gotoDashboard.style.display = 'none';
      if (fileInput) fileInput.value = '';
    };
  }

  if (analyze) {
    analyze.onclick = async () => {
      if (!files.length) { 
        if (error) error.textContent = 'Please add files first.'; 
        return; 
      }
      if (error) error.textContent = '';
      const fd = new FormData();
      files.forEach(f => fd.append('files', f));
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload');
      xhr.upload.onprogress = (e) => {
        if(e.lengthComputable && bar){ bar.style.width = (e.loaded/e.total*100).toFixed(0)+'%'; }
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300){
          const res = JSON.parse(xhr.responseText);
          if (summary) {
            summary.innerHTML = `
              <div class="card">Total: ${res.summary?.total_packets ?? '-'} </div>
              <div class="card">Duration: ${(res.summary?.duration_seconds || 0).toFixed(2)}s</div>
              <div class="card">ICMP/TCP/UDP: ${res.summary?.protocol_ratio?.ICMP ?? 0}/${res.summary?.protocol_ratio?.TCP ?? 0}/${res.summary?.protocol_ratio?.UDP ?? 0}</div>
              <div class="card">Unique Src/Dst: ${res.summary?.unique_sources ?? 0}/${res.summary?.unique_dests ?? 0}</div>`;
          }
          if (alertsBox) {
            alertsBox.innerHTML = (res.alerts||[]).map(a => `<div class="alert ${a.severity}"> ${a.message} </div>`).join('') || '<div class="muted">No alerts.</div>';
          }
          const uploadedFilesEl = document.getElementById('uploadedFiles');
          if (uploadedFilesEl) {
            uploadedFilesEl.textContent = 'Files: ' + (res.files||[]).join(', ');
          }
          if (gotoDashboard) gotoDashboard.style.display = '';
        } else {
          if (error) error.textContent = 'Upload failed.';
        }
      };
      xhr.onerror = () => { 
        if (error) error.textContent = 'Upload error.'; 
      };
      xhr.send(fd);
    };
  }
}

window.DashboardPage = async function(){
  const kTotal = document.getElementById('kpi-total');
  const kDur = document.getElementById('kpi-duration');
  const kRatio = document.getElementById('kpi-ratio');
  const kUniq = document.getElementById('kpi-unique');
  const alertList = document.getElementById('alertList');
  const dashError = document.getElementById('dashError');

  // Helper to clear error message
  function clearError() {
    if (dashError) {
      dashError.textContent = '';
      dashError.style.display = 'none';
    }
  }

  // Helper to show error only when truly no data exists
  function showErrorIfNeeded() {
    // Check if we have any visible data
    const hasKPIData = kTotal && !kTotal.textContent.includes('-');
    const hasCharts = document.getElementById('trafficChart') && document.getElementById('trafficChart').getContext('2d');
    const hasAlerts = alertList && alertList.children.length > 0;
    
    // Only show error if we have absolutely no data
    if (!hasKPIData && !hasCharts && !hasAlerts && dashError) {
      dashError.textContent = 'No analysis available. Please upload files first.';
      dashError.style.display = 'block';
    } else {
      clearError();
    }
  }

  async function fetchJson(url){ 
    const r = await fetch(url); 
    if(!r.ok) return null; // Return null instead of throwing
    return r.json(); 
  }

  // Clear error initially
  clearError();

  try{
    // Fetch all data, allowing some to fail
    const [sum, traffic, topS, topD, alerts] = await Promise.all([
      fetchJson('/api/overview').catch(() => null),
      fetchJson('/api/traffic').catch(() => null),
      fetchJson('/api/top-sources').catch(() => null),
      fetchJson('/api/top-dests').catch(() => null),
      fetchJson('/api/alerts').catch(() => null)
    ]);

    // Only proceed if we have at least summary data
    if (!sum || !sum.total_packets) {
      showErrorIfNeeded();
      return;
    }

    // Clear error since we have data
    clearError();
    // Update KPIs
    if (kTotal) kTotal.textContent = `Total Packets: ${sum.total_packets || 0}`;
    if (kDur) kDur.textContent = `Duration: ${(sum.duration_seconds || 0).toFixed(2)}s`;
    if (kRatio) kRatio.textContent = `ICMP/TCP/UDP: ${sum.protocol_ratio?.ICMP || 0}/${sum.protocol_ratio?.TCP || 0}/${sum.protocol_ratio?.UDP || 0}`;
    if (kUniq) kUniq.textContent = `Active Connections: ${(sum.unique_sources || 0) + (sum.unique_dests || 0)}`;

    // Traffic chart - only if we have traffic data
    if (traffic && traffic.length > 0) {
      const tc = document.getElementById('trafficChart');
      if (tc) {
        const ctx = tc.getContext('2d');
        const baseLabels = traffic.map(x=>x.time);
        window.trafficChart = new Chart(ctx, { type:'line', data:{
          labels: baseLabels,
          datasets:[
            {label:'ICMP', data: traffic.map(x=>x.ICMP || 0), borderColor:'#60a5fa'},
            {label:'TCP', data: traffic.map(x=>x.TCP || 0), borderColor:'#34d399'},
            {label:'UDP', data: traffic.map(x=>x.UDP || 0), borderColor:'#fca5a5'}
          ]
        }, options:{responsive:true, plugins:{legend:{labels:{color:'#e6eefc'}}}, scales:{x:{ticks:{color:'#9bb0d3'}}, y:{ticks:{color:'#9bb0d3'}}}}});
      }
    }

    // Top Sources chart - only if we have data
    if (topS && topS.length > 0) {
      const topSourcesEl = document.getElementById('topSources');
      if (topSourcesEl) {
        const barOptions = {type:'bar', options:{responsive:true, plugins:{legend:{display:false}}, scales:{x:{ticks:{color:'#9bb0d3'}}, y:{ticks:{color:'#9bb0d3'}}}}};
        new Chart(topSourcesEl.getContext('2d'), {
          ...barOptions,
          data:{ labels: topS.map(x=>x.ip), datasets:[{ label:'Packets', backgroundColor:'#60a5fa', data: topS.map(x=>x.count) }] }
        });
      }
    }

    // Top Destinations chart - only if we have data
    if (topD && topD.length > 0) {
      const topDestsEl = document.getElementById('topDests');
      if (topDestsEl) {
        const barOptions = {type:'bar', options:{responsive:true, plugins:{legend:{display:false}}, scales:{x:{ticks:{color:'#9bb0d3'}}, y:{ticks:{color:'#9bb0d3'}}}}};
        new Chart(topDestsEl.getContext('2d'), {
          ...barOptions,
          data:{ labels: topD.map(x=>x.ip), datasets:[{ label:'Packets', backgroundColor:'#34d399', data: topD.map(x=>x.count) }] }
        });
      }
    }

    // Alerts - always show, even if empty
    if (alertList) {
      const initialAlerts = (alerts?.alerts || alerts || []);
      alertList.innerHTML = initialAlerts.length > 0 
        ? initialAlerts.map(a => `<li>[${a.severity}] ${a.message}</li>`).join('')
        : '<li>No alerts.</li>';
    }

    // Download handlers - only show error temporarily, don't persist it
    const downloadPdfBtn = document.getElementById('downloadPdf');
    if (downloadPdfBtn) {
      downloadPdfBtn.onclick = async ()=>{
        const res = await fetch('/api/report/pdf', {method:'POST'});
        if(!res.ok){ 
          if (dashError) {
            dashError.textContent='Upload data first.';
            dashError.style.display = 'block';
            setTimeout(clearError, 3000); // Auto-hide after 3 seconds
          }
          return; 
        }
        clearError();
        const blob = await res.blob(); 
        const url = URL.createObjectURL(blob); 
        const a=document.createElement('a'); 
        a.href=url; 
        a.download='ddos_report.pdf'; 
        a.click(); 
        URL.revokeObjectURL(url);
      };
    }

    const downloadCsvBtn = document.getElementById('downloadCsv');
    if (downloadCsvBtn) {
      downloadCsvBtn.onclick = async ()=>{
        const res = await fetch('/api/report/csv', {method:'POST'});
        if(!res.ok){ 
          if (dashError) {
            dashError.textContent='Upload data first.';
            dashError.style.display = 'block';
            setTimeout(clearError, 3000);
          }
          return; 
        }
        clearError();
        const blob = await res.blob(); 
        const url = URL.createObjectURL(blob); 
        const a=document.createElement('a'); 
        a.href=url; 
        a.download='packets.csv'; 
        a.click(); 
        URL.revokeObjectURL(url);
      };
    }

    // Custom PDF from Dashboard
    const btnPdfCustom = document.getElementById('downloadPdfCustom');
    if(btnPdfCustom){
      btnPdfCustom.onclick = async ()=>{
        const body = { include_summary: true, include_alerts: true, include_counts: true, include_meta: true };
        const res = await fetch('/api/report/pdf', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
        if(!res.ok){ 
          if (dashError) {
            dashError.textContent='Upload data first.';
            dashError.style.display = 'block';
            setTimeout(clearError, 3000);
          }
          return; 
        }
        clearError();
        const blob = await res.blob(); 
        const url = URL.createObjectURL(blob); 
        const a=document.createElement('a'); 
        a.href=url; 
        a.download='ddos_report_custom.pdf'; 
        a.click(); 
        URL.revokeObjectURL(url);
      };
    }

    const btnXlsx = document.getElementById('downloadXlsx');
    if(btnXlsx){
      btnXlsx.onclick = async ()=>{
        const res = await fetch('/api/report/xlsx', {method:'POST'});
        if(!res.ok){ 
          if (dashError) {
            dashError.textContent='Upload data first.';
            dashError.style.display = 'block';
            setTimeout(clearError, 3000);
          }
          return; 
        }
        clearError();
        const blob = await res.blob(); 
        const url = URL.createObjectURL(blob); 
        const a=document.createElement('a'); 
        a.href=url; 
        a.download='packets.xlsx'; 
        a.click(); 
        URL.revokeObjectURL(url);
      };
    }

    // Live Mode simulation: fake packet logs, chart updates, dynamic alerts
    const liveBtn = document.getElementById('toggleLive');
    const liveLog = document.getElementById('liveLog');
    let liveOn = false; let liveTimer; let alertTimer;
    function rand(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
    function sample(arr){ return arr[Math.floor(Math.random()*arr.length)]; }
    function addLog(){
      if(!liveOn) return;
      const protos = ['ICMP','TCP','UDP']; const p = sample(protos);
      const src = `192.168.${rand(0,254)}.${rand(1,254)}`;
      const dst = `10.0.${rand(0,254)}.${rand(1,254)}`;
      const len = rand(60, 1400);
      const t = new Date().toISOString();
      const line = document.createElement('div');
      line.className = 'line';
      line.innerHTML = `<span class="t">${t}</span> <span class="proto">${p}</span> <span class="src">${src}</span> → <span class="dst">${dst}</span> <span class="len">len=${len}</span>`;
      liveLog && liveLog.appendChild(line);
      if(liveLog && liveLog.children.length>300){ liveLog.removeChild(liveLog.firstChild); }
      liveLog && (liveLog.scrollTop = liveLog.scrollHeight);
      // push to chart - only if chart exists
      const trafficChartEl = document.getElementById('trafficChart');
      if (trafficChartEl && window.trafficChart) {
        const trafficChart = window.trafficChart;
        const lastLabel = trafficChart.data.labels[trafficChart.data.labels.length-1] || new Date().toISOString();
        const nextLabel = new Date().toISOString();
        trafficChart.data.labels.push(nextLabel);
        const idx = { ICMP:0, TCP:1, UDP:2 }[p];
        for(let i=0;i<trafficChart.data.datasets.length;i++){
          const last = trafficChart.data.datasets[i].data[trafficChart.data.datasets[i].data.length-1] || 0;
          trafficChart.data.datasets[i].data.push(i===idx ? last + rand(1,5) : Math.max(0, last - rand(0,2)));
        }
        if(trafficChart.data.labels.length>80){
          trafficChart.data.labels.shift();
          trafficChart.data.datasets.forEach(d=>d.data.shift());
        }
        trafficChart.update('none');
      }
    }
    function addRandomAlert(){
      if(!liveOn) return;
      if(Math.random()<0.35){
        const alerts = [
          {sev:'high', msg:`Potential SYN flood: ${rand(500,4000)} SYNs in ${rand(10,60)}s`},
          {sev:'medium', msg:`Elevated UDP rate from ${`192.168.${rand(0,254)}.${rand(1,254)}`}`},
          {sev:'low', msg:`Spike in ICMP echo requests from ${`192.168.${rand(0,254)}.${rand(1,254)}`}`}
        ];
        const pick = sample(alerts);
        const li = document.createElement('li');
        li.className = `flash`;
        li.innerHTML = `[${pick.sev}] ${pick.msg}`;
        alertList && alertList.prepend(li);
        // trim
        while(alertList && alertList.children.length>15){ alertList.removeChild(alertList.lastChild); }
      }
    }
    function startLive(){ if(liveOn) return; liveOn=true; liveBtn.textContent='Disable Live Mode'; liveTimer=setInterval(addLog, 800); alertTimer=setInterval(addRandomAlert, 2500); }
    function stopLive(){ liveOn=false; liveBtn.textContent='Enable Live Mode'; clearInterval(liveTimer); clearInterval(alertTimer); }
    liveBtn && (liveBtn.onclick = () => liveOn ? stopLive() : startLive());

    // Timeline playback (static stream simulation) - only if we have traffic data
    const tcEl = document.getElementById('trafficChart');
    if(tcEl && traffic && traffic.length > 0){
      let playing = false, playIdx = 0;
      const labels = traffic.map(x=>x.time);
      const seriesICMP = traffic.map(x=>x.ICMP || 0);
      const seriesTCP = traffic.map(x=>x.TCP || 0);
      const seriesUDP = traffic.map(x=>x.UDP || 0);
      const ctx = tcEl.getContext('2d');
      const playChart = new Chart(ctx, { type:'line', data:{ labels:[], datasets:[
        {label:'ICMP', data:[], borderColor:'#60a5fa'},
        {label:'TCP', data:[], borderColor:'#34d399'},
        {label:'UDP', data:[], borderColor:'#fca5a5'}
      ]}, options:{responsive:true, plugins:{legend:{labels:{color:'#e6eefc'}}}, scales:{x:{ticks:{color:'#9bb0d3'}}, y:{ticks:{color:'#9bb0d3'}}}}});
      function step(){
        if(!playing) return;
        if(playIdx >= labels.length){ playing = false; return; }
        playChart.data.labels.push(labels[playIdx]);
        playChart.data.datasets[0].data.push(seriesICMP[playIdx]);
        playChart.data.datasets[1].data.push(seriesTCP[playIdx]);
        playChart.data.datasets[2].data.push(seriesUDP[playIdx]);
        playChart.update();
        playIdx++;
        setTimeout(step, 300);
      }
      const controls = document.querySelector('.controls');
      const playBtn = document.createElement('button'); playBtn.className='btn'; playBtn.textContent='Play Timeline';
      playBtn.onclick = ()=>{ if(!playing){ playing = true; playIdx = 0; playChart.data.labels=[]; playChart.data.datasets.forEach(d=>d.data=[]); playChart.update(); step(); } };
      controls && controls.prepend(playBtn);
    }
  } catch(e){ 
    // Only show error if we truly have no data
    showErrorIfNeeded();
  }
}

window.InspectorPage = function(){
  const tbody = document.querySelector('#packetTable tbody');
  const fProtocol = document.getElementById('fProtocol');
  const fSrc = document.getElementById('fSrc');
  const fDst = document.getElementById('fDst');
  const apply = document.getElementById('applyFilters');
  const err = document.getElementById('inspError');

  async function load(){
    try{
      const params = new URLSearchParams();
      if(fProtocol.value) params.set('protocol', fProtocol.value);
      if(fSrc.value) params.set('src', fSrc.value);
      if(fDst.value) params.set('dst', fDst.value);
      const res = await fetch('/api/packets?'+params.toString());
      if(!res.ok) throw new Error('no data');
      const rows = await res.json();
      tbody.innerHTML = rows.map(r => `<tr><td>${r.time||''}</td><td>${r.src||''}</td><td>${r.dst||''}</td><td>${r.protocol||''}</td><td>${r.length||''}</td><td>${r.flags||''}</td><td>${r.info||''}</td></tr>`).join('');
    } catch(e){ err.textContent = 'No data. Upload files first.'; }
  }
  apply.onclick = load;
  load();
}


