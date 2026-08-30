function hasLeadingZeros(hash, bits){
  const full = Math.floor(bits/8);
  const rem = bits%8;
  for(let i=0;i<full;i++) if(hash[i]!==0) return false;
  if(rem>0){
    if(hash[full] >> (8-rem) !==0) return false;
  }
  return true;
}

// Fallback main-thread solver when Worker execution is unavailable.
async function solvePowMainThread(challenge, salt, difficulty){
  const start = Date.now();
  let nonce = 0;
  const expected = Math.pow(2, difficulty);
  let statusEl = document.getElementById('pow-status');
  let progressEl = document.getElementById('pow-progress');
  let containerEl = document.getElementById('pow-progress-container');
  if (statusEl && !containerEl) {
    containerEl = document.createElement('div');
    containerEl.id = 'pow-progress-container';
    containerEl.style.cssText = 'width:100%;height:10px;background:var(--border);border:1px solid var(--border);margin:8px 0;overflow:hidden;display:none;border-radius:999px';
    const bar = document.createElement('div');
    bar.id = 'pow-progress';
    bar.style.cssText = 'height:100%;width:0%;background:var(--accent);transition:width 0.1s linear;border-radius:999px';
    containerEl.appendChild(bar);
    statusEl.parentNode.insertBefore(containerEl, statusEl.nextSibling);
    progressEl = bar;
  }
  if (containerEl) containerEl.style.display = 'block';
  if (progressEl) progressEl.style.width = '0%';
  while (true) {
    const data = new TextEncoder().encode('veil-forum-pow-v2' + salt + challenge + nonce);
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    if (hasLeadingZeros(hash, difficulty)) {
      if (progressEl) progressEl.style.width = '100%';
      if (statusEl) statusEl.textContent = statusEl.dataset.done || 'PoW anti-abuse check completed';
      return {nonce: String(nonce), timeMs: Date.now()-start};
    }
    nonce++;
    const pctDisplay = Math.min(99.9, (nonce / expected) * 100);
    if (statusEl) statusEl.textContent = `${statusEl.dataset.computing || 'Performing PoW anti-abuse computation...'} ${pctDisplay.toFixed(1)}%`;
    if (progressEl) {
      const pct = Math.min(99, (nonce / expected) * 100);
      progressEl.style.width = pct.toFixed(1) + '%';
    }
    await new Promise(r => setTimeout(r, 0));
  }
}

// worker-based solve (non-blocking)
function solvePowWorker(challenge, salt, difficulty){
  return new Promise((resolve, reject)=>{
    let statusEl = document.getElementById('pow-status');
    let progressEl = document.getElementById('pow-progress');
    let containerEl = document.getElementById('pow-progress-container');
    if (statusEl && !containerEl) {
      containerEl = document.createElement('div');
      containerEl.id = 'pow-progress-container';
      const bar = document.createElement('div');
      bar.id = 'pow-progress';
      containerEl.appendChild(bar);
      statusEl.parentNode.insertBefore(containerEl, statusEl.nextSibling);
      progressEl = bar;
    }
    if (containerEl) containerEl.style.display = 'block';
    if (progressEl) progressEl.style.width = '0%';

    const start = Date.now();
    const expected = Math.pow(2, difficulty);
    let worker;
    try{
      worker = new Worker('/static/pow-worker.js');
    }catch(e){
      reject(e);
      return;
    }
    // expose for abort on navigation
    window._powWorker = worker;
    let settled = false;
    const cleanup = ()=>{ if(window._powWorker===worker) window._powWorker=null; try{worker.terminate();}catch{} };
    worker.onmessage = (e)=>{
      const d = e.data;
      if(!d) return;
      if(d.type==='progress'){
        const nonce = d.nonce;
        const pctDisplay = Math.min(99.9, (nonce / expected) * 100);
        if (statusEl) statusEl.textContent = `${statusEl.dataset.computing || 'Performing PoW anti-abuse computation...'} ${pctDisplay.toFixed(1)}%`;
        if (progressEl) {
          const pct = Math.min(99, (nonce / expected) * 100);
          progressEl.style.width = pct.toFixed(1) + '%';
        }
      } else if(d.type==='done'){
        if(settled) return; settled=true;
        if (progressEl) progressEl.style.width = '100%';
        if (statusEl) statusEl.textContent = statusEl.dataset.done || 'PoW anti-abuse check completed';
        cleanup();
        resolve({nonce: String(d.nonce), timeMs: Date.now()-start});
      } else if(d.type==='error'){
        if(settled) return; settled=true;
        cleanup();
        reject(new Error(d.message || 'worker error'));
      }
    };
    worker.onerror = (e)=>{
      if(settled) return; settled=true;
      cleanup();
      reject(new Error(e.message || 'worker error'));
    };
    // timeout guard: if worker silent 60s, treat as failed and fallback
    const timeout = setTimeout(()=>{
      if(settled) return;
      settled=true;
      cleanup();
      reject(new Error('worker timeout'));
    }, 120000);
    // wrap resolve/reject to clear timeout
    const origResolve = resolve, origReject = reject;
    resolve = (v)=>{ clearTimeout(timeout); origResolve(v); };
    reject = (e)=>{ clearTimeout(timeout); origReject(e); };

    worker.postMessage({type:'start', challenge, salt, difficulty});
    // allow external abort
    worker._abort = ()=>{ if(settled) return; settled=true; cleanup(); reject(new Error('aborted')); };
  });
}

async function solvePow(challenge, salt, difficulty){
  // try worker first, fallback to main thread
  if(window.Worker){
    try{
      return await solvePowWorker(challenge, salt, difficulty);
    }catch(e){
      console.warn('worker failed, fallback to main thread', e);
      // fall through
    }
  }
  return solvePowMainThread(challenge, salt, difficulty);
}

async function attachPow(form, scope){
  // HTML defaults a button inside a form to submit, but server-rendered forms
  // do not need to spell that attribute out. Support both forms so the PoW UI
  // consistently disables the actual submit control while solving.
  const btn = form.querySelector('button[type=submit], button:not([type])');
  const origText = btn ? btn.textContent : '';
  if(btn) { btn.disabled=true; btn.textContent='PoW computing…'; }
  const pcon = document.getElementById('pow-progress-container');
  const pbar = document.getElementById('pow-progress');
  if(pcon) pcon.style.display='block';
  if(pbar) pbar.style.width='0%';
  try{
    const resp = await fetch('/api/pow/challenge?scope='+encodeURIComponent(scope));
    if(!resp.ok) throw new Error('challenge fetch failed');
    const ch = await resp.json();
    const {nonce} = await solvePow(ch.challenge, ch.salt, ch.difficulty);
    const fields = {challenge:ch.challenge, salt:ch.salt, difficulty:ch.difficulty, expires_at:ch.expires_at, hmac:ch.hmac, nonce, scope:ch.scope};
    for(const [k,v] of Object.entries(fields)){
      let inp = form.querySelector('input[name="pow_'+k+'"]');
      if(!inp){ inp=document.createElement('input'); inp.type='hidden'; inp.name='pow_'+k; form.appendChild(inp); }
      inp.value=v;
    }
    const status = document.getElementById('pow-status');
    if(status) status.textContent=status.dataset.submitting || 'PoW check completed, submitting...';
    if(pbar) pbar.style.width='100%';
    return true;
  }catch(e){
    // use non-blocking UI instead of alert where possible
    const msg = (document.getElementById('pow-status')?.dataset.failed || 'The PoW anti-abuse check failed. Please try again.') + ' (' + e.message + ')';
    try{ alert(msg); }catch{}
    const st = document.getElementById('pow-status');
    if(st) st.textContent=msg;
    const pc = document.getElementById('pow-progress-container');
    if(pc) pc.style.display='none';
    return false;
  }finally{
    if(window._powWorker){ try{window._powWorker.terminate();}catch{} window._powWorker=null; }
    if(btn){ btn.disabled=false; btn.textContent=origText; }
    setTimeout(()=>{
      const pc = document.getElementById('pow-progress-container');
      if(pc) pc.style.display='none';
      const pb = document.getElementById('pow-progress');
      if(pb) pb.style.width='0%';
    }, 1500);
  }
}
document.addEventListener('DOMContentLoaded', ()=>{
  // The page defaults to the visible manual fallback. Remove no-js only after
  // this script has actually executed, so per-site script blocking remains a
  // safe and usable fallback.
  document.body.classList.remove('no-js');
  document.querySelectorAll('form[data-pow-scope]').forEach(form=>{
    form.addEventListener('submit', async (e)=>{
      if(form.dataset.powSolved === "1"){
        form.dataset.powSolved = "0";
        return;
      }
      e.preventDefault();
      form.querySelectorAll('input[name^="pow_"]').forEach(el=>el.remove());
      const scope=form.getAttribute('data-pow-scope');
      const ok = await attachPow(form, scope);
      if(ok){
        form.dataset.powSolved = "1";
        form.requestSubmit();
      }
    });
  });
  // abort worker on page hide
  window.addEventListener('pagehide', ()=>{ if(window._powWorker) try{window._powWorker.terminate();}catch{} });
});
