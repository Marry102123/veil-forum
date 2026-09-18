// veil-forum app — 极简高密度增强：计数器 + flash 关闭
(function(){
  function addCounter(input, id){
    if(!input || document.getElementById(id)) return;
    const c=document.createElement('div');
    c.id=id; c.className='muted';
    c.style.cssText='text-align:right;font-size:11px;margin-top:2px;font-family:var(--font-mono)';
    input.insertAdjacentElement('afterend', c);
    const upd=()=>{
      const len=input.value.length;
      if(id==='title-counter'){
        const rem=120-len;
        let msg=len+'/120';
        if(len>0&&len<5) msg+=' · 至少5字';
        if(len>100) msg+=' · 剩余'+rem;
        c.textContent=msg;
        c.style.color=(len>0&&(len<5||len>120))?'var(--error)':'var(--muted)';
      } else c.textContent=len+' 字符';
    };
    input.addEventListener('input', upd); upd();
  }
  function initCounters(){
    addCounter(document.querySelector('input[name="title"]'),'title-counter');
    addCounter(document.querySelector('textarea[name="content"]'),'content-counter');
  }
  function initFlash(){
    document.querySelectorAll('.flash').forEach(el=>{
      if(el.querySelector('.flash-close')) return;
      const b=document.createElement('button');
      b.textContent='×'; b.className='flash-close'; b.setAttribute('aria-label','关闭');
      b.style.cssText='margin-left:auto;background:transparent;border:none;font-size:15px;cursor:pointer;padding:0 4px;line-height:1;color:inherit';
      b.onclick=()=>{el.style.opacity='0';setTimeout(()=>el.remove(),150)};
      el.style.display='flex'; el.style.alignItems='center';
      el.appendChild(b);
      if(el.classList.contains('flash-ok')) setTimeout(()=>{if(el.parentNode){el.style.opacity='0';setTimeout(()=>el.remove(),300)}},6000);
    });
  }
  function initRoleSearch(){
    const input=document.getElementById('role-user-search');
    const body=document.getElementById('role-user-results');
    const empty=document.getElementById('role-user-empty');
    if(!input||!body||!empty) return;
    const update=()=>{
      const query=input.value.trim().toLowerCase(); let visible=0;
      body.querySelectorAll('tr[data-role-user]').forEach(row=>{
        const show=!query||row.dataset.roleUser.toLowerCase().includes(query);
        row.hidden=!show; if(show) visible++;
      });
      empty.hidden=visible!==0;
    };
    input.addEventListener('input',update);
  }
  const ready=()=>{initCounters(); initFlash(); initRoleSearch();};
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', ready);
  else ready();
})();
