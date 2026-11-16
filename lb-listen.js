/* LinguaBridge "Listen" buttons for public pages (home, about).
   Reads the text of the element named in data-listen-target with the same Apollo / Callista voice used in lessons.
   Light on purpose: no lesson engine, no chat. Plays line by line, tap again to stop. */
(function(){
 var API='https://api.lingua-bridge.us/api/tts';
 function voice(){try{var v=localStorage.getItem('lb_voice4');if(v==='apollo'||v==='callista')return v;return localStorage.getItem('lb_voice_gender')==='girl'?'callista':'apollo'}catch(e){return'apollo'}}
 function url(t){var sp=voice();return API+'?engine=aura2&voice='+(sp==='callista'?'girl':'boy')+'&speaker='+sp+'&v=2&text='+encodeURIComponent(t)}
 function clean(t){t=String(t).replace(/<[^>]*>/g,'').replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{200D}]/gu,'').replace(/\s+/g,' ').trim();return /[.!?]$/.test(t)?t:t+'.'}
 function chunks(t,max){var x=String(t).replace(/\s+/g,' ').trim(),parts=x.match(/[^.!?]+[.!?]*\s*/g)||[x],out=[],cur='';
  parts.forEach(function(q){if((cur+q).length>max&&cur){out.push(cur.trim());cur=q}else cur+=q});if(cur.trim())out.push(cur.trim());return out}
 var cache={};
 function get(t){var u=url(t);if(cache[u])return cache[u];
  cache[u]=fetch(u,{credentials:'include'}).then(function(r){if(!r.ok)throw new Error(r.status);return r.blob()}).then(function(b){if(!b||b.size<1200)throw new Error('bad');return b}).catch(function(e){delete cache[u];throw e});return cache[u]}
 var AC=window.AudioContext||window.webkitAudioContext,ctx=null,el=null,run=0,cur=null,curBtn=null;
 function unlock(){try{if(AC){ctx=ctx||new AC();if(ctx.state==='suspended')ctx.resume();var b=ctx.createBuffer(1,1,22050),s=ctx.createBufferSource();s.buffer=b;s.connect(ctx.destination);s.start(0)}}catch(e){}
  try{el=el||new Audio();el.muted=false}catch(e){}}
 function stop(){run++;try{if(cur&&cur.pause)cur.pause()}catch(e){}cur=null;if(curBtn){curBtn.classList.remove('on');curBtn.setAttribute('aria-pressed','false');curBtn.querySelector('.lt').textContent=curBtn.dataset.label;curBtn=null}}
 function play(b){return new Promise(function(res){
  var u=URL.createObjectURL(b),done=false;function fin(){if(done)return;done=true;try{URL.revokeObjectURL(u)}catch(e){}res()}
  function viaCtx(){b.arrayBuffer().then(function(ab){return new Promise(function(ok,no){ctx.decodeAudioData(ab,ok,no)})}).then(function(buf){var s=ctx.createBufferSource();s.buffer=buf;s.connect(ctx.destination);s.onended=fin;s.pause=function(){try{s.stop()}catch(e){}fin()};cur=s;s.start(0)}).catch(fin)}
  function shared(){try{el.src=u;el.onended=fin;el.onerror=fin;cur=el;var p=el.play();if(p&&p.catch)p.catch(function(){if(ctx)viaCtx();else fin()})}catch(e){fin()}}
  try{var a=new Audio(u);a.onended=fin;a.onerror=fin;cur=a;var p=a.play();if(p&&p.catch)p.catch(function(){shared()})}catch(e){shared()}})}
 function start(btn,text){
  stop();unlock();var my=++run;curBtn=btn;btn.classList.add('on');btn.setAttribute('aria-pressed','true');btn.querySelector('.lt').textContent='Stop';
  var list=chunks(text,190).map(clean);
  var q=list.map(function(t){return get(t)});
  var failed=false;
  function next(i){if(my!==run)return;if(i>=list.length){stop();return}
   q[i].then(function(b){if(my!==run)return;return play(b)}).then(function(){if(my!==run)return;next(i+1)}).catch(function(){if(my!==run)return;failed=true;stop();btn.querySelector('.lt').textContent='Try again';setTimeout(function(){btn.querySelector('.lt').textContent=btn.dataset.label},2500)})}
  next(0)}
 function init(){
  var btns=document.querySelectorAll('[data-listen-target]');
  btns.forEach(function(btn){
   var tg=document.querySelector(btn.getAttribute('data-listen-target'));if(!tg)return;
   btn.dataset.label=btn.querySelector('.lt').textContent;
   function text(){var c=tg.cloneNode(true);c.querySelectorAll('[data-listen-skip],.section-label,.founder-sign,script,style,button,a.fun-btn').forEach(function(n){n.remove()});c.querySelectorAll('h1,h2,h3,p,li,blockquote').forEach(function(n){n.appendChild(document.createTextNode(' '))});return c.textContent}
   btn.addEventListener('click',function(){if(curBtn===btn){stop();return}start(btn,text())});
   /* warm the first line when the note scrolls into view so the first tap plays right away */
   try{var seen=false,io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting&&!seen){seen=true;var l=chunks(text(),190).map(clean);if(l[0])get(l[0]).catch(function(){});io.disconnect()}})},{rootMargin:'200px'});io.observe(tg)}catch(e){}});
  window.addEventListener('pagehide',stop)}
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
