/* LinguaBridge shared core: progress state (LB), curriculum structure (LEVELS),
   Bridge's TTS voice system (AUDIO/bridgeSpeak). Identical on every page that
   used to embed this inline (lesson, lesson-quiz, lesson-video, dashboard, badge,
   see-you-tomorrow) -- extracted so it's downloaded/cached once instead of six
   times. No logic changed from the original inline version. */
const LB={
 /* DAILY LOCK: one-lesson-per-day rule. Turned OFF 2026-11-05 at the founder's request:
    students may do as many lessons as they like; Bridge suggests breaks instead (see break reminder). */
 LOCK:false,
 KEY:'lb_student_v1',
 get(){let s={};try{s=JSON.parse(localStorage.getItem(this.KEY))||{}}catch(e){}
  return Object.assign({level:'explorer',completed:[],dayOffset:0},s)},
 set(s){try{localStorage.setItem(this.KEY,JSON.stringify(s))}catch(e){}
  if(typeof this._dirty==='function')this._dirty()},
 today(s){const d=new Date();d.setDate(d.getDate()+(s.dayOffset||0));
  return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')},
 doneToday(s){return s.completed.some(c=>c.date===this.today(s))},
 /* FOUNDER LOCK BYPASS: the dashboard caches the founder's role here (from
    /api/me) right after login, so this and the lesson/lesson-quiz pages can
    skip the daily lock for the founder's own testing account without
    re-checking auth on every page. Regular students are never cached as
    'founder', so the lock stays fully on for them. */
 ROLE_KEY:'lb_role_cache',
 cacheRole(role){try{localStorage.setItem(this.ROLE_KEY,role||'')}catch(e){}},
 isFounder(){try{return localStorage.getItem(this.ROLE_KEY)==='founder'}catch(e){return false}}
};
const LEVELS={
 explorer:{name:'Explorer',emoji:'🌱',chapters:[['Hello!',4],['My Family',5],['Colors, Numbers & Shapes',6],['My Home',5],['Food & Drinks',6],['Clothes',4],['Weather & Seasons',4],['Animals',5],['Places Around Me',6],['Explorer Celebration',2]]},
 builder:{name:'Builder',emoji:'🧩',chapters:[['My Daily Routine',5],['School Life',6],['Hobbies & Interests',5],['Feelings & Emotions',5],['Shopping & Money',6],['Getting Around',5],['Health & My Body',5],['My Community',5],['Technology & Communication',6],['Ready for Communicator',2]]},
 communicator:{name:'Communicator',emoji:'💬',chapters:[['Stories & Storytelling',6],['Conversations',6],['Writing',5],['Listening Skills',5],['Exploring the World',5],['Sharing Opinions',5],['Solving Problems Together',5],['Reading for Understanding',6],['Speaking with Confidence',5],['Ready for Leader',2]]},
 leader:{name:'Leader',emoji:'🌟',chapters:[['Public Speaking',6],['Academic Writing',6],['Professional Communication',5],['English Around the World',5],['Critical Thinking',5],['Leadership & Teamwork',5],['Goal Setting & Confidence',4],['Real-World English',6],['My Final Project',5],['LinguaBridge Graduation',2]]}
};
/* ---------- BRIDGE'S VOICE ----------
   ONE centralized config for Bridge's voice identity, used everywhere Bridge speaks (lesson videos,
   instructions, pronunciation practice, quiz feedback, badges, dashboard). Nothing else in the codebase
   should hard-code a voice, a rate, or a provider — it should all flow through BRIDGE_VOICE_CONFIG and
   bridgeSpeak() below.

   HONEST STATUS (so this doesn't overstate what it does): every recorded clip on the site today comes
   from Kokoro-82M, a free local neural TTS model — a real neural voice, but not in the same tier as a
   commercial voice like Amazon Polly Neural / Azure Neural / ElevenLabs. Those aren't reachable from
   this sandbox. The browser voice below is only the last-resort fallback when a clip is missing (that
   fallback, not the recorded clips, is what sounds robotic on some devices). `provider` and the
   `style`/`pitch` fields are placeholders for a future swap to a warmer commercial voice: to upgrade,
   add one more case inside bridgeSpeak() below that calls the new provider's API — nothing else on the
   site needs to change, because every page already calls bridgeSpeak()/bridgeSpeakSeq() rather than
   talking to a voice engine directly. */
const BRIDGE_VOICE_CONFIG={
 provider:'kokoro-local', // 'kokoro-local' today; swap in a case in bridgeSpeak() for e.g. 'azure-neural' / 'elevenlabs' later
 voiceId:'daniel',         // must match a key in AUDIO.voices/AUDIO.data. Was briefly switched to 'sky'
                          // (2026-10-10) for a livelier, more energetic default, then switched back to
                          // 'bella' (2026-10-11) at the founder's explicit request. Sarah is the third
                          // recorded option (more neutral/clear). (Nicole was removed earlier per the founder's
                          // request -- she leaned breathy/ASMR and didn't fit.) 'daniel' is a separate
                          // friendly-guy option added at the founder's request: Kokoro here only has recorded
                          // af_* (female) clips, so daniel has no baked clips and always speaks through the
                          // device's own speechSynthesis voice instead (see VOICE.malePrefs below) -- lower
                          // audio quality than the recorded voices, but a real male voice where the device has
                          // one. Known ceiling: the founder has said even the recorded voices still sound
                          // synthetic / "like a robot," not natural -- that's a real limit of this free local
                          // engine (Kokoro-82M), not a tuning problem, and is why Task #7 (commercial TTS,
                          // ElevenLabs) is queued next. The dashboard's voice-compare panel is where a human
                          // can listen and override LB.get().voice per-browser if needed.
 language:'en-US',
 volume:0.92,
 // Rate had been slowed down repeatedly this session (0.95 -> 0.85 -> 0.82)
 // to make narration easier to follow -- but the founder heard that as
 // lazy/sluggish AND too old-sounding, not calm, and asked for something
 // livelier and younger, closer to a 20-year-old than the original
 // recorded tone. Since there's no way to re-record Kokoro's clips here,
 // the two real levers are: (1) rate, pushed well past the original 0.95
 // baseline, and (2) letting that rate change also raise pitch instead of
 // only speeding up tempo (see `preservesPitch` in playClip() below) --
 // together these noticeably shift the recorded Sky/Bella/Sarah clips
 // younger-sounding, not just faster. Pronunciation mode stays a little
 // gentler than conversational so a word being taught is still clear.
 rate:{conversational:1.0,pronunciation:0.9}, // founder reported Listen/Speak on lesson pages sounding rushed (2026-10-11) --
 // Sky's own recorded pace runs brisk even in its dedicated pron clips, so pronunciation-mode now plays
 // noticeably slower than the raw recording (not just "not sped up" at 1.0) so a word being taught stays clear.
 pitch:1.05,                                               // raised further for a brighter, younger-sounding read -- only directly controls the browser fallback voice (used when a clip is missing, e.g. dynamic text); recorded clips get their pitch shift from rate + preservesPitch instead, since Kokoro itself exposes no pitch control
 style:{conversational:'bright',pronunciation:'clear'},    // placeholder: no style/emotion control in the current engine
 pronunciationMode:{extraClear:true,deliberate:true}
};
const VOICE={ // kept only for the browser-fallback voice PICK; rate now always comes from BRIDGE_VOICE_CONFIG
 skip:/Albert|Bad News|Bahh|Bells|Boing|Bubbles|Cellos|Deranged|Good News|Hysterical|Junior|Organ|Ralph|Trinoids|Whisper|Zarvox|Fred|Superstar|Eddy|Flo|Grandma|Grandpa|Reed|Rocko|Sandy|Shelley/,
 prefs:['Aria','Jenny','Natural','Ava','Allison','Samantha','Google US English','Karen','Moira','Tessa','Zira'],
 /* Male-leaning device voice names, used only for the 'daniel' (friendly guy) option, which has no
    recorded Kokoro clips -- it always plays through the device's own speechSynthesis, so picking the
    best-sounding male system voice available matters more here than for the recorded voices. */
 malePrefs:['Guy','Daniel','Ryan','Eric','Christopher','Matthew','David','Fred','Google UK English Male','Oliver','Brian'],
 list(){try{return speechSynthesis.getVoices().filter(v=>/^en/i.test(v.lang)&&!this.skip.test(v.name))}catch(e){return[]}},
 pick(force){const all=this.list(),st=LB.get();
  if(!force&&st.voice){const v=all.find(x=>x.name===st.voice);if(v)return v}
  if(force==='daniel'||st.voice==='daniel'){for(const k of this.malePrefs){const v=all.find(x=>x.name.includes(k));if(v)return v}}
  for(const k of this.prefs){const v=all.find(x=>x.name.includes(k)&&/en[-_]US/i.test(x.lang));if(v)return v}
  return all.find(x=>/en[-_]US/i.test(x.lang))||all[0]||null}
};
function utter(t,mode,vid){const u=new SpeechSynthesisUtterance(t);u.lang=BRIDGE_VOICE_CONFIG.language;const v=VOICE.pick(vid);if(v){u.voice=v;u.lang=v.lang}
 u.rate=BRIDGE_VOICE_CONFIG.rate[mode||'conversational'];u.pitch=BRIDGE_VOICE_CONFIG.pitch;u.volume=BRIDGE_VOICE_CONFIG.volume;return u}
/* Recorded natural voice clips, embedded directly in the page (base64) so playback never depends on
   a separate audio folder or on how the file was opened/shared. Same voice on every device.
   The device's own speech voice above is only a last-resort fallback if a clip is ever missing. */
const AUDIO={voices:{daniel:'Daniel (friendly guy — device voice)'},
/* Conversational-speed clips (lessons, instructions, feedback, celebrations). */
data:{},
/* Pronunciation-mode clips: rendered by the TTS model itself at a genuinely slower native speed
   (not a post-hoc playback-rate hack, which would also shift pitch and sound worse). Used only for
   the exact words/lines a student is asked to imitate. */
pron:{},
voice(){const v=LB.get().voice;return this.voices[v]?v:BRIDGE_VOICE_CONFIG.voiceId}};
let _cur=null,_failed=false;
function slugOf(t){return t.toLowerCase().replace(/[^a-z0-9 ]/g,'').trim().replace(/\s+/g,'-').slice(0,120)}
function stopAudio(){try{speechSynthesis.cancel()}catch(e){}if(_cur){_cur.onended=null;_cur.onerror=null;_cur.pause();_cur=null}}
function deviceSay(t,mode,vid){try{speechSynthesis.speak(utter(t,mode||'conversational',vid))}catch(e){}}
function playClip(b64,t,mode,done){const a=new Audio('data:audio/mpeg;base64,'+b64);_cur=a;_failed=false;a.volume=BRIDGE_VOICE_CONFIG.volume;a.playbackRate=BRIDGE_VOICE_CONFIG.rate[mode||'conversational'];
 // The recorded clips' actual timbre is fixed (baked into the audio, no
 // TTS-regeneration pipeline here to re-record it younger-sounding) --
 // but letting playbackRate also shift pitch (instead of the browser's
 // default pitch-preserving speed-up) is a real lever: a touch faster +
 // a touch higher-pitched reads as noticeably younger than the raw
 // recording. `preservesPitch`/vendor-prefixed variants default to true
 // (speed changes, pitch stays flat); setting them false lets pitch move
 // together with BRIDGE_VOICE_CONFIG.rate above.
 try{a.preservesPitch=true;a.mozPreservesPitch=true;a.webkitPreservesPitch=true}catch(e){} /* 2026-11-05: founder said the voice sounded robotic; the speed-up + pitch-raise trick made it sound squeaky, so clips now play at natural speed and pitch */
 a.onended=()=>{if(done)done()};
 a.onerror=()=>{if(_failed)return;_failed=true;deviceSay(t,mode);if(done)done()};
 const r=a.play();if(r&&r.catch)r.catch(()=>{if(_failed)return;_failed=true;deviceSay(t,mode);if(done)done()})}
/* bridgeSpeak(text, {mode, done}) — THE single entry point for every spoken line on the site.
   mode: 'conversational' (default: lessons, instructions, feedback, celebrations) or
         'pronunciation' (Listen-to-Bridge practice: extra clear, slightly slower, never robotic).
   Looks up the recorded clip for BRIDGE_VOICE_CONFIG.voiceId; falls back to the device voice at the
   correct rate for that mode so even the fallback path stays mode-appropriate. To swap in a commercial
   provider later, branch on BRIDGE_VOICE_CONFIG.provider here — every caller stays unchanged. */
/* All voices are now Daniel (device voice), at the founder's request 2026-11-09. */
function bridgeSpeak(t,opts){opts=opts||{};const mode=opts.mode||'conversational';stopAudio();
 try{const u=utter(t,mode,'daniel');if(opts.done){u.onend=opts.done;u.onerror=opts.done}speechSynthesis.speak(u)}catch(e){if(opts.done)opts.done()}}
function bridgeSpeakSeq(arr,mode){stopAudio();let i=0;const next=()=>{if(i>=arr.length)return;const t=arr[i++];
 try{const u=utter(t,mode||'conversational','daniel');u.onend=next;u.onerror=next;speechSynthesis.speak(u)}catch(e){next()}};next()}
// Backward-compatible aliases — existing pages that call speak()/speakSeq() automatically get
// conversational mode through BRIDGE_VOICE_CONFIG without needing to change their call sites.
function speak(t){bridgeSpeak(t,{mode:'conversational'})}
function speakSeq(arr){bridgeSpeakSeq(arr,'conversational')}

/* ------------------------------------------------------------------
   LESSON MINI-GAME — one small reusable engine, not per-lesson authored
   content. Built directly from a lesson's own vocab1/vocab2 (word, meaning,
   emoji triples), which every lesson already has, so it works on all ~109
   existing lessons and any future one with zero extra authoring.

   Three game types, picked (and combined) by level so difficulty rises with
   level, per the founder's request:
     - explorer:     Picture Match only (tap a word, tap its matching emoji)
     - builder:       + Memory Flip (find the emoji/word pairs)
     - communicator:  + Fill in the Blank (complete a line from the lesson's
                       own conversation using a word bank)
     - leader:        all three, with more items and fewer hints
   Each mini-game calls onDone() exactly once, the moment it's fully solved
   (every pair/word/round) -- not a running count -- so the host page can
   gate its "Next" button the same simple way it gates every other step
   (need[step]=1, one gate(step,0) callback), with no step-specific counting
   logic on the page side.
   ------------------------------------------------------------------ */
function LB_gameItems(lesson,max){
 const raw=[].concat(lesson.vocab1||[],lesson.vocab2||[]);
 const seen=new Set(),items=[];
 for(const [w,h,e] of raw){if(!w||!e||seen.has(w))continue;seen.add(w);items.push({word:w,hint:h,emoji:e});if(items.length>=max)break}
 return items}
function LB_shuffle(a){a=a.slice();for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]]}return a}
/* ---- Games v2 (2026-11-08): one question at a time, big friendly cards, Bridge cheers. ---- */
/* ---- Confetti + original drawn kids (2026-11-09). No emoji anywhere: these are SVG/canvas. ---- */
function LB_confetti(ms){
 try{const c=document.createElement('canvas');c.style.cssText='position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:99999';
  c.width=innerWidth;c.height=innerHeight;document.body.appendChild(c);const x=c.getContext('2d');
  const col=['#FFC83D','#159FE8','#12864A','#F0604D','#9B6BE0','#FF8FB1','#7FCB6E'];
  const P=Array.from({length:150},()=>({x:Math.random()*c.width,y:-20-Math.random()*c.height*.6,w:6+Math.random()*7,h:9+Math.random()*9,vy:2.5+Math.random()*4,vx:-2+Math.random()*4,r:Math.random()*6,vr:-.2+Math.random()*.4,c:col[Math.floor(Math.random()*col.length)]}));
  const end=performance.now()+(ms||3600);
  (function f(){x.clearRect(0,0,c.width,c.height);P.forEach(p=>{p.x+=p.vx;p.y+=p.vy;p.r+=p.vr;x.save();x.translate(p.x,p.y);x.rotate(p.r);x.fillStyle=p.c;x.fillRect(-p.w/2,-p.h/2,p.w,p.h);x.restore()});
   if(performance.now()<end)requestAnimationFrame(f);else c.remove()})()}catch(e){}}
function LB_kidSVG(i,size){
 const skins=['#F6D2B0','#D9A066','#9C6B43','#F1C27D'],hairs=['#2B1B12','#5A3A22','#1E1E1E','#C9772B'],tops=['#159FE8','#F0604D','#12864A','#9B6BE0'];
 const s=skins[i%4],h=hairs[(i+1)%4],t=tops[i%4];
 const hair=[ '<path d="M12 22Q14 6 24 6T36 22Q30 14 24 14T12 22Z" fill="'+h+'"/>',
  '<path d="M11 26Q8 6 24 6T37 26Q36 12 24 13T11 26Z" fill="'+h+'"/><circle cx="24" cy="5" r="5" fill="'+h+'"/>',
  '<path d="M11 24Q10 5 24 5T37 24Q30 12 24 15T11 24Z" fill="'+h+'"/>',
  '<path d="M10 28Q6 4 24 5T38 28L35 20Q24 10 13 20Z" fill="'+h+'"/>'][i%4];
 return '<svg class="lbkid" width="'+(size||72)+'" height="'+(size||72)+'" viewBox="0 0 48 52" aria-hidden="true">'+
  '<path d="M6 52Q8 36 24 36T42 52Z" fill="'+t+'"/><circle cx="24" cy="22" r="13" fill="'+s+'"/>'+hair+
  '<circle cx="19" cy="22" r="1.8" fill="#222"/><circle cx="29" cy="22" r="1.8" fill="#222"/>'+
  '<path d="M18 27Q24 33 30 27" fill="#fff" stroke="#222" stroke-width="1.6" stroke-linejoin="round"/>'+
  '<circle cx="15.5" cy="26" r="2" fill="#FF9AA2" opacity=".6"/><circle cx="32.5" cy="26" r="2" fill="#FF9AA2" opacity=".6"/>'+
  '<path d="M3 30l6 6M45 30l-6 6" stroke="'+s+'" stroke-width="4" stroke-linecap="round"/></svg>'}
function LB_starSVG(n){return '<svg viewBox="0 0 48 48" width="'+(n||44)+'" height="'+(n||44)+'" aria-hidden="true"><path d="M24 3l6 13 14 2-10 10 3 14-13-7-13 7 3-14L4 18l14-2z" fill="#FFC83D" stroke="#E9A800" stroke-width="2.5" stroke-linejoin="round"/></svg>'}
function LB_speakerSVG(){return '<svg viewBox="0 0 48 48" width="24" height="24" aria-hidden="true"><path d="M6 18h8l10-8v28l-10-8H6z" fill="#fff"/><path d="M31 17q6 7 0 14M36 12q10 12 0 24" fill="none" stroke="#fff" stroke-width="3.5" stroke-linecap="round"/></svg>'}
function LB_gameStyles(){
 if(document.getElementById('lbGameCss'))return;
 const s=document.createElement('style');s.id='lbGameCss';
 s.textContent=`
 .gm{background:linear-gradient(180deg,#EAF6FF,#FFF9F1);border-radius:22px;padding:18px 16px 20px;border:2px solid #CFE8F8}
 .gm-top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
 .gm-dots{display:flex;gap:6px;flex-wrap:wrap}
 .gm-dot{width:14px;height:14px;border-radius:50%;background:#fff;border:2px solid #9CCBE8;transition:all .25s}
 .gm-dot.on{background:#FFC83D;border-color:#E9A800;transform:scale(1.15)}
 .gm-dot.now{border-color:#159FE8;box-shadow:0 0 0 3px rgba(21,159,232,.25)}
 .gm-say{display:flex;align-items:center;gap:10px;margin-bottom:14px}
 .gm-bridge{flex:0 0 46px;height:46px;border-radius:50%;background:#159FE8;color:#fff;font-weight:700;font-size:1.3rem;display:flex;align-items:center;justify-content:center;font-family:var(--font-head,serif)}
 .gm-bubble{background:#fff;border-radius:16px 16px 16px 4px;padding:10px 14px;font-weight:600;color:#0B3B6B;box-shadow:0 2px 6px rgba(11,59,107,.12);flex:1;line-height:1.35}
 .gm-word{display:flex;align-items:center;justify-content:center;gap:12px;margin:6px 0 16px}
 .gm-word b{font-family:var(--font-head,serif);font-size:2rem;color:#0B3B6B;background:#fff;padding:8px 22px;border-radius:16px;box-shadow:0 3px 0 #CFE8F8}
 .gm-ear{border:none;background:#159FE8;color:#fff;border-radius:50%;width:44px;height:44px;cursor:pointer;font-size:1.2rem;box-shadow:0 3px 0 #0B6FAE;display:flex;align-items:center;justify-content:center}
 .gm-ear:active{transform:translateY(2px);box-shadow:0 1px 0 #0B6FAE}
 .gm-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
 @media(min-width:560px){.gm-grid.n4{grid-template-columns:repeat(4,1fr)}}
 .gm-card{border:3px solid #fff;background:#fff;border-radius:20px;padding:12px 6px;cursor:pointer;font-size:3rem;line-height:1;min-height:104px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 0 #CFE8F8;transition:transform .12s}
 .gm-card svg,.gm-card .lbe{width:64px;height:64px}
 .gm-card:hover{transform:translateY(-2px)}
 .gm-card:active{transform:translateY(2px);box-shadow:0 1px 0 #CFE8F8}
 .gm-card.right{background:#DDF6D6;border-color:#12864A;animation:gmpop .45s}
 .gm-card.wrong{background:#FFF0E0;border-color:#F0A04B;animation:gmwob .35s}
 @keyframes gmpop{0%{transform:scale(1)}40%{transform:scale(1.14)}100%{transform:scale(1)}}
 @keyframes gmwob{25%{transform:rotate(-5deg)}75%{transform:rotate(5deg)}}
 .gm-sent{font-family:var(--font-head,serif);font-size:1.3rem;color:#0B3B6B;background:#fff;border-radius:16px;padding:16px 18px;line-height:1.9;box-shadow:0 3px 0 #CFE8F8;margin-bottom:14px}
 .gm-slot{display:inline-block;min-width:92px;border-bottom:4px dashed #159FE8;color:transparent;text-align:center;border-radius:6px;background:#EAF6FF;padding:0 8px}
 .gm-slot.filled{color:#12864A;border-bottom:4px solid #12864A;background:#DDF6D6;font-weight:700}
 .gm-opts{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}
 .gm-chip{border:3px solid #fff;background:#fff;color:#0B3B6B;font-family:inherit;font-weight:600;font-size:1.1rem;padding:12px 20px;border-radius:999px;cursor:pointer;box-shadow:0 4px 0 #CFE8F8}
 .gm-chip:active{transform:translateY(2px);box-shadow:0 1px 0 #CFE8F8}
 .gm-chip.right{background:#DDF6D6;border-color:#12864A}
 .gm-chip.wrong{background:#FFF0E0;border-color:#F0A04B;animation:gmwob .35s}
 .gm-win{text-align:center;padding:14px 4px}
 .gm-win .stars{display:flex;justify-content:center;align-items:center;gap:6px}
 .gm-win .kids{display:flex;justify-content:center;gap:4px;margin-bottom:6px}
 .lbkid{animation:gmhop .8s ease-in-out infinite alternate}.lbkid:nth-child(2){animation-delay:.15s}.lbkid:nth-child(3){animation-delay:.3s}.lbkid:nth-child(4){animation-delay:.45s}
 @keyframes gmhop{to{transform:translateY(-10px)}}
 .gm-win h3{margin:8px 0 4px}
 `;document.head.appendChild(s)}
const GM_CHEER=['Great job!','You got it!','Awesome!','Super!','Yes! Well done!','Brilliant!','Nice one!'];
const GM_TRY=['Almost! Try another one.','Not quite. You can do it!','Oops! Have another look.','Good try! Pick again.'];
function LB_pickMsg(a){return a[Math.floor(Math.random()*a.length)]}
function LB_gmShell(el){
 LB_gameStyles();
 el.innerHTML='<div class="gm"><div class="gm-top"><div class="gm-dots"></div></div><div class="gm-say"><div class="gm-bridge">B</div><div class="gm-bubble"></div></div><div class="gm-body"></div></div>';
 const q=s=>el.querySelector(s);
 return {dots:q('.gm-dots'),say:t=>{q('.gm-bubble').textContent=t},body:q('.gm-body'),
  setDots(n,done){this.dots.innerHTML='';for(let i=0;i<n;i++){const d=document.createElement('span');d.className='gm-dot'+(i<done?' on':i===done?' now':'');this.dots.appendChild(d)}}}}
function LB_gmWin(sh,text,onDone){
 sh.dots.querySelectorAll('.gm-dot').forEach(d=>{d.classList.remove('now');d.classList.add('on')});
 sh.body.innerHTML='<div class="gm-win"><div class="kids">'+[0,1,2,3].map(i=>LB_kidSVG(i,74)).join('')+'</div><div class="stars">'+LB_starSVG(46)+LB_starSVG(56)+LB_starSVG(46)+'</div><h3>'+text+'</h3></div>';
 sh.say('Hooray! You finished! Tap Next to keep going.');LB_confetti();onDone()}
/* Find the Picture: one word at a time, tap the picture that matches. Wrong picks wobble, never penalised. */
function LB_mountMatchGame(el,items,onDone){
 const sh=LB_gmShell(el);const order=LB_shuffle(items.map((x,i)=>i));let step=0;
 function ask(){
  if(step>=order.length){LB_gmWin(sh,'You matched every word!',onDone);return}
  const it=items[order[step]];sh.setDots(order.length,step);
  sh.say('Which picture is "'+it.word+'"? Tap it!');
  const choices=LB_shuffle([it].concat(LB_shuffle(items.filter(x=>x!==it)).slice(0,3)));
  sh.body.innerHTML='<div class="gm-word"><b></b><button class="gm-ear" type="button" aria-label="Hear the word">'+LB_speakerSVG()+'</button></div><div class="gm-grid'+(choices.length>=4?' n4':'')+'"></div>';
  sh.body.querySelector('b').textContent=it.word;
  sh.body.querySelector('.gm-ear').onclick=()=>{try{bridgeSpeak(it.word,{mode:'pronunciation'})}catch(e){}};
  const grid=sh.body.querySelector('.gm-grid');let locked=false;
  choices.forEach(c=>{const b=document.createElement('button');b.type='button';b.className='gm-card';b.textContent=c.emoji;b.setAttribute('aria-label','picture choice');
   b.onclick=()=>{if(locked)return;
    if(c===it){locked=true;b.classList.add('right');sh.say(LB_pickMsg(GM_CHEER)+' That is "'+it.word+'".');
     const d=sh.dots.children[step];if(d){d.classList.remove('now');d.classList.add('on')}
     setTimeout(()=>{step++;ask()},1100)}
    else{b.classList.add('wrong');sh.say(LB_pickMsg(GM_TRY));setTimeout(()=>b.classList.remove('wrong'),400)}};
   grid.appendChild(b)})}
 ask()}
/* Finish the Sentence: one line at a time from the lesson's own conversation. Tap the missing word. */
function LB_mountFillBlankGame(el,items,conversation,onDone){
 const lines=(conversation||[]).map(([who,txt])=>txt);
 const rounds=[];
 items.forEach(it=>{const line=lines.find(l=>l.toLowerCase().includes(it.word.toLowerCase()));
  if(line){const idx=line.toLowerCase().indexOf(it.word.toLowerCase());
   rounds.push({before:line.slice(0,idx),after:line.slice(idx+it.word.length),answer:it.word,options:LB_shuffle([it.word].concat(LB_shuffle(items.filter(x=>x!==it).map(x=>x.word)).slice(0,2)))})}});
 if(!rounds.length){el.innerHTML='<p class="muted">Nothing to fill in for this lesson yet -- nice, you already know it all!</p>';onDone();return}
 const sh=LB_gmShell(el);let step=0;
 function ask(){
  if(step>=rounds.length){LB_gmWin(sh,'Every sentence is complete!',onDone);return}
  const r=rounds[step];sh.setDots(rounds.length,step);sh.say('One word is missing. Which word fits? Tap it!');
  sh.body.innerHTML='<div class="gm-sent"></div><div class="gm-opts"></div>';
  const sent=sh.body.querySelector('.gm-sent');
  sent.appendChild(document.createTextNode(r.before));
  const slot=document.createElement('span');slot.className='gm-slot';slot.textContent=r.answer;sent.appendChild(slot);
  sent.appendChild(document.createTextNode(r.after));
  const opts=sh.body.querySelector('.gm-opts');let locked=false;
  r.options.forEach(o=>{const b=document.createElement('button');b.type='button';b.className='gm-chip';b.textContent=o;
   b.onclick=()=>{if(locked)return;
    if(o.toLowerCase()===r.answer.toLowerCase()){locked=true;b.classList.add('right');slot.classList.add('filled');sh.say(LB_pickMsg(GM_CHEER));
     const d=sh.dots.children[step];if(d){d.classList.remove('now');d.classList.add('on')}
     try{bridgeSpeak(r.before+r.answer+r.after,{mode:'conversational'})}catch(e){}
     setTimeout(()=>{step++;ask()},1800)}
    else{b.classList.add('wrong');sh.say(LB_pickMsg(GM_TRY));setTimeout(()=>b.classList.remove('wrong'),400)}};
   opts.appendChild(b)})}
 ask()}
/* Entry used by the lesson page (contract unchanged): explorer/builder = Find the Picture,
   communicator = Finish the Sentence, leader = both. onAllDone() fires once when everything is solved. */
function LB_mountLessonGame(el,lesson,level,onAllDone){
 const tier={explorer:1,builder:2,communicator:3,leader:4}[level]||1;
 const items=LB_gameItems(lesson,tier>=4?8:tier>=2?6:4);
 const wrap=(title,fn)=>{el.innerHTML='<h2 style="margin-bottom:10px" id="lbGameTitle">'+title+'</h2><div id="lbGameBox"></div>';fn(el.querySelector('#lbGameBox'),el.querySelector('#lbGameTitle'))};
 if(tier<=2){wrap('Find the Picture',box=>LB_mountMatchGame(box,items,onAllDone));return}
 if(tier===3){wrap('Finish the Sentence',box=>LB_mountFillBlankGame(box,items,lesson.conversation,onAllDone));return}
 wrap('Find the Picture (1 of 2)',(box,t)=>LB_mountMatchGame(box,items,()=>{t.textContent='Finish the Sentence (2 of 2)';LB_mountFillBlankGame(box,items,lesson.conversation,onAllDone)}))}

/* ------------------------------------------------------------------
   ASK BRIDGE — a floating "ask a question" chat widget, available on
   every page that loads this file (lesson flow + dashboard). Calls the
   Cloudflare Worker's /api/ask-bridge endpoint (kid-safe system prompt,
   rate-limited, logged for founder review — see worker/src/index.js).
   Self-contained: injects its own styles/markup, no page changes needed.
   ------------------------------------------------------------------ */
(function () {
  const ASK_BRIDGE_API = 'https://api.lingua-bridge.us/api/ask-bridge';

  function injectStyles() {
    const css = `
      #askBridgeBtn{position:fixed;right:20px;bottom:20px;z-index:9999;background:#159FE8;color:#fff;
        border:none;border-radius:999px;padding:14px 20px;font-family:inherit;font-weight:600;font-size:.95rem;
        box-shadow:0 10px 24px rgba(11,59,107,.28);cursor:pointer;display:flex;align-items:center;gap:8px}
      #askBridgeBtn:hover{background:#0f86c4}
      #askBridgePanel{position:fixed;right:20px;bottom:86px;z-index:9999;width:320px;max-width:calc(100vw - 40px);
        max-height:60vh;background:#fff;border-radius:18px;box-shadow:0 16px 40px rgba(11,59,107,.28);
        display:none;flex-direction:column;overflow:hidden;font-family:inherit}
      #askBridgePanel.open{display:flex}
      #askBridgeHead{background:#0B3B6B;color:#fff;padding:12px 16px;display:flex;align-items:center;justify-content:space-between}
      #askBridgeHead span{font-weight:700}
      #askBridgeClose{background:none;border:none;color:#fff;font-size:1.1rem;cursor:pointer;line-height:1}
      #askBridgeLog{flex:1;overflow-y:auto;padding:12px 14px;display:flex;flex-direction:column;gap:10px;background:#F4FAFF}
      #askBridgeLog .ab-msg{border-radius:14px;padding:9px 12px;font-size:.88rem;line-height:1.4;max-width:88%;
        display:flex;align-items:flex-start;gap:6px}
      #askBridgeLog .ab-msg .ab-text{flex:1;white-space:pre-wrap}
      #askBridgeLog .ab-q{background:#159FE8;color:#fff;align-self:flex-end}
      #askBridgeLog .ab-a{background:#fff;color:#0B3B6B;align-self:flex-start;border:1px solid #e3eef7}
      #askBridgeLog .ab-hint{color:#5b6a78;font-size:.8rem;text-align:center}
      #askBridgeForm{display:flex;flex-wrap:wrap;gap:8px;padding:10px;border-top:1px solid #e3eef7}
      #askBridgeInput{flex:1;min-width:0;border:1px solid #cfe3f2;border-radius:10px;padding:8px 10px;font-family:inherit;font-size:.88rem}
      #askBridgeMic{background:#fff;color:#12864A;border:1.5px solid #12864A;border-radius:999px;padding:7px 14px;
        font-family:inherit;font-size:.82rem;font-weight:600;line-height:1;cursor:pointer;flex-shrink:0;white-space:nowrap}
      #askBridgeMic:hover{background:rgba(18,134,74,.06)}
      #askBridgeMic.listening{background:#EAF7EF;animation:abPulse 1.1s ease-in-out infinite}
      #askBridgeMic:disabled{opacity:.5;cursor:default}
      @keyframes abPulse{0%,100%{box-shadow:0 0 0 0 rgba(18,134,74,.35)}50%{box-shadow:0 0 0 7px rgba(18,134,74,0)}}
      #askBridgeSend{background:#12864A;color:#fff;border:none;border-radius:10px;padding:8px 14px;font-weight:600;cursor:pointer}
      #askBridgeSend:disabled{opacity:.6;cursor:default}
    `;
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
  }

  // The same bridge-arch mascot used site-wide, simplified into a small
  // round badge (own white background circle so it reads clearly on both
  // the blue floating button and the navy panel header).
  const BRIDGE_ICON_SVG =
    '<svg width="24" height="24" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" style="flex-shrink:0;display:block">' +
    '<circle cx="50" cy="50" r="48" fill="#ffffff"/>' +
    '<path d="M12 66 Q50 22 88 66" stroke="#159FE8" stroke-width="15" stroke-linecap="round" fill="none"/>' +
    '<circle cx="42" cy="42" r="5.5" fill="#0B3B6B"/>' +
    '<circle cx="58" cy="42" r="5.5" fill="#0B3B6B"/>' +
    '<circle cx="43.6" cy="40.4" r="1.5" fill="#ffffff"/>' +
    '<circle cx="59.6" cy="40.4" r="1.5" fill="#ffffff"/>' +
    '<path d="M43 50 Q50 56 57 50" stroke="#0B3B6B" stroke-width="3.2" stroke-linecap="round" fill="none"/>' +
    '</svg>';

  function buildWidget() {
    const btn = document.createElement('button');
    btn.id = 'askBridgeBtn';
    btn.type = 'button';
    btn.innerHTML = BRIDGE_ICON_SVG + '<span>Ask Bridge</span>';

    const panel = document.createElement('div');
    panel.id = 'askBridgePanel';
    panel.innerHTML =
      '<div id="askBridgeHead"><span style="display:flex;align-items:center;gap:8px">' + BRIDGE_ICON_SVG + '<span>Ask Bridge</span></span><button id="askBridgeClose" type="button" aria-label="Close">✕</button></div>' +
      '<div id="askBridgeLog"><div class="ab-hint">Ask Bridge about a word, a sentence, or today’s lesson!</div></div>' +
      '<form id="askBridgeForm"><input id="askBridgeInput" type="text" maxlength="300" placeholder="Type your question…" autocomplete="off"/>' +
      '<button id="askBridgeMic" type="button" aria-label="Practice saying this word out loud">🎤 Speak</button>' +
      '<button id="askBridgeSend" type="submit">Send</button></form>';

    document.body.appendChild(btn);
    document.body.appendChild(panel);

    const log = panel.querySelector('#askBridgeLog');
    const form = panel.querySelector('#askBridgeForm');
    const input = panel.querySelector('#askBridgeInput');
    const micBtn = panel.querySelector('#askBridgeMic');
    const sendBtn = panel.querySelector('#askBridgeSend');

    // Keeps Bridge's chat context within this page visit (resets on reload,
    // same as this conversation would) so follow-ups like "say that again
    // with easier words" actually have something to refer back to.
    const history = [];
    const MAX_HISTORY_TURNS = 10; // user+assistant messages kept, trimmed oldest-first

    // Ask Bridge answers are text. As of 2026-11-05 each answer has a Listen button
    // (founder request) that reads it in Daniel's voice; nothing plays automatically. The mic button below is one-way, for
    // the kid's own spoken input only.
    function addMsg(cls, text) {
      const div = document.createElement('div');
      div.className = 'ab-msg ' + cls;
      const textSpan = document.createElement('span');
      textSpan.className = 'ab-text';
      textSpan.textContent = text;
      div.appendChild(textSpan);
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
      return div;
    }

    // Pronunciation practice for any word, including ones not covered by a
    // lesson plan — same pattern as the "🎤 Speak" button on the lesson
    // pages (type/say the word -> try saying it -> hear whether it
    // matched), just reused here so Bridge can help with words outside
    // the curriculum. Checked entirely on-device (no AI call, no voice
    // played back) — type the word in the box, then tap Speak and say it.
    const PRAISE = [
      "🌟 Wow, that sounded great!",
      "🎉 Yes! I heard you loud and clear!",
      "👏 Great speaking! You've got it!",
      "😊 Super! That was just right!",
    ];
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      micBtn.disabled = true;
      micBtn.title = "Your device can't listen for speech right now.";
    } else {
      micBtn.addEventListener('click', () => {
        const target = input.value.trim();
        if (!target) {
          addMsg('ab-a', 'Type a word or sentence first, then tap Speak so I can hear you try it!');
          input.focus();
          return;
        }
        const rec = new SR();
        rec.lang = 'en-US';
        micBtn.classList.add('listening');
        const stop = () => micBtn.classList.remove('listening');
        rec.onresult = (e) => {
          stop();
          const said = e.results[0][0].transcript;
          const heard = said.toLowerCase().replace(/[^a-z0-9 ]/g, '').trim();
          const wanted = target.toLowerCase().replace(/[^a-z0-9 ]/g, '').trim();
          if (heard.includes(wanted) || wanted.includes(heard)) {
            addMsg('ab-a', PRAISE[Math.floor(Math.random() * PRAISE.length)]);
          } else {
            addMsg('ab-a', 'Ooh, I heard “' + said + '”. That was a brave try! 💛 Let’s try “' + target + '” again whenever you’re ready — tap Speak!');
          }
        };
        rec.onerror = (e) => {
          stop();
          addMsg(
            'ab-a',
            e.error === 'not-allowed'
              ? "I can't use the microphone right now, and that's okay!"
              : "I didn't catch that — tap Speak and we'll try again. No rush!"
          );
        };
        rec.onend = stop;
        try { rec.start(); } catch (e) { stop(); }
      });
    }

    btn.addEventListener('click', () => {
      panel.classList.toggle('open');
      if (panel.classList.contains('open')) input.focus();
    });
    panel.querySelector('#askBridgeClose').addEventListener('click', () => {
      panel.classList.remove('open');
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q) return;
      addMsg('ab-q', q);
      input.value = '';
      input.disabled = true;
      micBtn.disabled = true;
      sendBtn.disabled = true;
      const thinking = document.createElement('div');
      thinking.className = 'ab-msg ab-a';
      thinking.textContent = 'Bridge is thinking…';
      log.appendChild(thinking);
      log.scrollTop = log.scrollHeight;

      let levelCtx = '';
      let topicCtx = '';
      try {
        const st = LB.get();
        levelCtx = st && st.level ? st.level : '';
      } catch (e) {}
      try {
        if (typeof C !== 'undefined' && C && C.topic && C.topic.name) topicCtx = C.topic.name;
      } catch (e) {}

      try {
        const res = await fetch(ASK_BRIDGE_API, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ question: q, level: levelCtx, lessonTopic: topicCtx, history }),
        });
        const data = await res.json().catch(() => ({}));
        thinking.remove();
        if (res.ok && data.answer) {
          const ansDiv = addMsg('ab-a', data.answer);
          // Listen button: reads the answer aloud in Daniel's voice when the student taps it (no auto-play).
          if (window.speechSynthesis) {
            const lb = document.createElement('button');
            lb.type = 'button'; lb.className = 'ab-listen'; lb.textContent = 'Listen';
            lb.style.cssText = 'margin-top:6px;border:1px solid #159FE8;background:#fff;color:#0B6FAE;border-radius:999px;padding:4px 12px;font:inherit;font-size:.8rem;font-weight:600;cursor:pointer;display:block';
            lb.addEventListener('click', function () { bridgeSpeak(data.answer, { voice: 'daniel' }); });
            ansDiv.appendChild(lb);
          }
          history.push({ role: 'user', content: q });
          history.push({ role: 'assistant', content: data.answer });
          while (history.length > MAX_HISTORY_TURNS) history.shift();
        } else {
          addMsg('ab-a', (data && data.error) || "Bridge couldn't answer that right now. Please try again!");
        }
      } catch (err) {
        thinking.remove();
        addMsg('ab-a', "Bridge couldn't connect right now. Please try again in a moment!");
      } finally {
        input.disabled = false;
        if (SR) micBtn.disabled = false;
        sendBtn.disabled = false;
        input.focus();
      }
    });
  }

  function init() {
    injectStyles();
    buildWidget();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();



/* ---------------------------------------------------------------------
   LOG OUT + clean device (2026-11-09). Logging out ends the session AND wipes the progress,
   role and timer copies kept in this browser, so the next person who logs in on the same
   device starts completely fresh and never inherits the founder's view or anyone's progress.
   A small "Log out" button is added to every lesson-flow page.
   --------------------------------------------------------------------- */
LB.wipeLocal=function(){try{[LB.KEY,LB.ROLE_KEY,'lb_active_v1'].forEach(k=>localStorage.removeItem(k));sessionStorage.clear()}catch(e){}};
LB.logout=function(){const go=()=>{LB.wipeLocal();location.replace('linguabridge-login-2.html')};
 try{fetch('https://api.lingua-bridge.us/api/logout',{method:'POST',credentials:'include'}).then(go,go)}catch(e){go()}};
(function(){
 function add(){
  if(/login|signup|index|homepage|about/.test(location.pathname)&&!/dashboard|lesson|badge|tomorrow/.test(location.pathname))return;
  if(document.getElementById('lbLogoutBtn'))return;
  const b=document.createElement('button');b.id='lbLogoutBtn';b.type='button';b.textContent='Log out';
  b.style.cssText='position:fixed;left:14px;bottom:14px;z-index:9998;background:#fff;color:#0B3B6B;border:2px solid #CFE8F8;border-radius:999px;padding:8px 16px;font:600 .85rem Lexend,sans-serif;cursor:pointer;box-shadow:0 4px 10px rgba(11,59,107,.15)';
  b.onclick=LB.logout;document.body.appendChild(b)}
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',add);else add()})();

/* ---------------------------------------------------------------------
   ACCOUNT PROGRESS SYNC (added 2026-11-05)
   Progress is still kept in localStorage (instant, works offline), and is now
   ALSO saved to the signed-in student's account (GET/POST /api/progress on the
   Worker) so it follows their login to any device and survives cleared browser
   data. Rules:
   - The local copy is tagged with `owner` (the username). If a different person
     signs in on the same device, the previous person's local copy is NOT merged
     into the new account -- the new account's saved progress is loaded instead.
   - Merging two copies of the same account = union of finished lessons.
   - If the server can't be reached (offline, or the Worker not updated yet),
     everything keeps working from the local copy and syncs later.
   --------------------------------------------------------------------- */
(function(){
 const API='https://api.lingua-bridge.us';
 let authed=false,timer=null,owner=null;
 function clean(s){return {level:s.level,completed:s.completed,voice:s.voice,quizHistory:s.quizHistory}}
 function key(c){return c.level+':'+c.n}
 function merge(a,b){ // union of finished lessons, earliest date wins
  const m={};(a.completed||[]).concat(b.completed||[]).forEach(c=>{if(!c||!c.level)return;const k=key(c);if(!m[k]||(c.date&&c.date<m[k].date))m[k]=c});
  const hist=(a.quizHistory||[]).concat(b.quizHistory||[]).filter((q,i,arr)=>arr.findIndex(z=>z.level===q.level&&z.n===q.n&&z.score===q.score)===i).slice(-30);
  return Object.assign({},b,a,{completed:Object.values(m),quizHistory:hist})}
 async function push(){
  if(!authed)return;
  try{await fetch(API+'/api/progress',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:clean(LB.get())}),keepalive:true})}catch(e){}}
 LB._dirty=function(){if(!authed)return;clearTimeout(timer);timer=setTimeout(push,1200)};
 LB.pushNow=push;
 /* founder-only "reset all progress": clears this account's saved copy too. */
 LB.resetAll=async function(){const st=LB.get();st.completed=[];st.quizHistory=[];delete st.justPassed;st.dayOffset=0;
  try{localStorage.setItem(LB.KEY,JSON.stringify(st))}catch(e){} await push()};
 async function run(){
  if(!window.LB_AUTH_PROMISE)return;
  let me;try{me=await window.LB_AUTH_PROMISE}catch(e){return}
  if(!me||!me.authenticated||!me.username)return;
  owner=me.username;authed=true;
  let local=LB.get(),before=JSON.stringify(clean(local));
  if(local.owner!==owner)local={level:'explorer',completed:[],dayOffset:0}; // someone else's leftovers on this device
  let server=null;
  try{const r=await fetch(API+'/api/progress',{credentials:'include'});if(r.ok){const j=await r.json();server=j&&j.data}else if(r.status===404){authed=false;return}}catch(e){authed=false;return}
  let merged=server?merge(local,{level:server.level,completed:server.completed||[],voice:server.voice,quizHistory:server.quizHistory||[]}):local;
  if(local.owner!==owner&&server){merged.level=server.level||merged.level;if(server.voice)merged.voice=server.voice}
  merged.owner=owner;
  try{localStorage.setItem(LB.KEY,JSON.stringify(Object.assign({level:'explorer',completed:[],dayOffset:0},merged)))}catch(e){}
  const after=JSON.stringify(clean(LB.get()));
  if(!server||after!==JSON.stringify(clean(server)))await push();
  if(after!==before){ // page already drew itself from the old copy: redraw once
   const last=+sessionStorage.getItem('lb_sync_reload')||0;
   if(Date.now()-last>15000){try{sessionStorage.setItem('lb_sync_reload',String(Date.now()))}catch(e){} location.reload()}}
 }
 window.addEventListener('pagehide',()=>{if(authed&&timer){clearTimeout(timer);push()}});
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
})();

/* ---------------------------------------------------------------------
   BRIDGE BREAK REMINDER (added 2026-11-05)
   With the one-lesson-per-day rule removed, Bridge gently checks in instead:
   after every 15 minutes of active learning (counted across all lesson-flow
   pages, only while the tab is visible, and not counting gaps of 10+ minutes
   away) a friendly pop-up asks whether to take a break or keep going.
   --------------------------------------------------------------------- */
(function(){
 const KEY='lb_active_v1',EVERY=15*60*1000,GAP=10*60*1000;
 function load(){try{return JSON.parse(localStorage.getItem(KEY))||{}}catch(e){return {}}}
 function save(o){try{localStorage.setItem(KEY,JSON.stringify(o))}catch(e){}}
 let shown=false;
 function overlay(html){const d=document.createElement('div');d.setAttribute('role','dialog');d.setAttribute('aria-modal','true');
  d.style.cssText='position:fixed;inset:0;background:rgba(11,59,107,.55);z-index:99999;display:flex;align-items:center;justify-content:center;padding:16px;font-family:inherit';
  d.innerHTML='<div style="background:#fff;border-radius:22px;max-width:420px;width:100%;padding:26px 22px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.25)">'+html+'</div>';
  document.body.appendChild(d);return d}
 function ask(mins){
  if(shown)return;shown=true;
  const d=overlay('<div style="font-size:2.4rem" aria-hidden="true">⏰</div><h2 style="margin:8px 0;color:#0B3B6B">You have been learning for '+mins+' minutes!</h2><p style="color:#445;line-height:1.6;margin:0 0 18px">Great job! This is Bridge checking in. Would you like to take a break, or keep going?</p><div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap"><button id="lbBrk" style="background:#159FE8;color:#fff;border:0;border-radius:999px;padding:12px 22px;font-size:1rem;font-weight:600;cursor:pointer">Take a break</button><button id="lbKeep" style="background:#EAF5FD;color:#0B3B6B;border:0;border-radius:999px;padding:12px 22px;font-size:1rem;font-weight:600;cursor:pointer">Keep going</button></div>');
  d.querySelector('#lbKeep').onclick=()=>{d.remove();shown=false};
  d.querySelector('#lbBrk').onclick=()=>{d.innerHTML='<div style="background:#fff;border-radius:22px;max-width:420px;width:100%;padding:26px 22px;text-align:center"><div style="font-size:2.4rem" aria-hidden="true">💧</div><h2 style="margin:8px 0;color:#0B3B6B">Good idea!</h2><p style="color:#445;line-height:1.6;margin:0 0 18px">Stretch, drink some water, and rest your eyes. Your progress is saved. Come back whenever you are ready.</p><a href="linguabridge-dashboard.html" style="display:inline-block;background:#159FE8;color:#fff;border-radius:999px;padding:12px 22px;font-weight:600;text-decoration:none">Back to My Learning</a> <button id="lbBack" style="background:#EAF5FD;color:#0B3B6B;border:0;border-radius:999px;padding:12px 22px;font-size:1rem;font-weight:600;cursor:pointer">I am ready again</button></div>';
   d.querySelector('#lbBack').onclick=()=>{d.remove();shown=false}}}
 function tick(){
  if(document.hidden)return;
  const now=Date.now(),a=load();
  if(a.last&&now-a.last<GAP){a.ms=(a.ms||0)+(now-a.last)}else{a.ms=a.last?0:(a.ms||0);if(a.last&&now-a.last>=GAP){a.ms=0;a.asked=0}}
  a.last=now;
  const due=Math.floor((a.ms||0)/EVERY);
  if(due>(a.asked||0)){a.asked=due;save(a);ask(due*15)}else save(a)}
 window.LB_breakTest=ask;
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>setInterval(tick,5000));else setInterval(tick,5000);
 document.addEventListener('visibilitychange',()=>{if(document.hidden){const a=load();a.last=0;save(a)}});
})();

/* ---------------------------------------------------------------------
   ADAPTIVE QUIZ DIFFICULTY (added 2026-11-05)
   Every quiz records how many questions were answered correctly on the first
   try (LB.get().quizHistory). When a student's recent quizzes go well, Bridge
   adds challenge questions built from the lesson's OWN words and sentences, so
   they are always grounded in what was taught:
     tier 1 (last 3 quizzes avg >= 85%):  +3 questions (4-choice meaning questions)
     tier 2 (last 5 quizzes avg >= 95%):  +5 questions (adds listen-and-type
                                           spelling and complete-the-line typing)
   Because challenge answers count toward the score, a student who finds them
   too hard drops back to the normal 5 on their own. Nothing is graded.
   --------------------------------------------------------------------- */
LB.tier=function(level){
 const h=(LB.get().quizHistory||[]).filter(q=>q.level===level&&q.total>0);
 const acc=a=>a.reduce((t,q)=>t+q.score/q.total,0)/a.length;
 const last5=h.slice(-5),last3=h.slice(-3);
 if(last5.length>=5&&acc(last5)>=0.95)return 2;
 if(last3.length>=3&&acc(last3)>=0.85)return 1;
 return 0};
LB.recordQuiz=function(level,n,score,total){
 const st=LB.get();st.quizHistory=(st.quizHistory||[]).filter(q=>!(q.level===level&&q.n===n)).concat([{level,n,score,total}]).slice(-30);LB.set(st)};
function LB_shuffle(a){a=a.slice();for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]]}return a}
/* Typed answer: sentence/prompt, an input, a hint after a miss, the answer shown after three misses. */
function LB_mountTyped(el,q,onCorrect){
 el.innerHTML='<p style="font-family:var(--font-head);font-size:1.3rem;color:var(--navy);margin:0 0 12px;line-height:1.4"></p><p class="muted" style="margin:0 0 12px;font-size:.95rem"></p><div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px"><button class="mini" type="button" style="display:none">Listen</button><input type="text" autocomplete="off" autocapitalize="none" spellcheck="false" aria-label="Type your answer" style="flex:1;min-width:160px;font-size:1.1rem;padding:12px 14px;border:2px solid #BFD9EE;border-radius:14px"><button class="btn btn-primary" type="button">Check</button></div><p class="feedback" aria-live="polite"></p>';
 const [pq,hint]=el.querySelectorAll('p'),inp=el.querySelector('input'),fb=el.querySelector('.feedback'),btns=el.querySelectorAll('button'),listen=btns[0],chk=btns[1];
 pq.textContent=q.q;hint.textContent=q.hint||'';
 if(q.say){listen.style.display='';listen.textContent='Listen';listen.onclick=()=>bridgeSpeak(q.say,{mode:'pronunciation'});setTimeout(()=>{try{bridgeSpeak(q.say,{mode:'pronunciation'})}catch(e){}},300)}
 let misses=0,done=false;const norm=x=>String(x).toLowerCase().replace(/[^a-z0-9]/g,'');
 function check(){if(done)return;const v=norm(inp.value);if(!v){inp.focus();return}
  if(v===norm(q.answer)){done=true;inp.disabled=true;chk.disabled=true;fb.className='feedback ok';fb.textContent='Yes! '+q.why;onCorrect()}
  else{misses++;el.dataset.missed='1';fb.className='feedback retry';
   if(misses>=3){done=true;inp.value=q.answer;inp.disabled=true;chk.disabled=true;fb.textContent='The answer is “'+q.answer+'”. '+q.why+' You can do it next time!';onCorrect()}
   else fb.textContent='Good try! '+(misses===1?('Hint: it starts with “'+q.answer[0]+'”.'):('Hint: it has '+q.answer.length+' letters and starts with “'+q.answer[0]+'”.'))+' Try again!'}}
 chk.onclick=check;inp.onkeydown=e=>{if(e.key==='Enter')check()};setTimeout(()=>{try{inp.focus()}catch(e){}},50)}

LB.challenge=function(level,n,tier){
 if(!tier)return [];
 const C=advFor(level,n);
 const items=[].concat(C.vocab1||[],C.vocab2||[]).filter(v=>v&&v[0]&&v[1]);
 (C.whenSayIt||[]).forEach(w=>{if(w&&w[0]&&w[1])items.push([w[0],w[1]])});
 let pool=items.slice();
 [n-1,n+1].forEach(k=>{if(k>=1&&k<=advCount(level)){const D=advFor(level,k);[].concat(D.vocab1||[],D.vocab2||[]).forEach(v=>{if(v&&v[0]&&v[1])pool.push(v)})}});
 const uniq=a=>{const o=[];a.forEach(v=>{if(!o.some(u=>u[0].toLowerCase()===v[0].toLowerCase()||u[1].toLowerCase()===v[1].toLowerCase()))o.push(v)});return o};
 const mine=uniq(items),all=uniq(items.concat(pool));
 const out=[];
 function choiceQ(v,reverse){
  const others=LB_shuffle(all.filter(u=>u!==v&&u[0].toLowerCase()!==v[0].toLowerCase()&&u[1].toLowerCase()!==v[1].toLowerCase())).slice(0,3);
  if(others.length<3)return null;
  const opts=LB_shuffle([v].concat(others));
  return reverse?
   {q:'Which word or phrase means “'+v[1]+'”?',options:opts.map(x=>x[0]),answer:opts.indexOf(v),why:'“'+v[0]+'” means “'+v[1]+'”.',wrong:opts.map(x=>x===v?null:'“'+x[0]+'” means “'+x[1]+'”.')}:
   {q:'What does “'+v[0]+'” mean?',options:opts.map(x=>x[1]),answer:opts.indexOf(v),why:'“'+v[0]+'” means “'+v[1]+'”.',wrong:opts.map(x=>x===v?null:'That is what “'+x[0]+'” means.')}}
 const shuffled=LB_shuffle(mine);
 const nChoice=tier===1?3:2;
 for(let i=0;i<shuffled.length&&out.length<nChoice;i++){const q=choiceQ(shuffled[i],i%2===1);if(q){q.kind='choice';out.push(q)}}
 if(tier>=2){
  // listen-and-type: single words only
  const singles=LB_shuffle(mine.filter(v=>/^[A-Za-z]{3,12}$/.test(v[0].trim())));
  for(let i=0;i<singles.length&&out.length<nChoice+1;i++){const v=singles[i];
   out.push({kind:'typed',q:'Listen, then type the word you hear.',say:v[0],hint:'Tap Listen to hear it again.',answer:v[0].toLowerCase(),why:'“'+v[0]+'” means “'+v[1]+'”.'})}
  // complete-the-line: blank one taught word in a conversation line
  const words=mine.map(v=>v[0].trim()).filter(w=>/^[A-Za-z]{3,12}$/.test(w));
  const lines=LB_shuffle((C.conversation||[]).map(c=>c[1]));
  for(let i=0;i<lines.length&&out.length<nChoice+3;i++){
   const line=lines[i],w=words.find(x=>new RegExp('\\b'+x+'\\b','i').test(line));
   if(!w)continue;const m=line.match(new RegExp('\\b'+w+'\\b','i'))[0];
   out.push({kind:'typed',q:'Type the missing word: '+line.replace(new RegExp('\\b'+w+'\\b','i'),'_____'),hint:'It starts with “'+m[0]+'” and has '+m.length+' letters.',answer:m.toLowerCase(),why:'The line is: “'+line+'”'})}
 }
 return out};
