
/* Bridge music (2026-11-15): a short happy tune made with the Web Audio API (no audio files). Plays when Bridge is tapped. */
var _ac=null,_tune=0;
function bridgeTune(){try{
 var AC=window.AudioContext||window.webkitAudioContext;if(!AC)return;_ac=_ac||new AC();if(_ac.state==='suspended')_ac.resume();
 var tunes=[[0,2,4,7,4,7,9,7],[7,9,7,4,2,4,0,4],[0,4,7,9,7,4,9,12],[4,4,7,9,7,4,2,0]];
 var seq=tunes[_tune++%tunes.length],root=262,t=_ac.currentTime+.03,step=.19;
 var master=_ac.createGain();master.gain.value=.22;master.connect(_ac.destination);
 seq.forEach(function(n,i){var f=root*Math.pow(2,n/12);
  [['triangle',1,.5],['sine',2,.18]].forEach(function(v){var o=_ac.createOscillator(),g=_ac.createGain();o.type=v[0];o.frequency.value=f*v[1];
   var st=t+i*step;g.gain.setValueAtTime(0,st);g.gain.linearRampToValueAtTime(v[2],st+.02);g.gain.exponentialRampToValueAtTime(.001,st+step*1.5);
   o.connect(g);g.connect(master);o.start(st);o.stop(st+step*1.6)})});
 /* soft bouncy bass on beats 1 and 5 */
 [0,4].forEach(function(i){var o=_ac.createOscillator(),g=_ac.createGain();o.type='sine';o.frequency.value=root/2;var st=t+i*step;
  g.gain.setValueAtTime(0,st);g.gain.linearRampToValueAtTime(.45,st+.02);g.gain.exponentialRampToValueAtTime(.001,st+step*3.5);o.connect(g);g.connect(master);o.start(st);o.stop(st+step*3.6)})
}catch(e){}}
(function(){var m=document.getElementById('bridgeMascot'),b=document.getElementById('bridgeBubble');if(!m)return;
var say=["Hello! Welcome!","Great job! Ready to learn?","Let's learn English together!","Hi there! I'm Bridge!"],k=0,cols=['#FF7A59','#FFC83D','#159FE8','#12A15A','#8B6BFF'];
function pop(){bridgeTune();m.classList.remove('hop');void m.getBoundingClientRect();m.classList.add('hop');if(b)b.textContent=say[k++%say.length];
 var r=m.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/3;
 for(var i=0;i<26;i++){var e=document.createElement('span');e.className='fun-bit';e.style.left=x+'px';e.style.top=y+'px';e.style.background=cols[i%5];
  e.style.setProperty('--dx',(Math.random()*340-170)+'px');e.style.setProperty('--dy',(Math.random()*-200-20)+'px');e.style.setProperty('--r',(Math.random()*700-350)+'deg');document.body.appendChild(e);setTimeout(function(n){n.remove()},1200,e)}}
m.addEventListener('click',pop);m.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();pop()}});})();
