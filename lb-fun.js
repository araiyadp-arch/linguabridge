(function(){var m=document.getElementById('bridgeMascot'),b=document.getElementById('bridgeBubble');if(!m)return;
var say=["Hello! Welcome!","Great job! Ready to learn?","Let's learn English together!","Hi there! I'm Bridge!"],k=0,cols=['#FF7A59','#FFC83D','#159FE8','#12A15A','#8B6BFF'];
function pop(){m.classList.remove('hop');void m.getBoundingClientRect();m.classList.add('hop');if(b)b.textContent=say[k++%say.length];
 var r=m.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/3;
 for(var i=0;i<26;i++){var e=document.createElement('span');e.className='fun-bit';e.style.left=x+'px';e.style.top=y+'px';e.style.background=cols[i%5];
  e.style.setProperty('--dx',(Math.random()*340-170)+'px');e.style.setProperty('--dy',(Math.random()*-200-20)+'px');e.style.setProperty('--r',(Math.random()*700-350)+'deg');document.body.appendChild(e);setTimeout(function(n){n.remove()},1200,e)}}
m.addEventListener('click',pop);m.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();pop()}});})();
