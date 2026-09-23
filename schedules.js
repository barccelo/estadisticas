// ===== Módulo Horarios =====
const SCH_normal = s => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9 ]/g,' ').replace(/\s+/g,' ').trim();
const SCH_D = (dia, grado, disciplinas, categoria) => ({day: dia, grade: grado, disciplines: disciplinas, type: categoria || 'Deportes'});
const SCH_DAY_ORDER = ["Lunes","Martes","Miércoles","Jueves","Viernes","Sábado"];
const SCH_GRADE_ORDER = ["1er Grado","2do Grado","3er Grado","4to Grado","5to Grado","6to Grado","1er Año","2do Año","3er Año","4to Año","5to Año"];
function scheduleTodayName(){const dias=["Domingo","Lunes","Martes","Miércoles","Jueves","Viernes","Sábado"]; return dias[new Date().getDay()];}
const SCH_DATA = [
  // ===== CLUB DEPORTIVO · EDUCACIÓN BÁSICA PRIMARIA · PRIMERA ETAPA =====
  SCH_D('Lunes','1er Grado',["Béisbol","Futsal"]),
  SCH_D('Lunes','2do Grado',["Béisbol","Futsal"]),
  SCH_D('Lunes','3er Grado',["Ajedrez","Tenis"]),
  SCH_D('Martes','1er Grado',["Baloncesto"]),
  SCH_D('Martes','2do Grado',["Baloncesto"]),
  SCH_D('Martes','3er Grado',["Béisbol","Futsal"]),
  SCH_D('Miércoles','1er Grado',["Atletismo","Ajedrez"]),
  SCH_D('Miércoles','2do Grado',["Atletismo","Ajedrez"]),
  SCH_D('Miércoles','3er Grado',["Fútbol campo"]),
  SCH_D('Jueves','1er Grado',["Fútbol campo"]),
  SCH_D('Jueves','2do Grado',["Fútbol campo"]),
  SCH_D('Jueves','3er Grado',["Atletismo"]),
  SCH_D('Viernes','1er Grado',["Tenis"]),
  SCH_D('Viernes','2do Grado',["Tenis"]),
  SCH_D('Viernes','3er Grado',["Baloncesto"]),
  SCH_D('Sábado','1er Grado',["Encuentros deportivos"]),
  SCH_D('Sábado','2do Grado',["Encuentros deportivos"]),
  SCH_D('Sábado','3er Grado',["Encuentros deportivos"]),

  // ===== CLUB DEPORTIVO · EDUCACIÓN BÁSICA PRIMARIA · SEGUNDA ETAPA =====
  SCH_D('Lunes','4to Grado',["Ajedrez","Tenis"]),
  SCH_D('Lunes','5to Grado',["Atletismo"]),
  SCH_D('Lunes','6to Grado',["Atletismo"]),
  SCH_D('Martes','4to Grado',["Béisbol","Futsal"]),
  SCH_D('Martes','5to Grado',["Ajedrez","Tenis"]),
  SCH_D('Martes','6to Grado',["Ajedrez","Tenis"]),
  SCH_D('Miércoles','4to Grado',["Fútbol campo"]),
  SCH_D('Miércoles','5to Grado',["Béisbol","Futsal"]),
  SCH_D('Miércoles','6to Grado',["Béisbol","Futsal"]),
  SCH_D('Jueves','4to Grado',["Atletismo"]),
  SCH_D('Jueves','5to Grado',["Baloncesto"]),
  SCH_D('Jueves','6to Grado',["Baloncesto"]),
  SCH_D('Viernes','4to Grado',["Baloncesto"]),
  SCH_D('Viernes','5to Grado',["Fútbol campo"]),
  SCH_D('Viernes','6to Grado',["Fútbol campo"]),
  SCH_D('Sábado','4to Grado',["Encuentros deportivos"]),
  SCH_D('Sábado','5to Grado',["Encuentros deportivos"]),
  SCH_D('Sábado','6to Grado',["Encuentros deportivos"]),

  // ===== CLUB DEPORTIVO · EDUCACIÓN MEDIA GENERAL · 1ER–3ER AÑO =====
  SCH_D('Lunes','1er Año',["Baloncesto","Voleibol"]),
  SCH_D('Lunes','2do Año',["Baloncesto","Voleibol"]),
  SCH_D('Lunes','3er Año',["Fútbol campo"]),
  SCH_D('Martes','1er Año',["Atletismo","Fútbol campo"]),
  SCH_D('Martes','2do Año',["Atletismo","Fútbol campo"]),
  SCH_D('Martes','3er Año',["Voleibol"]),
  SCH_D('Miércoles','1er Año',["Tenis"]),
  SCH_D('Miércoles','2do Año',["Tenis"]),
  SCH_D('Miércoles','3er Año',["Baloncesto"]),
  SCH_D('Jueves','1er Año',["Futsal","Ajedrez"]),
  SCH_D('Jueves','2do Año',["Futsal","Ajedrez"]),
  SCH_D('Jueves','3er Año',["Béisbol","Voleibol","Tenis"]),
  SCH_D('Viernes','1er Año',["Béisbol"]),
  SCH_D('Viernes','2do Año',["Béisbol"]),
  SCH_D('Viernes','3er Año',["Atletismo","Futsal","Ajedrez"]),
  SCH_D('Sábado','1er Año',["Encuentros deportivos"]),
  SCH_D('Sábado','2do Año',["Encuentros deportivos"]),
  SCH_D('Sábado','3er Año',["Encuentros deportivos"]),

  // ===== CLUB DEPORTIVO · EDUCACIÓN MEDIA GENERAL · 4TO–5TO AÑO =====
  SCH_D('Lunes','4to Año',["Fútbol campo"]),
  SCH_D('Lunes','5to Año',["Fútbol campo"]),
  SCH_D('Martes','4to Año',["Voleibol"]),
  SCH_D('Martes','5to Año',["Voleibol"]),
  SCH_D('Miércoles','4to Año',["Baloncesto"]),
  SCH_D('Miércoles','5to Año',["Baloncesto"]),
  SCH_D('Jueves','4to Año',["Béisbol","Voleibol","Tenis"]),
  SCH_D('Jueves','5to Año',["Béisbol","Voleibol","Tenis"]),
  SCH_D('Viernes','4to Año',["Atletismo","Futsal","Ajedrez"]),
  SCH_D('Viernes','5to Año',["Atletismo","Futsal","Ajedrez"]),
  SCH_D('Sábado','4to Año',["Encuentros deportivos"]),
  SCH_D('Sábado','5to Año',["Encuentros deportivos"]),

  // ===== CLUB DE MÚSICA Y CIENCIAS · EDUCACIÓN PRIMARIA =====
  SCH_D('Lunes','1er Grado',["Iniciación musical","Robótica"],'Música y Ciencias'),
  SCH_D('Lunes','2do Grado',["Iniciación musical","Robótica"],'Música y Ciencias'),
  SCH_D('Martes','1er Grado',["Astronomía"],'Música y Ciencias'),
  SCH_D('Martes','2do Grado',["Astronomía"],'Música y Ciencias'),
  SCH_D('Martes','3er Grado',["Violín","Teclado","Robótica"],'Música y Ciencias'),
  SCH_D('Martes','4to Grado',["Violín","Teclado","Robótica"],'Música y Ciencias'),
  SCH_D('Martes','5to Grado',["Cuatro","Gaita","Teclado"],'Música y Ciencias'),
  SCH_D('Martes','6to Grado',["Cuatro","Gaita","Teclado"],'Música y Ciencias'),
  SCH_D('Miércoles','3er Grado',["Astronomía"],'Música y Ciencias'),
  SCH_D('Miércoles','4to Grado',["Astronomía"],'Música y Ciencias'),
  SCH_D('Miércoles','5to Grado',["Violín","Percusión","Robótica"],'Música y Ciencias'),
  SCH_D('Miércoles','6to Grado',["Violín","Percusión","Robótica"],'Música y Ciencias'),
  SCH_D('Jueves','1er Grado',["Gaita"],'Música y Ciencias'),
  SCH_D('Jueves','2do Grado',["Gaita"],'Música y Ciencias'),
  SCH_D('Jueves','3er Grado',["Gaita"],'Música y Ciencias'),
  SCH_D('Jueves','4to Grado',["Gaita"],'Música y Ciencias'),
  SCH_D('Jueves','5to Grado',["Guitarra acústica","Astronomía"],'Música y Ciencias'),
  SCH_D('Jueves','6to Grado',["Guitarra acústica","Astronomía"],'Música y Ciencias'),

  // ===== CLUB DE MÚSICA Y CIENCIAS · EDUCACIÓN MEDIA GENERAL =====
  SCH_D('Lunes','1er Año',["Astronomía"],'Música y Ciencias'),
  SCH_D('Lunes','2do Año',["Astronomía"],'Música y Ciencias'),
  SCH_D('Martes','1er Año',["Gaita"],'Música y Ciencias'),
  SCH_D('Martes','2do Año',["Gaita"],'Música y Ciencias'),
  SCH_D('Martes','3er Año',["Gaita"],'Música y Ciencias'),
  SCH_D('Martes','4to Año',["Gaita"],'Música y Ciencias'),
  SCH_D('Martes','5to Año',["Gaita"],'Música y Ciencias'),
  SCH_D('Miércoles','1er Año',["Percusión"],'Música y Ciencias'),
  SCH_D('Miércoles','2do Año',["Percusión"],'Música y Ciencias'),
  SCH_D('Miércoles','3er Año',["Percusión"],'Música y Ciencias'),
  SCH_D('Miércoles','4to Año',["Percusión"],'Música y Ciencias'),
  SCH_D('Miércoles','5to Año',["Percusión"],'Música y Ciencias'),
  SCH_D('Jueves','1er Año',["Violín","Guitarra acústica","Robótica"],'Música y Ciencias'),
  SCH_D('Jueves','2do Año',["Violín","Guitarra acústica","Robótica"],'Música y Ciencias'),
  SCH_D('Jueves','3er Año',["Guitarra acústica"],'Música y Ciencias'),
  SCH_D('Jueves','4to Año',["Guitarra acústica"],'Música y Ciencias'),
  SCH_D('Jueves','5to Año',["Guitarra acústica"],'Música y Ciencias'),
  SCH_D('Viernes','1er Año',["Teclado","Guitarra eléctrica","Bajo eléctrico","Ensamble musical"],'Música y Ciencias'),
  SCH_D('Viernes','2do Año',["Teclado","Guitarra eléctrica","Bajo eléctrico","Ensamble musical"],'Música y Ciencias'),
  SCH_D('Viernes','3er Año',["Violín","Teclado","Guitarra eléctrica","Bajo eléctrico","Ensamble musical","Astronomía","Robótica"],'Música y Ciencias'),
  SCH_D('Viernes','4to Año',["Violín","Teclado","Guitarra eléctrica","Bajo eléctrico","Ensamble musical","Astronomía","Robótica"],'Música y Ciencias'),
  SCH_D('Viernes','5to Año',["Violín","Teclado","Guitarra eléctrica","Bajo eléctrico","Ensamble musical","Astronomía","Robótica"],'Música y Ciencias'),
].flat();
let scheduleSelectedDay = '';
let scheduleSelectedGrade = '';
let scheduleSelectedDisc = '';
function scheduleButton(label, attr, value, active=false){return `<button class="schedule-chip ${active ? 'active' : ''}" type="button" ${attr}="${escapeHtml(value)}">${escapeHtml(label)}</button>`;}
function initScheduleModule(){
  const discBox=document.getElementById('scheduleDiscChips'), gradeBox=document.getElementById('scheduleGradeChips'), dayBox=document.getElementById('scheduleDayChips');
  if(!discBox || !gradeBox || !dayBox) return;
  const hot=["Fútbol campo","Baloncesto","Béisbol","Atletismo","Tenis","Ajedrez","Futsal","Voleibol","Robótica","Astronomía","Iniciación musical","Violín","Percusión","Cuatro","Gaita","Teclado","Guitarra acústica","Guitarra eléctrica","Bajo eléctrico","Ensamble musical"];
  discBox.innerHTML=hot.map(name=>scheduleButton(name,'data-sdisc',name)).join('');
  gradeBox.innerHTML=['Todos',...SCH_GRADE_ORDER].map((g,i)=>scheduleButton(g,'data-sgrade',g,i===0)).join('');
  const today=scheduleTodayName();
  const dayItems=['Todos','Hoy',...SCH_DAY_ORDER];
  dayBox.innerHTML=dayItems.map(d=>scheduleButton(d,'data-sday',d,d==='Todos')).join('');
  scheduleSelectedDay='';
  discBox.addEventListener('click', e=>{
    const b=e.target.closest('[data-sdisc]'); if(!b) return;
    const will=!b.classList.contains('active');
    discBox.querySelectorAll('.schedule-chip').forEach(c=>c.classList.remove('active'));
    scheduleSelectedDisc=will ? b.dataset.sdisc : '';
    if(will) b.classList.add('active');
    renderSchedule();
  });
  gradeBox.addEventListener('click', e=>{
    const b=e.target.closest('[data-sgrade]'); if(!b) return;
    const val=b.dataset.sgrade; const will=!b.classList.contains('active');
    gradeBox.querySelectorAll('.schedule-chip').forEach(c=>c.classList.remove('active'));
    scheduleSelectedGrade=(val==='Todos' || !will) ? '' : val;
    if(will) b.classList.add('active');
    if(!scheduleSelectedGrade){ const all=gradeBox.querySelector('[data-sgrade="Todos"]'); if(all) all.classList.add('active'); }
    renderSchedule();
  });
  dayBox.addEventListener('click', e=>{
    const b=e.target.closest('[data-sday]'); if(!b) return;
    const val=b.dataset.sday; const will=!b.classList.contains('active');
    dayBox.querySelectorAll('.schedule-chip').forEach(c=>c.classList.remove('active'));
    if(val==='Hoy' && will){scheduleSelectedDay=SCH_DAY_ORDER.includes(today)?today:''; b.classList.add('active');}
    else {scheduleSelectedDay=(val==='Todos'||!will)?'':val; if(will) b.classList.add('active');}
    if(!scheduleSelectedDay && (!will || val==='Todos')){ const all=dayBox.querySelector('[data-sday="Todos"]'); if(all) all.classList.add('active'); }
    renderSchedule();
  });
  const search=document.getElementById('scheduleSearch');
  if(search) search.addEventListener('input', renderSchedule);
  const reset=document.getElementById('scheduleResetBtn');
  if(reset) reset.addEventListener('click', resetScheduleFilters);
  renderSchedule();
}
function resetScheduleFilters(){
  scheduleSelectedDay=scheduleSelectedGrade=scheduleSelectedDisc='';
  const search=document.getElementById('scheduleSearch'); if(search) search.value='';
  document.querySelectorAll('#view-horarios .schedule-chip').forEach(c=>c.classList.remove('active'));
  const gAll=document.querySelector('#scheduleGradeChips [data-sgrade="Todos"]'); if(gAll) gAll.classList.add('active');
  const dAll=document.querySelector('#scheduleDayChips [data-sday="Todos"]'); if(dAll) dAll.classList.add('active');
  renderSchedule();
}
function renderSchedule(){
  const results=document.getElementById('scheduleResults'); const empty=document.getElementById('scheduleEmpty'); const search=document.getElementById('scheduleSearch');
  if(!results || !empty) return;
  const qText=SCH_normal(search ? search.value : '');
  const filtered=SCH_DATA.filter(row=>{
    const okDay=!scheduleSelectedDay || row.day===scheduleSelectedDay;
    const okGrade=!scheduleSelectedGrade || row.grade===scheduleSelectedGrade;
    const okDisc=!scheduleSelectedDisc || row.disciplines.includes(scheduleSelectedDisc);
    const searchable=SCH_normal(`${row.day} ${row.grade} ${row.type} ${row.disciplines.join(' ')}`);
    const okText=!qText || searchable.includes(qText);
    return okDay && okGrade && okDisc && okText;
  });
  const groups=new Map();
  for(const row of filtered){
    if(!groups.has(row.grade)) groups.set(row.grade,new Map());
    const byDay=groups.get(row.grade);
    if(!byDay.has(row.day)) byDay.set(row.day,new Set());
    row.disciplines.forEach(d=>byDay.get(row.day).add(d));
  }
  results.innerHTML='';
  const gradesSorted=Array.from(groups.keys()).sort((a,b)=>SCH_GRADE_ORDER.indexOf(a)-SCH_GRADE_ORDER.indexOf(b));
  gradesSorted.forEach(grade=>{
    const byDay=groups.get(grade);
    const daysSorted=Array.from(byDay.keys()).sort((a,b)=>SCH_DAY_ORDER.indexOf(a)-SCH_DAY_ORDER.indexOf(b));
    const card=document.createElement('article'); card.className='schedule-card-item';
    const dayBlocks=daysSorted.map(day=>{
      const disc=Array.from(byDay.get(day)).sort((a,b)=>a.localeCompare(b,'es',{numeric:true}));
      return `<span class="schedule-day">${escapeHtml(day)}</span><div class="schedule-tags">${disc.map(d=>`<button class="schedule-tag" type="button" data-schedule-d="${escapeHtml(d)}">${escapeHtml(d)}</button>`).join('')}</div>`;
    }).join('');
    card.innerHTML=`<h3>${escapeHtml(grade)}</h3>${dayBlocks}`;
    card.addEventListener('click', e=>{
      const t=e.target.closest('[data-schedule-d]'); if(!t) return;
      scheduleSelectedDisc=t.dataset.scheduleD;
      document.querySelectorAll('#scheduleDiscChips .schedule-chip').forEach(c=>c.classList.toggle('active', c.dataset.sdisc===scheduleSelectedDisc));
      renderSchedule();
    });
    results.appendChild(card);
  });
  empty.hidden=gradesSorted.length!==0;
}
initScheduleModule();
