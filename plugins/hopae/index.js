// Trusted native-style Hangang console package; credentials stay in the host broker.
export async function mount(host) {
  const root=host.root, ko=()=>host.locale()==='ko', unified=host.authentication==='hangang';
  let paused=false, disposed=false, busy=false, canWrite=false, view='status', cursor=null, next=null, history=[];
  let generation=0, resumePending=false;
  const drafts=new Map();
  const scrub=()=>{for(const d of drafts.values()){d.text='';d.original='';d.latest=null;d.message='';}drafts.clear();content.querySelectorAll('textarea').forEach(e=>e.value='');for(const element of localized.keys())if(content.contains(element))localized.delete(element);};
  const label=(en,kr)=>ko()?kr:en;
  const localized=new Map();let localeScheduled=false;
  function refreshLocale(){if(disposed)return;for(const [element,renderers] of localized){if(!root.contains(element))localized.delete(element);else for(const render of renderers)render();}}
  function localize(element,render){const renders=localized.get(element)||[];renders.push(render);localized.set(element,renders);render();if(!localeScheduled){localeScheduled=true;queueMicrotask(()=>{localeScheduled=false;refreshLocale();});}}
  const node=(tag,text,cls)=>{const e=document.createElement(tag);if(typeof text==='function')localize(e,()=>{e.textContent=text();});else if(text!==undefined)e.textContent=text;if(tag==='button')e.className='button button-secondary';if(cls)e.className=cls;return e;};
  const stopLocale=host.onLocaleChange?.(refreshLocale)||(()=>{});
  root.classList.add('hopae-console');
  const login=node('a',()=>label('Sign in to Hopae','Hopae 로그인'));login.href='/_hopae/login?return=%2Fui%2F';login.className='button button-primary';
  const logout=node('a',()=>label('Sign out of Hopae','Hopae 로그아웃'));logout.href='/_hopae/logout?return=%2Fui%2F';logout.className='button button-quiet';logout.hidden=true;
  const tabs=node('div',undefined,'hopae-toolbar'), notice=node('p',undefined,'muted'), error=node('p',undefined,'error'), content=node('div'), pager=node('div',undefined,'hopae-toolbar');
  const previous=node('button',()=>label('Previous','이전')), more=node('button',()=>label('Next','다음')), refresh=node('button',()=>label('Refresh','새로고침'));
  for(const [key,en,kr] of [['status','Status','상태'],['users','Users','사용자'],['sessions','Sessions','세션'],['events','Events','이벤트'],['profiles','Authentication profiles','인증 프로필'],['projections','Credential projection','자격 변환']]){
    const b=node('button',()=>label(en,kr));b.dataset.tab=key;b.onclick=()=>{if(busy)return;view=key;cursor=null;history=[];load();};tabs.append(b);
  }
  refresh.onclick=()=>load();tabs.append(refresh);
  localize(notice,()=>{notice.textContent=unified?label('Managed with your Hangang administrator session.','Hangang 관리자 세션으로 관리합니다.'):label('Manage identities, sessions and security events.','사용자·세션·보안 이벤트를 관리합니다.');});
  previous.onclick=()=>{if(!busy&&history.length){cursor=history.pop();load();}};
  more.onclick=()=>{if(!busy&&next){history.push(cursor);cursor=next;load();}};pager.append(previous,more);pager.hidden=true;previous.disabled=true;more.disabled=true;
  const sessionActions=node('div',undefined,'hopae-toolbar');sessionActions.append(login,logout);
  sessionActions.hidden=unified;

  root.replaceChildren(tabs,notice,sessionActions,error,content,pager);
  const show=(v)=>typeof v==='function'?show(v()):v==null?'—':typeof v==='object'?JSON.stringify(v):String(v);
  async function mutate(path,id){
    if(busy||disposed||paused||!canWrite)return;
    if(!window.confirm(label('Apply this Hopae management change?','이 Hopae 관리 변경을 적용합니까?')))return;
    busy=true;error.textContent='';let applied=false;
    try{await host.api(path,{method:'POST',json:{id}});applied=true;}catch(e){if(!disposed)error.textContent=e.message;}finally{busy=false;}
    if(applied&&!disposed&&!paused)await load();
  }
  function table(items){
    const columns=view==='users'?['user_id','human_subject','primary_email','username','display_name','status','role']:view==='sessions'?['session_id','user_id','provider_id','aal','auth_time']:['event_id','kind','outcome','reason','user_id','request_id'];
    const t=node('table'), head=node('thead'), row=node('tr');for(const c of columns)row.append(node('th',c==='human_subject'?()=>label('Human policy subject','사람 권한 주체'):c));if(view!=='events')row.append(node('th',()=>label('Actions','작업')));head.append(row);t.append(head);const body=node('tbody');
    for(const item of items){const data=item.user??item.session??item, tr=node('tr');for(const c of columns)tr.append(node('td',show(data[c]??item[c])));
      if(view!=='events'){const td=node('td'), id=view==='users'?data.user_id:data.session_id;
        const actions=view==='users'?[[()=>label('Disable','비활성화'),'users/disable'],[()=>label('Enable','활성화'),'users/enable'],[()=>label('End sessions','세션 회수'),'users/sessions-terminate']]:[[()=>label('Terminate','회수'),'sessions/terminate']];
        for(const [name,path] of actions){const b=node('button',name);b.disabled=!canWrite||typeof id!=='string';b.onclick=()=>mutate(path,id);td.append(b);}tr.append(td);
      }body.append(tr);
    }t.append(body);return t;
  }
  const validRevision=value=>Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0);
  const canAdvance=value=>validRevision(value)&&Number.isSafeInteger(value+1);
  // Drafts stay in this mounted administrator session only; never browser storage.
  function bindDraft(key,data,editor,save,summarize){
    const fresh=JSON.stringify(data.configuration??null,null,2);
    if(!canWrite){editor.value=fresh;editor.disabled=true;save.disabled=true;return [];}
    let d=drafts.get(key);
    if(!d){d={text:fresh,base:data.revision,original:fresh,latest:data,message:'',needsReconcile:false};drafts.set(key,d);}
    d.latest=data;if(d.needsReconcile)d.message='';d.needsReconcile=false;
    if(d.text===d.original){d.text=fresh;d.original=fresh;d.base=data.revision;}
    editor.value=d.text;editor.disabled=!canWrite;
    let publishing=false;
    const state=node('p');state.setAttribute('role','status');
    const discard=node('button',()=>label('Discard draft and use latest revision','초안을 버리고 최신 리비전 사용'));
    const stateCopy=()=>publishing?label('Publishing…','게시 중…'):(d.message?show(d.message)+' · ':'')+label('Base revision: ','기준 리비전: ')+show(d.base)+(d.text!==d.original?label(' · Unsaved draft',' · 저장하지 않은 초안'):'')+(d.base!==d.latest.revision?label(' · Conflict: server revision ',' · 충돌: 서버 리비전 ')+show(d.latest.revision):'');
    localize(state,()=>{state.textContent=stateCopy();});
    const update=()=>{if(!drafts.has(key)){editor.value='';editor.disabled=true;save.disabled=true;discard.disabled=true;return;}const dirty=d.text!==d.original, conflict=d.base!==d.latest.revision;
      state.textContent=stateCopy();
      discard.disabled=publishing||!canWrite||d.needsReconcile||(!dirty&&!conflict);save.disabled=publishing||!canWrite||d.needsReconcile||conflict||!canAdvance(d.base);};
    const preview=()=>{try{summarize(JSON.parse(editor.value));}catch{summarize(undefined);}};
    preview();update();
    editor.oninput=()=>{d.text=editor.value;d.message='';preview();update();};
    discard.onclick=()=>{if(busy||!canWrite||d.needsReconcile||!window.confirm(label('Discard this unsaved draft?','저장하지 않은 초안을 버릴까요?')))return;
      d.text=JSON.stringify(d.latest.configuration??null,null,2);d.original=d.text;d.base=d.latest.revision;d.message='';editor.value=d.text;preview();update();};
    save.onclick=async()=>{
      if(busy||disposed||paused||!canWrite||d.needsReconcile||d.base!==d.latest.revision||!canAdvance(d.base))return;
      let configuration;try{configuration=JSON.parse(d.text);}catch(e){d.message=e.message;update();return;}
      const submitted=d.text,base=d.base,epoch=generation;
      if(key==='projections'&&configuration&&typeof configuration==='object'&&!Array.isArray(configuration))configuration.revision=base+1;
      busy=true;publishing=true;editor.disabled=true;save.disabled=true;discard.disabled=true;refresh.disabled=true;
      state.textContent=label('Publishing…','게시 중…');
      try{
        const {data:result}=await host.api('authentication/'+key+'/publish',{method:'POST',json:{revision:base,configuration}});
        if(disposed||epoch!==generation)return;
        if(!validRevision(result?.revision)||result.revision!==base+1)throw Error(label('Invalid publication acknowledgement revision.','게시 확인 리비전이 올바르지 않습니다.'));
        // Even synthetic input during publication cannot be replaced by the response.
        d.original=submitted;
        d.base=result.revision;d.latest={revision:d.base,configuration};
        const savedRevision=d.base;d.message=()=>label('Saved revision: ','저장한 리비전: ')+show(savedRevision);
      }catch(e){d.needsReconcile=true;if(e.status===401||e.status===403){canWrite=false;scrub();}if(!disposed&&epoch===generation)d.message=()=>(e.status===409?label('Revision conflict; refresh to compare with the latest revision. Draft retained. ','리비전 충돌: 새로고침하여 최신 리비전과 비교하세요. 초안을 보존했습니다. '):label('Publication failed or outcome unknown; refresh to reconcile. Draft retained. ','게시 실패 또는 결과 불명: 새로고침으로 확인하세요. 초안을 보존했습니다. '))+e.message;}
      finally{busy=false;publishing=false;if(!disposed&&!paused){editor.disabled=!canWrite;refresh.disabled=false;update();if(resumePending){resumePending=false;load();}}}
    };
    return [state,discard];
  }
  async function load(){
    if(busy||disposed||paused)return;const epoch=++generation;busy=true;refresh.disabled=true;error.textContent='';
    try{
      const {data:me}=await host.api('me');if(disposed||paused||epoch!==generation)return;canWrite=me.role==='admin';login.hidden=true;logout.hidden=false;if(!canWrite)scrub();
      const {data}=await host.api(view==='projections'?'authentication/projections':view==='profiles'?'authentication/profiles':view==='status'?'status':view+'/query',(view==='status'||view==='profiles'||view==='projections')?{}:{method:'POST',json:{cursor,limit:50}});
      if(disposed||paused||epoch!==generation)return;
      if((view==='profiles'||view==='projections')&&!validRevision(data?.revision))throw Error(label('Invalid configuration revision; refresh to reconcile.','설정 리비전이 올바르지 않습니다. 새로고침으로 확인하세요.'));
      content.replaceChildren();
      if(view==='projections'){
        const summary=node('div');
        const summarize=(configuration)=>{
          summary.replaceChildren();
          if(configuration===undefined){summary.append(node('p',()=>label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));return;}
          if(configuration==null){summary.append(node('p',()=>label('Credential projection is disabled.','자격 변환이 비활성 상태입니다.')));return;}
          if(!Array.isArray(configuration.plans)){summary.append(node('p',()=>label('No preview; the server validates the configuration.','미리보기가 없습니다. 서버가 설정을 검증합니다.')));return;}
          const table=node('table'),head=node('tr'),body=node('tbody');
          for(const title of [()=>label('Service','서비스'),()=>label('Audience','대상'),()=>label('Resource','자원'),()=>label('Action','행위'),()=>label('Minimum AAL','최소 AAL'),()=>label('Credential','자격 방식'),()=>label('Reference','참조')])head.append(node('th',title));
          const thead=node('thead');thead.append(head);table.append(thead);
          for(const plan of configuration.plans){
            if(!plan||typeof plan!=='object')continue;
            const row=node('tr');
            for(const value of [plan.service,plan.audience,plan.resource,plan.action,plan.minimum_aal,plan.credential?.type,plan.credential?.secret_ref])row.append(node('td',()=>show(value)));
            body.append(row);
          }table.append(body);summary.append(table);
        };
        const editor=node('textarea');editor.rows=20;editor.maxLength=65536;localize(editor,()=>editor.setAttribute('aria-label',label('Credential projection configuration','자격 변환 설정')));editor.value=JSON.stringify(data.configuration??null,null,2);editor.disabled=!canWrite;
        summarize(data.configuration??null);
        editor.oninput=()=>{try{summarize(JSON.parse(editor.value));}catch{summary.replaceChildren(node('p',()=>label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));}};
        const save=node('button',()=>label('Save projection plans','변환 설정 저장'));save.disabled=!canWrite;
        const draftControls=bindDraft('projections',data,editor,save,summarize);
        content.append(node('p',()=>label('Revision: ','Revision: ')+show(data.revision)),node('p',()=>label('Configure service credential conversion using declared references. Enter no passwords or token values. Set null to disable; saving replaces all plans.','선언된 참조로 서비스 자격 변환을 설정합니다. 비밀번호·토큰 값을 입력하지 마세요. null은 비활성화이며 저장하면 전체 설정을 교체합니다.')),node('p',()=>label('Only declared credential references are accepted. Assurance requirements cannot be lowered. Saving these settings alone does not enable credential delivery.','등록된 자격 참조만 사용할 수 있고 최소 인증 수준을 낮출 수 없습니다. 설정 저장만으로 자격 전달이 활성화되지는 않습니다.')),summary,editor,save,...draftControls);next=null;
      }
      else if(view==='profiles'){
        const help=node('p',()=>label('Edit service authentication profiles. Use declared credential references; enter no passwords or token values. Saving replaces the complete profile configuration.','서비스 인증 프로필을 편집합니다. 선언된 자격 정보 참조를 사용하고 비밀번호·토큰 값을 입력하지 마세요. 저장하면 프로필 설정 전체를 교체합니다.'));
        const routing=node('p',()=>label('Active profiles come from the database; startup JSON only bootstraps an empty authority. Mixed native keys and relay require relay_token_prefix (for example partner:), which is removed once before forwarding. Keep it when retiring keys. Use a distinct relay issuer. Lua conditions restrict verified identities and grant no permissions.','활성 프로필은 DB가 소유하며 시작 JSON은 비어 있는 authority만 초기화합니다. 자체 key·relay 혼합에는 relay_token_prefix(예: partner:)가 필요하며 전달 시 하나를 제거합니다. key 회수 후에도 유지하고 다른 relay issuer를 사용하세요. Lua 조건은 검증된 신원을 제한하며 권한을 부여하지 않습니다.'));
        const expiry=node('p',()=>label('API key expires_at is an absolute Unix timestamp in milliseconds, not seconds. Expired keys are refused immediately; omit expires_at for no configured expiry.','API key의 expires_at은 초가 아닌 Unix 밀리초 절대 시각입니다. 만료된 key는 즉시 거부하며, 설정 만료가 없으면 expires_at을 생략합니다.'));
        const summary=node('div');
        const summarize=(configuration)=>{
          summary.replaceChildren();
          if(configuration===undefined){summary.append(node('p',()=>label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));return;}
          if(configuration==null){summary.append(node('p',()=>label('Service authentication is disabled.','서비스 인증이 비활성 상태입니다.')));return;}
          if(!Array.isArray(configuration.profiles)){summary.append(node('p',()=>label('No preview; the server validates the configuration.','미리보기가 없습니다. 서버가 설정을 검증합니다.')));return;}
          const t=node('table'),head=node('thead'),tr=node('tr');
          for(const title of [()=>label('Service','서비스'),()=>label('Realm','Realm'),()=>label('Methods','인증수단'),()=>label('Issuers','Issuer'),()=>label('Relay prefix','Relay 접두사'),()=>label('Lua condition','Lua 조건'),()=>label('Session fallback','Session 대체'),()=>label('Kubernetes scope','Kubernetes 범위')])tr.append(node('th',title));
          head.append(tr);t.append(head);const body=node('tbody');
          for(const profile of configuration.profiles){
            if(!profile||typeof profile!=='object')continue;
            const count=Array.isArray(profile.api_keys)?profile.api_keys.length:0,relay=profile.api_relay,kubernetes=profile.kubernetes_tokenreview,row=node('tr');
            const methods=()=>[count?label('Native keys: ','자체 key: ')+count:null,relay?'API relay':null,kubernetes?'Kubernetes TokenReview':null].filter(Boolean).join(' + ');
            const issuers=[count?'hopae:'+show(configuration.authority_id):null,relay?show(relay.issuer):null,kubernetes?show(kubernetes.connection?.issuer):null].filter(Boolean).join(' / ');
            for(const value of [profile.service_id,profile.realm,methods,issuers,profile.relay_token_prefix,()=>profile.eligibility_lua?label('Enabled','활성'):label('None','없음'),()=>profile.session_fallback?label('Missing credential only','자격 미제시만'):label('Disabled','비활성'),()=>kubernetes?[show(kubernetes.connection?.cluster_id),show(kubernetes.connection?.audience),Array.isArray(kubernetes.connection?.namespaces)?kubernetes.connection.namespaces.map(show).join(', '):label('Namespace required','Namespace 필요'),show(kubernetes.token_prefix)].join(' / '):null])row.append(node('td',()=>show(value)));
            body.append(row);
          }t.append(body);summary.append(t);
        };
        const editor=node('textarea');editor.rows=20;editor.maxLength=65536;localize(editor,()=>editor.setAttribute('aria-label',label('Authentication profile configuration','인증 프로필 설정')));editor.value=JSON.stringify(data.configuration??null,null,2);editor.disabled=!canWrite;
        summarize(data.configuration??null);
        editor.oninput=()=>{try{summarize(JSON.parse(editor.value));}catch{summary.replaceChildren(node('p',()=>label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));}};
        const save=node('button',()=>label('Save profiles','프로필 저장'));save.disabled=!canWrite;
        const draftControls=bindDraft('profiles',data,editor,save,summarize);
        content.append(node('p',()=>label('Revision: ','Revision: ')+show(data.revision)),help,routing,expiry,summary,editor,save,...draftControls);next=null;
      }
      else if(view==='status'){
        const grid=node('div',undefined,'hopae-metrics');
        for(const [name,value] of [[()=>label('Users','사용자'),data.store?.users],[()=>label('Live sessions','활성 세션'),data.store?.live_sessions],[()=>label('Events','이벤트'),data.store?.events],[()=>label('Providers','프로바이더'),data.providers?.length]]){
          const card=node('div',undefined,'panel hopae-metric');card.append(node('span',name,'muted'),node('strong',show(value)));grid.append(card);
        }content.append(grid);
        const heading=node('h2',()=>label('Providers','프로바이더')),providerTable=node('table'),head=node('tr');for(const title of ['provider_id','kind','enabled','health'])head.append(node('th',title));providerTable.append(head);
        for(const provider of data.providers??[]){const row=node('tr');for(const key of ['provider_id','kind','enabled','health'])row.append(node('td',show(provider[key])));providerTable.append(row);}content.append(heading,providerTable);
        const circuits=node('table'),circuitHead=node('tr');
        for(const title of ['service_id','connector','circuit','available_capacity'])circuitHead.append(node('th',title));circuits.append(circuitHead);
        for(const connector of data.authentication_gateway?.connectors??[]){const row=node('tr');for(const key of ['service_id','connector','circuit','available_capacity'])row.append(node('td',show(connector[key])));circuits.append(row);}
        content.append(node('h2',()=>label('Service authentication circuits','서비스 인증 서킷')),node('p',()=>label('Observed at last refresh. An open circuit refuses external authentication; this view does not reset circuits.','마지막 새로고침 시점의 상태입니다. 열린 서킷은 외부 인증을 거부하며 이 화면은 서킷을 초기화하지 않습니다.')),circuits);

        const details=node('details'),summary=node('summary',()=>label('Runtime details','런타임 상세'));details.append(summary,node('pre',JSON.stringify(data,null,2)));content.append(details);next=null;
      }
      else {content.append(table(Array.isArray(data.items)?data.items:[]));next=data.next_cursor??null;if(!data.items?.length)content.append(node('p',()=>label('No records','조회 결과 없음')));}
      for(const tab of tabs.querySelectorAll('[data-tab]'))tab.classList.toggle('button-primary',tab.dataset.tab===view);
      pager.hidden=view==='status'||view==='profiles'||view==='projections';previous.disabled=!history.length;more.disabled=!next;
    }catch(e){if(!disposed&&!paused){canWrite=false;if(e.status===401||e.status===403)scrub();login.hidden=unified;content.querySelectorAll('button').forEach(b=>b.disabled=true);error.textContent=e.message;}}finally{busy=false;refresh.disabled=false;if(resumePending&&!disposed&&!paused){resumePending=false;load();}}
  }
  const timer=setInterval(()=>{if(view==='status')load();},30000);host.signal.addEventListener('abort',()=>{disposed=true;generation++;scrub();stopLocale();localized.clear();clearInterval(timer);root.replaceChildren();},{once:true});
  await load();
  return {pause(){paused=true;},resume(){paused=false;if(busy)resumePending=true;else load();},dispose(){disposed=true;generation++;scrub();stopLocale();localized.clear();clearInterval(timer);root.replaceChildren();}};
}
