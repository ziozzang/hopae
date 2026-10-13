// Trusted native-style Hangang console package; credentials stay in the host broker.
export async function mount(host) {
  const root=host.root, ko=()=>host.locale()==='ko', unified=host.authentication==='hangang';
  let paused=false, disposed=false, busy=false, canWrite=false, view='status', cursor=null, next=null, history=[];
  const label=(en,kr)=>ko()?kr:en;
  const node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(tag==='button')e.className='button button-secondary';if(cls)e.className=cls;return e;};
  root.classList.add('hopae-console');
  const login=node('a',label('Sign in to Hopae','Hopae 로그인'));login.href='/_hopae/login?return=%2Fui%2F';login.className='button button-primary';
  const logout=node('a',label('Sign out of Hopae','Hopae 로그아웃'));logout.href='/_hopae/logout?return=%2Fui%2F';logout.className='button button-quiet';logout.hidden=true;
  const tabs=node('div',undefined,'hopae-toolbar'), notice=node('p',undefined,'muted'), error=node('p',undefined,'error'), content=node('div'), pager=node('div',undefined,'hopae-toolbar');
  const previous=node('button',label('Previous','이전')), more=node('button',label('Next','다음')), refresh=node('button',label('Refresh','새로고침'));
  for(const [key,en,kr] of [['status','Status','상태'],['users','Users','사용자'],['sessions','Sessions','세션'],['events','Events','이벤트'],['profiles','Authentication profiles','인증 프로필'],['projections','Credential projection','자격 변환']]){
    const b=node('button',label(en,kr));b.dataset.tab=key;b.onclick=()=>{if(busy)return;view=key;cursor=null;history=[];load();};tabs.append(b);
  }
  refresh.onclick=()=>load();tabs.append(refresh);
  notice.textContent=label('Manage identities, sessions and security events.','사용자·세션·보안 이벤트를 관리합니다.');
  previous.onclick=()=>{if(!busy&&history.length){cursor=history.pop();load();}};
  more.onclick=()=>{if(!busy&&next){history.push(cursor);cursor=next;load();}};pager.append(previous,more);pager.hidden=true;previous.disabled=true;more.disabled=true;
  const sessionActions=node('div',undefined,'hopae-toolbar');sessionActions.append(login,logout);
  sessionActions.hidden=unified;
  if(unified)notice.textContent=label("Managed with your Hangang administrator session.","Hangang 관리자 세션으로 관리합니다.");
  root.replaceChildren(tabs,notice,sessionActions,error,content,pager);
  const show=(v)=>v==null?'—':typeof v==='object'?JSON.stringify(v):String(v);
  async function mutate(path,id){
    if(busy||disposed||paused||!canWrite)return;
    if(!window.confirm(label('Apply this Hopae management change?','이 Hopae 관리 변경을 적용합니까?')))return;
    busy=true;error.textContent='';let applied=false;
    try{await host.api(path,{method:'POST',json:{id}});applied=true;}catch(e){if(!disposed)error.textContent=e.message;}finally{busy=false;}
    if(applied&&!disposed&&!paused)await load();
  }
  function table(items){
    const columns=view==='users'?['user_id','primary_email','username','display_name','status','role']:view==='sessions'?['session_id','user_id','provider_id','aal','auth_time']:['event_id','kind','outcome','reason','user_id','request_id'];
    const t=node('table'), head=node('thead'), row=node('tr');for(const c of columns)row.append(node('th',c));if(view!=='events')row.append(node('th',label('Actions','작업')));head.append(row);t.append(head);const body=node('tbody');
    for(const item of items){const data=item.user??item.session??item, tr=node('tr');for(const c of columns)tr.append(node('td',show(data[c]??item[c])));
      if(view!=='events'){const td=node('td'), id=view==='users'?data.user_id:data.session_id;
        const actions=view==='users'?[[label('Disable','비활성화'),'users/disable'],[label('Enable','활성화'),'users/enable'],[label('End sessions','세션 회수'),'users/sessions-terminate']]:[[label('Terminate','회수'),'sessions/terminate']];
        for(const [name,path] of actions){const b=node('button',name);b.disabled=!canWrite||typeof id!=='string';b.onclick=()=>mutate(path,id);td.append(b);}tr.append(td);
      }body.append(tr);
    }t.append(body);return t;
  }
  async function load(){
    if(busy||disposed||paused)return;busy=true;refresh.disabled=true;error.textContent='';
    try{
      const {data:me}=await host.api('me');if(disposed||paused)return;canWrite=me.role==='admin';login.hidden=true;logout.hidden=false;
      const {data}=await host.api(view==='projections'?'authentication/projections':view==='profiles'?'authentication/profiles':view==='status'?'status':view+'/query',(view==='status'||view==='profiles'||view==='projections')?{}:{method:'POST',json:{cursor,limit:50}});
      if(disposed||paused)return;
      content.replaceChildren();
      if(view==='projections'){
        const summary=node('div');
        const summarize=(configuration)=>{
          summary.replaceChildren();
          if(configuration==null){summary.append(node('p',label('Credential projection is disabled.','자격 변환이 비활성 상태입니다.')));return;}
          if(!Array.isArray(configuration.plans)){summary.append(node('p',label('No preview; the server validates the configuration.','미리보기가 없습니다. 서버가 설정을 검증합니다.')));return;}
          const table=node('table'),head=node('tr'),body=node('tbody');
          for(const title of [label('Service','서비스'),label('Audience','대상'),label('Resource','자원'),label('Action','행위'),label('Minimum AAL','최소 AAL'),label('Credential','자격 방식'),label('Reference','참조')])head.append(node('th',title));
          const thead=node('thead');thead.append(head);table.append(thead);
          for(const plan of configuration.plans){
            if(!plan||typeof plan!=='object')continue;
            const row=node('tr');
            for(const value of [plan.service,plan.audience,plan.resource,plan.action,plan.minimum_aal,plan.credential?.type,plan.credential?.secret_ref])row.append(node('td',show(value)));
            body.append(row);
          }table.append(body);summary.append(table);
        };
        const editor=node('textarea');editor.rows=20;editor.maxLength=65536;editor.setAttribute('aria-label',label('Credential projection configuration','자격 변환 설정'));editor.value=JSON.stringify(data.configuration??null,null,2);editor.disabled=!canWrite;
        summarize(data.configuration??null);
        editor.oninput=()=>{try{summarize(JSON.parse(editor.value));}catch{summary.replaceChildren(node('p',label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));}};
        const save=node('button',label('Save projection plans','변환 설정 저장'));save.disabled=!canWrite;
        save.onclick=async()=>{if(busy||disposed||paused||!canWrite)return;busy=true;save.disabled=true;refresh.disabled=true;error.textContent='';let saved=false;
          try{
            const configuration=JSON.parse(editor.value);
            if(configuration&&typeof configuration==='object'&&!Array.isArray(configuration))configuration.revision=data.revision+1;
            await host.api('authentication/projections/publish',{method:'POST',json:{revision:data.revision,configuration}});saved=true;
          }catch(e){if(!disposed&&!paused)error.textContent=e.message;}
          finally{busy=false;if(!disposed&&!paused){save.disabled=!canWrite;refresh.disabled=false;}}
          if(saved&&!disposed&&!paused)await load();
        };
        content.append(node('p',label('Revision: ','Revision: ')+show(data.revision)),node('p',label('Configure service credential conversion using declared references. Enter no passwords or token values. Set null to disable; saving replaces all plans.','선언된 참조로 서비스 자격 변환을 설정합니다. 비밀번호·토큰 값을 입력하지 마세요. null은 비활성화이며 저장하면 전체 설정을 교체합니다.')),node('p',label('Only declared credential references are accepted. Assurance requirements cannot be lowered. Saving these settings alone does not enable credential delivery.','등록된 자격 참조만 사용할 수 있고 최소 인증 수준을 낮출 수 없습니다. 설정 저장만으로 자격 전달이 활성화되지는 않습니다.')),summary,editor,save);next=null;
      }
      else if(view==='profiles'){
        const help=node('p',label('Edit service authentication profiles. Use declared credential references; enter no passwords or token values. Saving replaces the complete profile configuration.','서비스 인증 프로필을 편집합니다. 선언된 자격 정보 참조를 사용하고 비밀번호·토큰 값을 입력하지 마세요. 저장하면 프로필 설정 전체를 교체합니다.'));
        const routing=node('p',label('Active profiles come from the database; startup JSON only bootstraps an empty authority. Mixed native keys and relay require relay_token_prefix (for example partner:), which is removed once before forwarding. Keep it when retiring keys. Use a distinct relay issuer. Lua conditions restrict verified identities and grant no permissions.','활성 프로필은 DB가 소유하며 시작 JSON은 비어 있는 authority만 초기화합니다. 자체 key·relay 혼합에는 relay_token_prefix(예: partner:)가 필요하며 전달 시 하나를 제거합니다. key 회수 후에도 유지하고 다른 relay issuer를 사용하세요. Lua 조건은 검증된 신원을 제한하며 권한을 부여하지 않습니다.'));
        const summary=node('div');
        const summarize=(configuration)=>{
          summary.replaceChildren();
          if(configuration==null){summary.append(node('p',label('Service authentication is disabled.','서비스 인증이 비활성 상태입니다.')));return;}
          if(!Array.isArray(configuration.profiles)){summary.append(node('p',label('No preview; the server validates the configuration.','미리보기가 없습니다. 서버가 설정을 검증합니다.')));return;}
          const t=node('table'),head=node('thead'),tr=node('tr');
          for(const title of [label('Service','서비스'),label('Realm','Realm'),label('Methods','인증수단'),label('Issuers','Issuer'),label('Relay prefix','Relay 접두사'),label('Lua condition','Lua 조건'),label('Session fallback','Session 대체')])tr.append(node('th',title));
          head.append(tr);t.append(head);const body=node('tbody');
          for(const profile of configuration.profiles){
            if(!profile||typeof profile!=='object')continue;
            const count=Array.isArray(profile.api_keys)?profile.api_keys.length:0,relay=profile.api_relay,row=node('tr');
            const methods=[count?label('Native keys: ','자체 key: ')+count:null,relay?'API relay':null].filter(Boolean).join(' + ');
            const issuers=[count?'hopae:'+show(configuration.authority_id):null,relay?show(relay.issuer):null].filter(Boolean).join(' / ');
            for(const value of [profile.service_id,profile.realm,methods,issuers,profile.relay_token_prefix,profile.eligibility_lua?label('Enabled','활성'):label('None','없음'),profile.session_fallback?label('Missing credential only','자격 미제시만'):label('Disabled','비활성')])row.append(node('td',show(value)));
            body.append(row);
          }t.append(body);summary.append(t);
        };
        const editor=node('textarea');editor.rows=20;editor.maxLength=65536;editor.setAttribute('aria-label',label('Authentication profile configuration','인증 프로필 설정'));editor.value=JSON.stringify(data.configuration??null,null,2);editor.disabled=!canWrite;
        summarize(data.configuration??null);
        editor.oninput=()=>{try{summarize(JSON.parse(editor.value));}catch{summary.replaceChildren(node('p',label('Invalid JSON; preview unavailable.','JSON 오류로 미리보기를 표시할 수 없습니다.')));}};
        const save=node('button',label('Save profiles','프로필 저장'));save.disabled=!canWrite;
        save.onclick=async()=>{if(busy||disposed||paused||!canWrite)return;busy=true;save.disabled=true;refresh.disabled=true;error.textContent='';let saved=false;
          try{const configuration=JSON.parse(editor.value);await host.api('authentication/profiles/publish',{method:'POST',json:{revision:data.revision,configuration}});saved=true;}
          catch(e){if(!disposed&&!paused)error.textContent=e.message;}
          finally{busy=false;if(!disposed&&!paused){save.disabled=!canWrite;refresh.disabled=false;}}
          if(saved&&!disposed&&!paused)await load();
        };
        content.append(node('p',label('Revision: ','Revision: ')+show(data.revision)),help,routing,summary,editor,save);next=null;
      }
      else if(view==='status'){
        const grid=node('div',undefined,'hopae-metrics');
        for(const [name,value] of [[label('Users','사용자'),data.store?.users],[label('Live sessions','활성 세션'),data.store?.live_sessions],[label('Events','이벤트'),data.store?.events],[label('Providers','프로바이더'),data.providers?.length]]){
          const card=node('div',undefined,'panel hopae-metric');card.append(node('span',name,'muted'),node('strong',show(value)));grid.append(card);
        }content.append(grid);
        const heading=node('h2',label('Providers','프로바이더')),providerTable=node('table'),head=node('tr');for(const title of ['provider_id','kind','enabled','health'])head.append(node('th',title));providerTable.append(head);
        for(const provider of data.providers??[]){const row=node('tr');for(const key of ['provider_id','kind','enabled','health'])row.append(node('td',show(provider[key])));providerTable.append(row);}content.append(heading,providerTable);
        const details=node('details'),summary=node('summary',label('Runtime details','런타임 상세'));details.append(summary,node('pre',JSON.stringify(data,null,2)));content.append(details);next=null;
      }
      else {content.append(table(Array.isArray(data.items)?data.items:[]));next=data.next_cursor??null;if(!data.items?.length)content.append(node('p',label('No records','조회 결과 없음')));}
      for(const tab of tabs.querySelectorAll('[data-tab]'))tab.classList.toggle('button-primary',tab.dataset.tab===view);
      pager.hidden=view==='status'||view==='profiles'||view==='projections';previous.disabled=!history.length;more.disabled=!next;
    }catch(e){if(!disposed&&!paused){canWrite=false;login.hidden=false;content.querySelectorAll('button').forEach(b=>b.disabled=true);error.textContent=e.message;}}finally{busy=false;refresh.disabled=false;}
  }
  const timer=setInterval(()=>{if(view==='status')load();},30000);host.signal.addEventListener('abort',()=>{disposed=true;clearInterval(timer);root.replaceChildren();},{once:true});
  await load();
  return {pause(){paused=true;},resume(){paused=false;load();},dispose(){disposed=true;clearInterval(timer);root.replaceChildren();}};
}
