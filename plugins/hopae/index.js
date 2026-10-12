// Trusted native-style Hangang console package; credentials stay in the host broker.
export async function mount(host) {
  const root=host.root, ko=()=>host.locale()==='ko';
  let paused=false, disposed=false, busy=false, canWrite=false, view='status', cursor=null, next=null, history=[];
  const label=(en,kr)=>ko()?kr:en;
  const node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
  root.classList.add('hopae-console');
  const login=node('a',label('Sign in to Hopae','Hopae 로그인'));login.href='/_hopae/login?return=%2Fui%2F';login.className='button';
  const logout=node('a',label('Sign out of Hopae','Hopae 로그아웃'));logout.href='/_hopae/logout?return=%2Fui%2F';logout.className='button';
  const tabs=node('div',undefined,'hopae-toolbar'), notice=node('p',undefined,'muted'), error=node('p',undefined,'error'), content=node('div'), pager=node('div',undefined,'hopae-toolbar');
  const previous=node('button',label('Previous','이전')), more=node('button',label('Next','다음')), refresh=node('button',label('Refresh','새로고침'));
  for(const [key,en,kr] of [['status','Status','상태'],['users','Users','사용자'],['sessions','Sessions','세션'],['events','Events','이벤트']]){
    const b=node('button',label(en,kr));b.dataset.tab=key;b.onclick=()=>{if(busy)return;view=key;cursor=null;history=[];load();};tabs.append(b);
  }
  refresh.onclick=()=>load();tabs.append(refresh);
  notice.textContent=label('Manage identities, sessions and security events.','사용자·세션·보안 이벤트를 관리합니다.');
  previous.onclick=()=>{if(!busy&&history.length){cursor=history.pop();load();}};
  more.onclick=()=>{if(!busy&&next){history.push(cursor);cursor=next;load();}};pager.append(previous,more);root.replaceChildren(tabs,notice,login,logout,error,content,pager);
  const show=(v)=>v==null?'—':typeof v==='object'?JSON.stringify(v):String(v);
  async function mutate(path,id){
    if(busy||disposed||paused)return;
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
      const {data:me}=await host.api('me');if(disposed||paused)return;canWrite=me.role==='admin';
      const {data}=await host.api(view==='status'?'status':view+'/query',view==='status'?{}:{method:'POST',json:{cursor,limit:50}});
      if(disposed||paused)return;
      content.replaceChildren();
      if(view==='status'){const pre=node('pre',JSON.stringify(data,null,2));content.append(pre);next=null;}
      else {content.append(table(Array.isArray(data.items)?data.items:[]));next=data.next_cursor??null;if(!data.items?.length)content.append(node('p',label('No records','조회 결과 없음')));}
      for(const tab of tabs.querySelectorAll('[data-tab]'))tab.classList.toggle('primary',tab.dataset.tab===view);
      pager.hidden=view==='status';previous.disabled=!history.length;more.disabled=!next;
    }catch(e){if(!disposed&&!paused)error.textContent=e.message;}finally{busy=false;refresh.disabled=false;}
  }
  const timer=setInterval(()=>{if(view==='status')load();},30000);host.signal.addEventListener('abort',()=>{disposed=true;clearInterval(timer);root.replaceChildren();},{once:true});
  await load();
  return {pause(){paused=true;},resume(){paused=false;load();},dispose(){disposed=true;clearInterval(timer);root.replaceChildren();}};
}
