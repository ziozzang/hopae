const {test,expect}=require(process.env.HANGANG_PLAYWRIGHT_MODULE || '../../../hangang-console-plugins/web/node_modules/@playwright/test');
const fs=require('fs');
const source=fs.readFileSync(require('path').join(__dirname,'../../plugins/hopae/index.js'),'utf8');
async function setup(page,key,authentication="hangang"){
 await page.goto('about:blank');
 await page.evaluate(async({source,key,authentication})=>{
  document.body.innerHTML='<main></main>';window.controller=new AbortController();window.revision=1;window.fail=false;window.calls=[];
  window.host={root:document.querySelector('main'),locale:()=> 'en',authentication,signal:controller.signal,api:async(path,options)=>{
   calls.push({path,options});if(path==='me')return {data:{role:'admin'}};
   if(path.endsWith('/publish')){await new Promise(r=>window.finish=r);if(fail)throw Object.assign(Error('fixture publish failure'),{status:window.failStatus});return {data:{revision:++window.revision}};}
   return {data:path==='status'?{}:{revision:window.revision,configuration:key==='profiles'?{profiles:[]}:{plans:[]}}};
  }};
  window.plugin=await (await import(URL.createObjectURL(new Blob([source],{type:'text/javascript'})))).mount(host);
 },{source,key,authentication});
 await page.locator(`[data-tab="${key}"]`).click();
 await expect(page.locator('textarea')).toBeVisible();
}
for(const key of ['profiles','projections']){
 test(key+' preserves invalid drafts through tabs, refresh, resume, conflict and explicit discard',async({page})=>{
  await setup(page,key);await page.locator('textarea').fill('{ invalid draft');
  await page.locator('[data-tab="status"]').click();await page.locator(`[data-tab="${key}"]`).click();
  await expect(page.locator('textarea')).toHaveValue('{ invalid draft');
  await page.evaluate(()=>{plugin.pause();plugin.resume();});await expect(page.locator('textarea')).toHaveValue('{ invalid draft');
  await page.evaluate(()=>window.revision=2);await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('Conflict');await expect(page.locator('textarea')).toHaveValue('{ invalid draft');
  await expect(page.getByRole('button',{name:key==='profiles'?'Save profiles':'Save projection plans',exact:true})).toBeDisabled();
  page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Discard draft and use latest revision',exact:true}).click();
  await expect(page.locator('textarea')).not.toHaveValue('{ invalid draft');
 });
 test(key+' freezes publication, sends once, retains conflict draft and scrubs on logout',async({page})=>{
  await setup(page,key);const draft=JSON.stringify(key==='profiles'?{profiles:[],marker:'draft'}:{plans:[],marker:'draft'});
  await page.locator('textarea').fill(draft);await page.evaluate(()=>window.fail=true);
  const save=page.getByRole('button',{name:key==='profiles'?'Save profiles':'Save projection plans',exact:true});await save.click();
  await expect(page.locator('textarea')).toBeDisabled();await expect(save).toBeDisabled();
  await page.evaluate(()=>finish());await expect(page.getByRole('status')).toContainText('Draft retained');await expect(page.locator('textarea')).toHaveValue(draft);
  expect(await page.evaluate(()=>calls.filter(c=>c.path.endsWith('/publish')).length)).toBe(1);
  await page.evaluate(()=>controller.abort());await expect(page.locator('textarea')).toHaveCount(0);
 });
 test(key+' successful delayed publication preserves subsequent synthetic edits',async({page})=>{
  await setup(page,key);await page.locator('textarea').fill('{"submitted":true}');
  await page.getByRole('button',{name:key==='profiles'?'Save profiles':'Save projection plans',exact:true}).click();
  await page.evaluate(()=>{const e=document.querySelector('textarea');e.value='{"newer":true}';e.dispatchEvent(new Event('input'));finish();});
  await expect(page.getByRole('status')).toContainText('Saved revision: 2');await expect(page.locator('textarea')).toHaveValue('{"newer":true}');
  await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.locator('textarea')).toHaveValue('{"newer":true}');
 });
}
test('permission loss scrubs both editor drafts; a late publication after logout cannot restore content',async({page})=>{
 await setup(page,'profiles');await page.locator('textarea').fill('{"privateDraft":true}');
 await page.evaluate(()=>{const api=host.api;host.api=async(path,options)=>path==='me'?{data:{role:'viewer'}}:api(path,options);});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.locator('textarea')).toBeDisabled();await expect(page.locator('textarea')).not.toContainText('privateDraft');
 await expect(page.getByRole('button',{name:'Save profiles',exact:true})).toBeDisabled();
 await page.locator('[data-tab=\"status\"]').click();await expect(page.locator('textarea')).toHaveCount(0);
 await setup(page,'profiles');await page.locator('textarea').fill('{"privateDraft":true}');
 await page.getByRole('button',{name:'Save profiles',exact:true}).click();
 await page.evaluate(()=>{controller.abort();finish();});await expect(page.locator('main')).toBeEmpty();
});
for(const authentication of ['native','hangang'])test(authentication+' error keeps correct login authority',async({page})=>{
 await setup(page,'profiles',authentication);
 await page.evaluate(()=>{host.api=async()=>{throw Error('offline');};});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.locator('.error')).toHaveText('offline');
 const login=page.getByRole('link',{name:'Sign in to Hopae',exact:true});
 if(authentication==='native')await expect(login).toBeVisible();else await expect(login).toBeHidden();
});
test('acknowledged submitted snapshot becomes baseline even when draft changes during save',async({page})=>{
 await setup(page,'profiles');const original=await page.locator('textarea').inputValue();
 await page.locator('textarea').fill('{"submitted":true}');await page.getByRole('button',{name:'Save profiles',exact:true}).click();
 await page.evaluate(original=>{const e=document.querySelector('textarea');e.value=original;e.dispatchEvent(new Event('input'));finish();},original);
 await expect(page.getByRole('status')).toContainText('Unsaved draft');
 await page.evaluate(()=>{plugin.pause();plugin.resume();});await expect(page.locator('textarea')).toHaveValue(original);
 await expect(page.getByRole('status')).toContainText('Unsaved draft');
});
for(const failStatus of [undefined,409,503])test('mutation failure '+failStatus+' blocks replay and cached discard until successful reconciliation',async({page})=>{
 await setup(page,'profiles');await page.locator('textarea').fill('{"draft":true}');
 await page.evaluate(status=>{window.fail=true;window.failStatus=status;},failStatus);const save=page.getByRole('button',{name:'Save profiles',exact:true});
 await save.click();await page.evaluate(()=>finish());await expect(page.getByRole('status')).toContainText(failStatus===409?'Revision conflict':'outcome unknown');
 await expect(save).toBeDisabled();const discard=page.getByRole('button',{name:'Discard draft and use latest revision',exact:true});await expect(discard).toBeDisabled();
 await page.evaluate(()=>{const api=host.api;window.goodApi=api;host.api=async()=>{throw Error('offline');};});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.locator('.error')).toHaveText('offline');await expect(save).toBeDisabled();await expect(discard).toBeDisabled();
 await page.evaluate(()=>host.api=goodApi);await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(save).toBeEnabled();await expect(discard).toBeEnabled();await expect(page.locator('textarea')).toHaveValue('{"draft":true}');
 expect(await page.evaluate(()=>calls.filter(c=>c.path.endsWith('/publish')).length)).toBe(1);
});
for(const key of ['profiles','projections'])for(const ack of [null,{}, {revision:'2'},{revision:1},{revision:3},{revision:2.5},{revision:-1},{revision:Number.MAX_SAFE_INTEGER+1}])test(key+' rejects malformed publication acknowledgement '+JSON.stringify(ack),async({page})=>{
 await setup(page,key);const draft='{"draft":true}';await page.locator('textarea').fill(draft);
 await page.evaluate(ack=>{const api=host.api;host.api=async(path,options)=>path.endsWith('/publish')?{data:ack}:api(path,options);},ack);
 const save=page.getByRole('button',{name:key==='profiles'?'Save profiles':'Save projection plans',exact:true});await save.click();
 await expect(page.getByRole('status')).toContainText('outcome unknown');await expect(page.getByRole('status')).not.toContainText('Saved revision');
 await expect(page.locator('textarea')).toHaveValue(draft);await expect(save).toBeDisabled();await expect(page.getByRole('button',{name:'Discard draft and use latest revision',exact:true})).toBeDisabled();
 await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(save).toBeEnabled();await expect(page.locator('textarea')).toHaveValue(draft);
});
for(const revision of [null,'1',-1,1.5,Number.MAX_SAFE_INTEGER+1])test('malformed GET revision '+revision+' cannot clear reconciliation block',async({page})=>{
 await setup(page,'profiles');await page.locator('textarea').fill('{"draft":true}');await page.evaluate(()=>window.fail=true);
 const save=page.getByRole('button',{name:'Save profiles',exact:true});await save.click();await page.evaluate(()=>finish());await expect(save).toBeDisabled();
 await page.evaluate(revision=>{window.revision=revision;},revision);await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.locator('.error')).toContainText('Invalid configuration revision');await expect(save).toBeDisabled();await expect(page.getByRole('button',{name:'Discard draft and use latest revision',exact:true})).toBeDisabled();await expect(page.locator('textarea')).toHaveValue('{"draft":true}');
 await page.evaluate(()=>window.revision=1);await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(save).toBeEnabled();
});
test('maximum safe revision cannot publish an overflowing successor',async({page})=>{
 await setup(page,'profiles');await page.evaluate(()=>window.revision=Number.MAX_SAFE_INTEGER);await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await page.locator('textarea').fill('{"draft":true}');await expect(page.getByRole('button',{name:'Save profiles',exact:true})).toBeDisabled();
 expect(await page.evaluate(()=>calls.filter(c=>c.path.endsWith('/publish')).length)).toBe(0);
});
