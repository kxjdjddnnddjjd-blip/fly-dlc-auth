// Ephemeral opt-in menu relay. Only whitelisted menu primitives can be published.
export function menuSnapshot(value){
  if(!value || typeof value!=='object' || Array.isArray(value))throw Error('invalid-menu');
  const number=(v,min,max)=>{if(typeof v!=='number'||!Number.isFinite(v)||v<min||v>max)throw Error('invalid-menu');return v;};
  const label=v=>{if(typeof v!=='string'||v.length>96||/[\u0000-\u0008\u000b-\u001f]/.test(v))throw Error('invalid-menu');return v;};
  const rect=v=>({x:number(v.x,0,560),y:number(v.y,-4000,4000),w:number(v.w,1,560),h:number(v.h,1,2048),text:label(v.text)});
  if(!Array.isArray(value.cards)||value.cards.length>150||!Array.isArray(value.controls)||value.controls.length>200)throw Error('invalid-menu');
  return {page:number(value.page,0,4),cursorX:number(value.cursorX,0,560),cursorY:number(value.cursorY,0,320),
    cards:value.cards.map(v=>({...rect(v),row:v.row===true})),
    controls:value.controls.map(v=>({...rect(v),kind:['button','check','slider','choice'].includes(v.kind)?v.kind:'button',selected:v.selected===true,value:number(v.value??0,0,1)}))};
}
export function createGlobalView({verify,now=Date.now}){
  const peers=new Map(),rates=new Map(),tokens=new Map();
  const fail=(reply,status,code)=>reply(status,{error:{code}});
  return async(req,reply)=>{
    if(req.method!=='POST')return fail(reply,405,'method-not-allowed');
    const time=now();for(const [uid,p]of peers)if(time-p.updatedAt>8000)peers.delete(uid);
    for(const [key,b]of rates)if(time>=b.until)rates.delete(key);
    for(const [key,t]of tokens)if(time>=t.until)tokens.delete(key);
    const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',').at(-1).trim();
    function limited(key,max,period){const bucket=rates.get(key);if(!bucket){if(rates.size>=5000)return true;rates.set(key,{count:1,until:time+period});return false;}return ++bucket.count>max;}
    if(limited('ip:'+ip,6000,60000))return fail(reply,429,'globalview/rate-limit');
    const token=String(req.headers.authorization||'').match(/^Bearer ([A-Za-z0-9_.-]{20,4096})$/)?.[1];
    if(!token)return fail(reply,401,'globalview/sign-in');
    let user;
    try{const cached=tokens.get(token);user=cached?.user??await verify(token);if(!user?.uid || !user.exp || user.exp*1000<=time)throw Error();
      if(tokens.size<2000)tokens.set(token,{user,until:Math.min(time+60000,user.exp*1000)});
    }catch{return fail(reply,401,'globalview/sign-in');}
    if(limited('uid:'+user.uid,12,1000))return fail(reply,429,'globalview/rate-limit');
    if(!String(req.headers['content-type']).startsWith('application/json'))return fail(reply,415,'invalid-content-type');
    let input;
    try{let body='',length=0;for await(const chunk of req){length+=chunk.length;if(length>65536)return fail(reply,413,'request-too-large');body+=chunk.toString('utf8');}input=JSON.parse(body);}catch{return fail(reply,400,'invalid-json');}
    if(input?.enabled===false){peers.delete(user.uid);return reply(200,{peers:[]});}
    try{
      if(input?.enabled!==true || !/^[a-f0-9]{64}$/.test(input.realm) || !/^[a-f0-9-]{36}$/.test(input.uuid) || !/^[A-Za-z0-9_]{1,16}$/.test(input.name) || !Number.isInteger(input.theme) || input.theme<0 || input.theme>5)throw Error();
      if(!Array.isArray(input.players)||input.players.length>1000||input.players.some(v=>typeof v!=='string'||!/^[a-f0-9-]{36}$/.test(v)))throw Error();
      if(input.watch && !/^[a-f0-9-]{36}$/.test(input.watch))throw Error();
      const menu=input.menu==null?null:menuSnapshot(input.menu);
      if(peers.size>=1000 && !peers.has(user.uid))return fail(reply,503,'globalview/full');
      // One active game identity per website account; no credentials, chat, screen pixels or server address.
      const self={uuid:input.uuid,name:input.name,realm:input.realm,theme:input.theme,menu,updatedAt:time};peers.set(user.uid,self);
      const visible=new Set(input.players);const result=[];
      for(const [uid,p]of peers)if(uid!==user.uid && p.realm===self.realm && visible.has(p.uuid))result.push({uuid:p.uuid,name:p.name,theme:p.theme,menuOpen:p.menu!==null,menu:p.uuid===input.watch?p.menu:null});
      return reply(200,{peers:result.slice(0,1000)});
    }catch{return fail(reply,400,'globalview/invalid-state');}
  };
}
