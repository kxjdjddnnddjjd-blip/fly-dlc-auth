import http from 'node:http';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const invalid={code:'auth/invalid-credential'};
export function credentials(value){
  if(!value || typeof value.identifier!=='string' || typeof value.password!=='string' || !value.password || value.password.length>4096)throw invalid;
  const identifier=value.identifier.trim();
  if(identifier.length>254 || (!identifier.includes('@') && !/^[A-Za-z0-9_]{3,20}$/.test(identifier)))throw invalid;
  return {identifier,password:value.password,client:value.client==='web'?'web':'native'};
}
export function createGateway({resolveNickname,signIn,customToken,now=Date.now,origins=['https://fly-dlc.web.app','https://fly-dlc.firebaseapp.com']}){
  const attempts=new Map(),windowMs=15*60*1000;
  function limited(key,max){
    const time=now();if(attempts.size>20000)for(const [name,entry]of attempts)if(entry.until<=time)attempts.delete(name);
    const item=attempts.get(key);if(!item || item.until<=time){if(attempts.size>=20000)return true;attempts.set(key,{until:time+windowMs,count:1});return false;}
    return ++item.count>max;
  }
  return http.createServer(async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
    const origin=req.headers.origin;
    const reply=(status,value)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
    if(origin && !origins.includes(origin))return reply(403,{error:{code:'auth/unauthorized-origin'}});
    if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');}
    if(req.method==='GET' && req.url==='/health')return reply(200,{status:'ok'});
    if(req.url!=='/login')return reply(404,{error:{code:'not-found'}});
    if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
    if(req.method!=='POST')return reply(405,{error:{code:'method-not-allowed'}});
    // Render's reverse proxy appends its trusted client address to X-Forwarded-For.
    const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',').at(-1).trim();
    if(limited('ip:'+ip,40))return reply(429,{error:{code:'auth/too-many-requests'}});
    if(!String(req.headers['content-type']).startsWith('application/json'))return reply(415,{error:{code:'invalid-content-type'}});
    try{
      let body='',length=0;
      for await(const chunk of req){length+=chunk.length;if(length>8192){reply(413,{error:{code:'request-too-large'}});req.destroy();return;}body+=chunk.toString('utf8');}
      let input;try{input=credentials(JSON.parse(body));}catch{return reply(400,{error:invalid});}
      const canonical=input.identifier.toLowerCase();
      const bucket=createHash('sha256').update(canonical).digest('hex');
      if(limited('account:'+bucket,15))return reply(429,{error:{code:'auth/too-many-requests'}});
      const isEmail=canonical.includes('@');
      const resolved=isEmail?{email:input.identifier}:await resolveNickname(canonical);
      // Unknown names still follow the password verification path; no email lookup endpoint.
      const session=await signIn(resolved?.email || 'unknown@invalid.example',input.password);
      if(!resolved || (resolved.uid && resolved.uid!==session.localId))return reply(400,{error:invalid});
      if(input.client==='web')return reply(200,{customToken:await customToken(session.localId)});
      return reply(200,{idToken:session.idToken,refreshToken:session.refreshToken,expiresIn:session.expiresIn,localId:session.localId});
    }catch(error){
      const code=error?.code;
      if(code==='auth/invalid-credential' || code==='auth/user-not-found' || code==='auth/user-disabled')return reply(400,{error:invalid});
      if(code==='auth/too-many-requests')return reply(429,{error:{code}});
      // Never log passwords, identifiers, request payloads or Firebase credentials.
      console.error('Login upstream unavailable');return reply(503,{error:{code:'auth/service-unavailable'}});
    }
  });
}
async function production(){
  const {initializeApp,cert}=await import('firebase-admin/app');
  const {getAuth}=await import('firebase-admin/auth');const {getFirestore}=await import('firebase-admin/firestore');
  if(!process.env.FIREBASE_SERVICE_ACCOUNT || !process.env.FIREBASE_API_KEY)throw new Error('Server credentials are required');
  const credential=JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  initializeApp({credential:cert(credential),projectId:'fly-dlc'});
  const firebaseAuth=getAuth(),db=getFirestore();
  const server=createGateway({
    async resolveNickname(name){const snapshot=await db.doc(`usernames/${name}`).get();if(!snapshot.exists)return null;const uid=snapshot.get('uid');try{const user=await firebaseAuth.getUser(uid);return user.disabled?null:{uid,email:user.email};}catch(error){if(error.code==='auth/user-not-found')return null;throw error;}},
    async signIn(email,password){
      const response=await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,returnSecureToken:true}),signal:AbortSignal.timeout(15000)});
      const result=await response.json();if(!response.ok){const message=result.error?.message||'';throw {code:message.includes('TOO_MANY_ATTEMPTS')?'auth/too-many-requests':response.status>=500?'auth/service-unavailable':'auth/invalid-credential'};}return result;
    },
    customToken:uid=>firebaseAuth.createCustomToken(uid)
  });
  server.requestTimeout=20000;server.headersTimeout=10000;
  server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Fly DLC account gateway ready'));
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href)production().catch(()=>{console.error('Cannot initialize account gateway');process.exit(1);});
