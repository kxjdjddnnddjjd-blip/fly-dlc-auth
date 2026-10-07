import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createGateway,credentials} from './server.mjs';

test('credential validation keeps passwords literal and validates identifiers',()=>{
  assert.deepEqual(credentials({identifier:' Admin ',password:' secret '}),{identifier:'Admin',password:' secret ',client:'native'});
  for(const value of [{identifier:'ab',password:'x'},{identifier:'admin',password:''},{identifier:'<script>',password:'x'},{identifier:'admin',password:{}}])assert.throws(()=>credentials(value));
});
async function fixture(t){
  const server=createGateway({resolveNickname:async name=>name==='admin'?{uid:'one',email:'private@example.test'}:null,signIn:async(email,password)=>{if(email!=='private@example.test'||password!=='correct')throw{code:'auth/invalid-credential'};return{localId:'one',idToken:'id',refreshToken:'refresh',expiresIn:'3600'};},customToken:async uid=>'custom-'+uid});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());const url=`http://127.0.0.1:${server.address().port}`;
  return async(body,origin)=>fetch(url+'/login',{method:'POST',headers:{'Content-Type':'application/json',...(origin?{Origin:origin}:{})},body:JSON.stringify(body)});
}
test('web nickname login returns a token without exposing private email or refresh token',async t=>{const send=await fixture(t);const r=await send({identifier:'ADMIN',password:'correct',client:'web'},'https://fly-dlc.web.app');assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');assert.deepEqual(await r.json(),{customToken:'custom-one'});});
test('native nickname and email login return validated sessions',async t=>{const send=await fixture(t);for(const identifier of ['Admin','private@example.test']){const r=await send({identifier,password:'correct'});assert.equal(r.status,200);assert.equal((await r.json()).localId,'one');}});
test('unknown nickname and wrong password have identical responses; untrusted origins are rejected',async t=>{const send=await fixture(t);const wrong=await send({identifier:'admin',password:'wrong'}),unknown=await send({identifier:'unknown',password:'wrong'});assert.equal(wrong.status,400);assert.deepEqual(await wrong.json(),await unknown.json());assert.equal((await send({identifier:'admin',password:'correct'},'https://attacker.example')).status,403);});
test('repeated credential attempts are rate limited',async t=>{const send=await fixture(t);for(let i=0;i<15;i++)await send({identifier:'admin',password:'wrong'});assert.equal((await send({identifier:'admin',password:'wrong'})).status,429);});
