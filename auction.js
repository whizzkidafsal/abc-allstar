const out=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
async function signed(secret,msg){const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return enc(await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(msg)));}
async function authorized(req,env){const [exp,sig]=(req.headers.get('authorization')||'').replace(/^Bearer /i,'').split('.');return !!(exp&&sig&&/^\d+$/.test(exp)&&Number(exp)>Date.now()&&env.ADMIN_PASSWORD&&sig===await signed(env.ADMIN_PASSWORD,exp));}
export async function onRequest({request,env}){
 try{
  if(!env.DB)return out({error:'D1 DB binding missing'},503);
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS auction_state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)').run();
  const base={selected:null,bid:0,owner:'',status:'READY',owners:[],results:[],year:new Date().getFullYear()};
  const saved=await env.DB.prepare('SELECT payload,updated_at FROM auction_state WHERE id=1').first();
  const state=saved?JSON.parse(saved.payload):base;
  if(request.method==='GET'){
    const players=await env.DB.prepare('SELECT * FROM players ORDER BY name ASC').all();
    return out({state,players:players.results.map(p=>({id:p.id,name:p.name,grade:p.grade,photo:p.photo||p.photo_key||''})),updated_at:saved?.updated_at||null});
  }
  if(request.method!=='POST')return out({error:'Method not allowed'},405);
  if(!(await authorized(request,env)))return out({error:'Admin login required'},401);
  const x=await request.json();let next={...state};
  if(x.action==='owners'){
    if(!Array.isArray(x.owners)||x.owners.length>30)return out({error:'Invalid owners'},400);
    next.owners=x.owners.map(v=>String(v).trim().slice(0,80)).filter(Boolean);
    next.year=Number(x.year)||new Date().getFullYear();
  }else if(x.action==='select'){
    const p=await env.DB.prepare('SELECT id FROM players WHERE id=?').bind(x.id).first();
    if(!p)return out({error:'Player not found'},404);
    next={...next,selected:p.id,bid:0,owner:'',status:'BIDDING'};
  }else if(x.action==='bid'){
    if(next.selected==null)return out({error:'Select a player'},400);
    const bid=Number(x.bid),owner=String(x.owner||'');
    if(!Number.isSafeInteger(bid)||bid<0||bid>1000000000)return out({error:'Invalid bid'},400);
    if(owner&&!next.owners.includes(owner))return out({error:'Choose a listed owner'},400);
    next={...next,bid,owner,status:'BIDDING'};
  }else if(x.action==='sold'||x.action==='unsold'){
    if(next.selected==null)return out({error:'Select a player'},400);
    if(x.action==='sold'&&(!next.owner||next.bid<=0))return out({error:'Owner and positive bid required'},400);
    next.status=x.action.toUpperCase();
    next.results=[...next.results.filter(r=>String(r.id)!==String(next.selected)),{id:next.selected,bid:next.bid,owner:next.owner,status:next.status,year:next.year}];
  }else if(x.action==='reset'){
    next={...base,owners:next.owners,year:next.year};
  }else return out({error:'Invalid action'},400);
  const updated=new Date().toISOString();
  await env.DB.prepare('INSERT INTO auction_state(id,payload,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at').bind(JSON.stringify(next),updated).run();
  return out({ok:true,state:next,updated_at:updated});
 }catch(e){return out({error:String(e.message||e)},500);}
}
