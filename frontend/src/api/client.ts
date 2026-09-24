const BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';

async function request(path:string, options:RequestInit={}){
  const res=await fetch(BASE+path,{headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
  if(!res.ok){const text=await res.text();throw new Error(text||`HTTP ${res.status}`)}
  const json=await res.json();return json.data ?? json;
}
export const api={
  get:(p:string)=>request(p),
  post:(p:string,b:any={})=>request(p,{method:'POST',body:JSON.stringify(b)}),
  patch:(p:string,b:any)=>request(p,{method:'PATCH',body:JSON.stringify(b)}),
};
export const wsBase=BASE.replace(/^http/,'ws');
