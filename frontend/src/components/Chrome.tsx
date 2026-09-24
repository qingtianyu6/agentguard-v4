import React from 'react';
import {Activity,ShieldCheck,Workflow,Route,FlaskConical,FileSearch2,Settings,Command,Radio,Search,Bell,Hexagon,Database,Braces,GitBranch} from 'lucide-react';

export const nav=[
  {id:'overview',label:'安全总览',en:'Security Overview',icon:Activity},
  {id:'policy',label:'策略工作台',en:'Policy Studio',icon:ShieldCheck},
  {id:'runtime',label:'实时运行',en:'Live Runtime',icon:Workflow},
  {id:'provenance',label:'溯源图谱',en:'Provenance Graph',icon:Route},
  {id:'attack',label:'攻击实验室',en:'Attack & Benchmark',icon:FlaskConical},
  {id:'audit',label:'审计中心',en:'Evidence Center',icon:FileSearch2},
];
export function Logo(){return <div className="brand"><div className="brand-mark"><Hexagon size={22}/><ShieldCheck size={13} className="brand-shield"/></div><div><b>智契 · AgentGuard</b><span>VERIFIABLE AGENT RUNTIME SAFETY</span></div></div>}
export function Sidebar({page,setPage}:{page:string,setPage:(p:string)=>void}){return <aside className="sidebar"><Logo/><div className="nav-caption">RUNTIME CONTROL PLANE</div><nav>{nav.map(n=>{const I=n.icon;return <button className={'nav-item '+(page===n.id?'active':'')} onClick={()=>setPage(n.id)} key={n.id}><I size={18}/><span><b>{n.label}</b><small>{n.en}</small></span><i/></button>})}</nav><div className="sidebar-footer"><div className="stack-card"><div className="stack-head"><span className="pulse-dot"/><span>V3 Research Stack</span></div><div className="stack-row"><Braces size={13}/><span>P2C-V + Formal</span><b>ON</b></div><div className="stack-row"><GitBranch size={13}/><span>Trajectory Guard</span><b>ON</b></div><div className="stack-row"><Database size={13}/><span>Evidence DB</span><b>ON</b></div></div><button className="plain-btn"><Settings size={17}/>系统配置 <small>v3.0</small></button></div></aside>}
export function Topbar({title}:{title:string}){return <header className="topbar"><div><div className="crumb">AgentGuard <i/> Control Plane <i/> <span>{title}</span></div><h1>{title}</h1></div><div className="top-actions"><div className="search"><Search size={16}/><span>搜索策略 / Trace / Risk</span><kbd>⌘ K</kbd></div><button className="icon-btn"><Bell size={18}/><i/></button><div className="live-chip"><Radio size={13}/><span>LIVE</span></div><div className="avatar">AG</div></div></header>}
export function PageShell({children,title}:{children:React.ReactNode,title:string}){return <><Topbar title={title}/><main className="content">{children}</main></>}
export function SectionTitle({eyebrow,title,desc,action}:{eyebrow:string,title:string,desc?:string,action?:React.ReactNode}){return <div className="section-title"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2>{desc&&<p>{desc}</p>}</div>{action}</div>}
export function Empty({text='暂无数据'}:{text?:string}){return <div className="empty"><Command size={24}/><span>{text}</span></div>}
