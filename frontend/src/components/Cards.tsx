import React from 'react';
import {ArrowUpRight,Shield,CheckCircle2,AlertTriangle,Wrench,LockKeyhole} from 'lucide-react';
export function MetricCard({label,value,sub,tone='normal',icon}:{label:string,value:any,sub:string,tone?:string,icon?:React.ReactNode}){return <div className={'metric-card '+tone}><div className="metric-top"><span>{label}</span>{icon||<ArrowUpRight size={16}/>}</div><strong>{value}</strong><small>{sub}</small></div>}
export function DecisionBadge({value}:{value:string}){const map:any={ALLOW:[CheckCircle2,'allow'],ASK:[AlertTriangle,'ask'],REPAIR:[Wrench,'repair'],DENY:[LockKeyhole,'deny']};const [I,c]=map[value]||[Shield,''];return <span className={'decision '+c}><I size={13}/>{value}</span>}
export function RiskBadge({value}:{value:string}){return <span className={'risk '+String(value||'LOW').toLowerCase()}>{value||'LOW'}</span>}
export function MiniBar({label,value,max=100}:{label:string,value:number,max?:number}){return <div className="mini-bar"><div><span>{label}</span><b>{value}</b></div><div className="bar-track"><i style={{width:`${Math.min(100,(value/max)*100)}%`}}/></div></div>}
