import React,{useState} from 'react';
import {Sidebar} from './components/Chrome';
import Overview from './pages/Overview';
import PolicyStudio from './pages/PolicyStudio';
import LiveRuntime from './pages/LiveRuntime';
import Provenance from './pages/Provenance';
import AttackLab from './pages/AttackLab';
import AuditCenter from './pages/AuditCenter';
export default function App(){const [page,setPage]=useState('overview');const pages:any={overview:<Overview/>,policy:<PolicyStudio/>,runtime:<LiveRuntime/>,provenance:<Provenance/>,attack:<AttackLab/>,audit:<AuditCenter/>};return <div className="app"><Sidebar page={page} setPage={setPage}/><div className="main">{pages[page]}</div></div>}
