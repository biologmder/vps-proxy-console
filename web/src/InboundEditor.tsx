import { useState, type FormEvent } from 'react';
import { ArrowRight, Check, ChevronDown, CircleHelp, Globe2, LockKeyhole, Network, ShieldCheck, X } from 'lucide-react';
import './inbound.css';

type Item = { id: string; [key: string]: unknown };
type Protocol = 'vless-reality' | 'vless-tls' | 'trojan-tls' | 'vmess-ws-tls' | 'ss' | 'socks' | 'http';
type Purpose = 'public' | 'private';
type Draft = {
  node_id: string; name: string; protocol: Protocol; listen: string; port: string;
  domain: string; path: string; reality_dest: string; enabled: boolean;
  service_user: string; service_password: string; ss_server_key: string;
};

const protocolOptions: { id: Protocol; label: string; transport: string; security: string; description: string; purpose: Purpose; badge?: string }[] = [
  { id: 'vless-reality', label: 'VLESS · REALITY', transport: 'TCP / RAW', security: 'REALITY', description: '不需要自己的 TLS 证书，适合现代客户端。', purpose: 'public', badge: '推荐' },
  { id: 'vless-tls', label: 'VLESS · TLS', transport: 'TCP / RAW', security: 'TLS', description: '使用自己的域名和自动签发的证书。', purpose: 'public' },
  { id: 'trojan-tls', label: 'Trojan · TLS', transport: 'TCP / RAW', security: 'TLS', description: 'TLS 连接，适合兼容 Trojan 的客户端。', purpose: 'public' },
  { id: 'vmess-ws-tls', label: 'VMess · WS', transport: 'WebSocket', security: 'TLS', description: 'WebSocket + TLS，供需要 VMess 的客户端使用。', purpose: 'public' },
  { id: 'ss', label: 'Shadowsocks', transport: 'TCP + UDP', security: 'AES-256-GCM', description: '轻量加密入口，支持 TCP 和 UDP。', purpose: 'public' },
  { id: 'socks', label: 'SOCKS5 落地', transport: 'TCP', security: '私网账号', description: '仅监听节点私网 IP，供入口节点作为上游使用。', purpose: 'private' },
  { id: 'http', label: 'HTTP 落地', transport: 'TCP', security: '私网账号', description: '仅监听节点私网 IP，不出现在订阅中。', purpose: 'private' },
];
const recommendedPort: Record<Protocol, number> = {
  'vless-reality': 443, 'vless-tls': 8443, 'trojan-tls': 443,
  'vmess-ws-tls': 2053, ss: 8388, socks: 10808, http: 18080,
};
const defaultRealityHost = 'www.microsoft.com';

function suggestPort(protocol: Protocol, nodeID: string, inbounds: Item[], editingID?: string): string {
  const used = new Set(inbounds.filter(x => x.node_id === nodeID && x.id !== editingID).map(x => Number(x.port)));
  const preferred = recommendedPort[protocol];
  if (!used.has(preferred)) return String(preferred);
  for (let port = 20000; port <= 60000; port++) if (!used.has(port)) return String(port);
  return '';
}
function validDomain(value: string): boolean {
  return value.length <= 253 && value.includes('.') && value.split('.').every(part => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(part));
}
function initialDraft(item: Item | undefined, nodes: Item[], inbounds: Item[]): Draft {
  if (item) return {
    node_id: String(item.node_id || ''), name: String(item.name || ''), protocol: item.protocol as Protocol,
    listen: String(item.listen || ''), port: String(item.port || ''), domain: String(item.domain || ''),
    path: String(item.path || ''), reality_dest: String(item.reality_dest || ''), enabled: Boolean(item.enabled),
    service_user: String(item.service_user || ''), service_password: String(item.service_password || ''),
    ss_server_key: String(item.ss_server_key || ''),
  };
  const node = nodes[0];
  return { node_id: node?.id || '', name: '', protocol: 'vless-reality', listen: '',
    port: suggestPort('vless-reality', node?.id || '', inbounds), domain: defaultRealityHost,
    path: '/ws', reality_dest: `${defaultRealityHost}:443`, enabled: true,
    service_user: '', service_password: '', ss_server_key: '' };
}

export default function InboundEditor({ item, nodes, inbounds, onClose, onSave, busy, error }: {
  item?: Item; nodes: Item[]; inbounds: Item[]; onClose: () => void;
  onSave: (body: Record<string, unknown>) => void; busy: boolean; error: string;
}) {
  const [form, setForm] = useState<Draft>(() => initialDraft(item, nodes, inbounds));
  const [advanced, setAdvanced] = useState(false);
  const [validation, setValidation] = useState('');
  const spec = protocolOptions.find(p => p.id === form.protocol)!;
  const node = nodes.find(n => n.id === form.node_id);
  const purpose = spec.purpose;
  const nodeName = String(node?.name || '节点');
  const proposedName = `${nodeName} · ${spec.label}`;
  const isReality = form.protocol === 'vless-reality';
  const isTLS = ['vless-tls', 'trojan-tls', 'vmess-ws-tls'].includes(form.protocol);
  const isPrivate = purpose === 'private';

  const update = (key: keyof Draft, value: string | boolean) => {
    setValidation('');
    setForm(previous => ({ ...previous, [key]: value }));
  };
  const chooseNode = (nodeID: string) => {
    const nextNode = nodes.find(n => n.id === nodeID);
    setValidation('');
    setForm(previous => ({ ...previous, node_id: nodeID,
      port: item ? previous.port : suggestPort(previous.protocol, nodeID, inbounds),
      listen: isPrivate ? String(nextNode?.private_ip || '') : previous.listen,
      domain: isTLS && !item ? String(nextNode?.domain || '') : previous.domain }));
  };
  const chooseProtocol = (protocol: Protocol) => {
    if (item) return;
    const next = protocolOptions.find(p => p.id === protocol)!;
    setValidation('');
    setForm(previous => ({ ...previous, protocol,
      port: suggestPort(protocol, previous.node_id, inbounds),
      listen: next.purpose === 'private' ? String(node?.private_ip || '') : '',
      domain: protocol === 'vless-reality' ? defaultRealityHost : next.purpose === 'private' || protocol === 'ss' ? '' : String(node?.domain || ''),
      reality_dest: protocol === 'vless-reality' ? `${defaultRealityHost}:443` : '',
      path: protocol === 'vmess-ws-tls' ? '/ws' : '' }));
  };
  const changeRealityHost = (value: string) => {
    setValidation('');
    setForm(previous => ({ ...previous, domain: value,
      reality_dest: previous.reality_dest === `${previous.domain}:443` || !previous.reality_dest ? `${value}:443` : previous.reality_dest }));
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!node) return setValidation('先选择一台 VPS 节点。');
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 80 || port === 10085) return setValidation('请输入可用端口；80 用于证书验证，10085 为 Xray 内部 API。');
    if (inbounds.some(x => x.node_id === node.id && x.id !== item?.id && Number(x.port) === port)) return setValidation('这台节点已有入站使用该端口，请换一个。');
    if (isPrivate && !node.private_ip) return setValidation('请先在 VPS 节点中填写私网 / 隧道 IP。');
    if ((isTLS || isReality) && !validDomain(form.domain.trim())) return setValidation(isReality ? '请填写有效的伪装域名（SNI）。' : '请填写有效的证书域名。');
    if (isReality && !/^([a-zA-Z0-9.-]+):([0-9]{1,5})$/.test(form.reality_dest.trim())) return setValidation('REALITY 目标应为「域名:端口」，例如 www.microsoft.com:443。');
    if (form.protocol === 'vmess-ws-tls' && !form.path.startsWith('/')) return setValidation('WebSocket 路径必须以 / 开头。');
    const payload: Record<string, unknown> = {
      node_id: node.id, name: form.name.trim() || proposedName, protocol: form.protocol,
      listen: isPrivate ? String(node.private_ip) : form.listen.trim(), port,
      domain: isReality || isTLS ? form.domain.trim() : '',
      path: form.protocol === 'vmess-ws-tls' ? form.path.trim() || '/ws' : '',
      reality_dest: isReality ? form.reality_dest.trim() : '',
      reality_private_key: isReality ? String(item?.reality_private_key || '') : '',
      reality_public_key: isReality ? String(item?.reality_public_key || '') : '',
      reality_short_id: isReality ? String(item?.reality_short_id || '') : '',
      service_user: isPrivate ? form.service_user.trim() : '',
      service_password: isPrivate ? form.service_password : '',
      ss_server_key: form.protocol === 'ss' ? form.ss_server_key : '',
      enabled: form.enabled,
    };
    onSave(payload);
  };

  return <div className="overlay" onMouseDown={onClose}>
    <div className="modal inbound-modal" onMouseDown={event => event.stopPropagation()}>
      <div className="modal-head inbound-head"><div><p className="eyebrow">INBOUND STUDIO</p><h2>{item ? '编辑入站' : '创建入站'}</h2><p className="muted">先选用途和协议，再填写此协议真正需要的参数。</p></div><button className="icon" onClick={onClose} aria-label="关闭"><X size={20}/></button></div>
      <form onSubmit={submit}>
        <div className="inbound-scroll">
        <div className="purpose-tabs" role="tablist" aria-label="入站用途">
          <button type="button" role="tab" aria-selected={purpose === 'public'} className={purpose === 'public' ? 'selected' : ''} disabled={!!item} onClick={() => chooseProtocol('vless-reality')}><Globe2 size={18}/><span><strong>客户端入口</strong><small>分发订阅，供他人连接</small></span></button>
          <button type="button" role="tab" aria-selected={purpose === 'private'} className={purpose === 'private' ? 'selected' : ''} disabled={!!item} onClick={() => chooseProtocol('socks')}><Network size={18}/><span><strong>私网落地</strong><small>接中转，只供入口节点使用</small></span></button>
        </div>
        <div className="inbound-grid">
          <div className="protocol-pane">
            <div className="inbound-section-heading"><span>01</span><div><strong>选择协议</strong><small>{item ? '已有入站不能直接切换协议；请另建入站' : purpose === 'public' ? '只列出当前项目可部署的组合' : '落地入口不会出现在用户订阅中'}</small></div></div>
            <div className="protocol-list">{protocolOptions.filter(p => p.purpose === purpose).map(p => <button type="button" key={p.id} className={'protocol-card ' + (form.protocol === p.id ? 'selected' : '')} disabled={!!item && form.protocol !== p.id} onClick={() => chooseProtocol(p.id)}><span className="protocol-title"><strong>{p.label}</strong>{p.badge && <em>{p.badge}</em>}</span><span className="protocol-description">{p.description}</span><span className="protocol-chips"><span>{p.transport}</span><span>{p.security}</span></span></button>)}</div>
          </div>
          <div className="inbound-config-pane">
            <div className="inbound-section-heading"><span>02</span><div><strong>连接配置</strong><small>已根据协议填入常用默认值</small></div></div>
            <div className="inbound-fields">
              <div className="field"><label htmlFor="inbound-node">所属 VPS 节点</label><select id="inbound-node" value={form.node_id} disabled={!!item} onChange={e => chooseNode(e.target.value)}><option value="">选择节点</option>{nodes.map(n => <option key={n.id} value={n.id}>{String(n.name)} · {String(n.domain)}</option>)}</select>{item && <small>已有入站不可直接迁移节点；请在目标节点新建。</small>}</div>
              <div className="field"><label htmlFor="inbound-port">监听端口</label><input id="inbound-port" type="number" min="1" max="65535" value={form.port} onChange={e => update('port', e.target.value)}/><small>建议端口；若主机已有其他服务占用，可改为高位端口。</small></div>
              <div className="field inbound-wide"><label htmlFor="inbound-name">入站名称 <span className="optional">可留空</span></label><input id="inbound-name" value={form.name} placeholder={proposedName} onChange={e => update('name', e.target.value)}/></div>
              {isReality && <><div className="field"><label htmlFor="reality-sni">伪装站点 SNI</label><input id="reality-sni" value={form.domain} placeholder="www.microsoft.com" onChange={e => changeRealityHost(e.target.value)}/><small>填写真实 TLS 站点的域名，不是你的 VPS 域名。</small></div><div className="field"><label htmlFor="reality-target">REALITY 目标</label><input id="reality-target" value={form.reality_dest} placeholder="www.microsoft.com:443" onChange={e => update('reality_dest', e.target.value)}/><small>通常与 SNI 对应；密钥和 Short ID 自动生成。</small></div></>}
              {isTLS && <div className="field inbound-wide"><label htmlFor="tls-domain">证书域名 / SNI</label><input id="tls-domain" value={form.domain} placeholder={String(node?.domain || 'node.example.com')} onChange={e => update('domain', e.target.value)}/><small>需解析到所选 VPS；Agent 会为此域名申请证书。</small></div>}
              {form.protocol === 'vmess-ws-tls' && <div className="field inbound-wide"><label htmlFor="ws-path">WebSocket 路径</label><input id="ws-path" value={form.path} placeholder="/ws" onChange={e => update('path', e.target.value)}/></div>}
              {form.protocol === 'ss' && <div className="fixed-choice inbound-wide"><ShieldCheck size={17}/><div><strong>加密方式：AES-256-GCM</strong><small>服务密码创建时自动生成；分配用户后各自使用独立凭据。</small></div></div>}
              {isPrivate && <div className="fixed-choice inbound-wide"><LockKeyhole size={17}/><div><strong>仅监听私网地址：{String(node?.private_ip || '尚未配置')}</strong><small>不会对公网监听，也不会进入用户订阅。服务账号和密码可自动生成。</small></div></div>}
              <div className="inbound-wide"><button type="button" className="advanced-toggle" aria-expanded={advanced} onClick={() => setAdvanced(!advanced)}><ChevronDown size={16} className={advanced ? 'turned' : ''}/>高级设置 <span>大多数情况下无需修改</span></button>{advanced && <div className="advanced-fields">
                {!isPrivate && <div className="field"><label htmlFor="listen">监听地址</label><input id="listen" value={form.listen} placeholder="留空则监听 0.0.0.0" onChange={e => update('listen', e.target.value)}/></div>}
                {isPrivate && <><div className="field"><label htmlFor="service-user">落地账号</label><input id="service-user" value={form.service_user} placeholder="留空自动生成 relay" onChange={e => update('service_user', e.target.value)}/></div><div className="field"><label htmlFor="service-password">落地密码</label><input id="service-password" type="password" value={form.service_password} placeholder="留空自动生成" onChange={e => update('service_password', e.target.value)}/></div></>}
                {form.protocol === 'ss' && <div className="field"><label htmlFor="ss-password">服务密码</label><input id="ss-password" type="password" value={form.ss_server_key} placeholder="留空自动生成" onChange={e => update('ss_server_key', e.target.value)}/></div>}
                <label className="switch-row"><input type="checkbox" checked={form.enabled} onChange={e => update('enabled', e.target.checked)}/><span>创建后立即启用</span></label>
              </div>}</div>
            </div>
          </div>
        </div>
        <div className="inbound-summary"><CircleHelp size={18}/><div><strong>{spec.label} <ArrowRight size={13}/> {nodeName}:{form.port || '—'}</strong><p>{isPrivate ? '私网落地入口；随后可在「出口与落地」中选作上游。' : isReality ? 'REALITY 无需节点 TLS 证书；伪装域名必须与目标站点的证书一致。' : isTLS ? 'TLS 入站需要域名解析和节点的 80 端口用于签发证书。' : '公网订阅入口；启用后可分配给人员。'}</p></div></div>
        {(validation || error) && <div className="error inbound-error">{validation || error}</div>}
        </div>
        <div className="modal-actions inbound-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" disabled={busy || nodes.length === 0}><Check size={16}/>{busy ? '正在保存…' : item ? '保存修改' : '创建入站'}</button></div>
      </form>
    </div>
  </div>;
}
