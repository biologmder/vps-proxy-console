import { useState, type FormEvent, type ReactNode } from 'react';
import { Check, Dices, RefreshCw, X } from 'lucide-react';
import './inbound.css';

type Item = { id: string; [key: string]: unknown };
type Protocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'socks' | 'http';
type Network = 'tcp' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp';
type Security = 'none' | 'tls' | 'reality';
type Draft = {
  node_id: string; name: string; protocol: Protocol; network: Network; security: Security;
  listen: string; port: string; enabled: boolean;
  domain: string; path: string; host: string; service_name: string; xhttp_mode: string;
  flow: string; ss_method: string; ss_server_key: string; fingerprint: string;
  reality_dest: string; reality_short_id: string; regenerate_reality: boolean;
  service_user: string; service_password: string;
};

// Mirrors model.CheckCombination in internal/model/inbound.go.
const protocols: { id: Protocol; label: string; landing?: boolean; networks: Network[]; securities: Security[] }[] = [
  { id: 'vless', label: 'VLESS', networks: ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp'], securities: ['none', 'tls', 'reality'] },
  { id: 'vmess', label: 'VMess', networks: ['tcp', 'ws', 'grpc', 'httpupgrade'], securities: ['none', 'tls'] },
  { id: 'trojan', label: 'Trojan', networks: ['tcp', 'ws', 'grpc', 'httpupgrade'], securities: ['tls', 'reality'] },
  { id: 'shadowsocks', label: 'Shadowsocks', networks: ['tcp'], securities: ['none'] },
  { id: 'socks', label: 'SOCKS5 落地', landing: true, networks: ['tcp'], securities: ['none'] },
  { id: 'http', label: 'HTTP 落地', landing: true, networks: ['tcp'], securities: ['none'] },
];
const networkLabels: Record<Network, string> = { tcp: 'TCP (RAW)', ws: 'WebSocket', grpc: 'gRPC', httpupgrade: 'HTTPUpgrade', xhttp: 'XHTTP' };
const securityLabels: Record<Security, string> = { none: '无', tls: 'TLS', reality: 'REALITY' };
const realityNetworks: Network[] = ['tcp', 'grpc', 'xhttp'];
const ssMethods = [
  { value: '2022-blake3-aes-128-gcm', label: '2022-blake3-aes-128-gcm（推荐）' },
  { value: '2022-blake3-aes-256-gcm', label: '2022-blake3-aes-256-gcm' },
  { value: '2022-blake3-chacha20-poly1305', label: '2022-blake3-chacha20-poly1305' },
  { value: 'aes-256-gcm', label: 'aes-256-gcm' },
  { value: 'aes-128-gcm', label: 'aes-128-gcm' },
  { value: 'chacha20-ietf-poly1305', label: 'chacha20-ietf-poly1305' },
];
const fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'edge', 'random'];
const xhttpModes = ['auto', 'packet-up', 'stream-up', 'stream-one'];
const defaultRealityHost = 'www.microsoft.com';

const legacy: Record<string, [Protocol, Network, Security]> = {
  'vless-tls': ['vless', 'tcp', 'tls'], 'vless-reality': ['vless', 'tcp', 'reality'],
  'trojan-tls': ['trojan', 'tcp', 'tls'], 'vmess-ws-tls': ['vmess', 'ws', 'tls'], ss: ['shadowsocks', 'tcp', 'none'],
};

/** Short label such as "VLESS · XHTTP · REALITY" for inbound lists. */
export function inboundLabel(x: Record<string, unknown>): string {
  const raw = String(x.protocol || '');
  const [protocol, network, security] = legacy[raw] || [raw as Protocol, (x.network || 'tcp') as Network, (x.security || 'none') as Security];
  const spec = protocols.find(p => p.id === protocol);
  if (!spec) return raw;
  if (spec.landing) return spec.label;
  if (protocol === 'shadowsocks') return String(x.ss_method || '').startsWith('2022-') ? 'Shadowsocks 2022' : 'Shadowsocks';
  const parts = [spec.label, networkLabels[network] || network];
  if (security !== 'none') parts.push(securityLabels[security] || security);
  return parts.join(' · ');
}

const str = (v: unknown) => (v == null ? '' : String(v));
function randomPort(nodeID: string, inbounds: Item[], editingID?: string): string {
  const used = new Set(inbounds.filter(x => x.node_id === nodeID && x.id !== editingID).map(x => Number(x.port)));
  for (let i = 0; i < 200; i++) {
    const port = 10000 + Math.floor(Math.random() * 50000);
    if (!used.has(port) && port !== 10085) return String(port);
  }
  return '';
}
function suggestPort(preferred: number, nodeID: string, inbounds: Item[]): string {
  const used = new Set(inbounds.filter(x => x.node_id === nodeID).map(x => Number(x.port)));
  return used.has(preferred) ? randomPort(nodeID, inbounds) : String(preferred);
}
function randomPath(): string { return '/' + Math.random().toString(36).slice(2, 10); }
function validDomain(value: string): boolean {
  return value.length <= 253 && value.includes('.') && value.split('.').every(part => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(part));
}
function initialDraft(item: Item | undefined, nodes: Item[], inbounds: Item[]): Draft {
  if (item) {
    const [protocol, network, security] = legacy[str(item.protocol)] || [item.protocol as Protocol, (str(item.network) || 'tcp') as Network, (str(item.security) || 'none') as Security];
    return {
      node_id: str(item.node_id), name: str(item.name), protocol, network, security,
      listen: str(item.listen), port: str(item.port), enabled: Boolean(item.enabled),
      domain: str(item.domain), path: str(item.path), host: str(item.host), service_name: str(item.service_name),
      xhttp_mode: str(item.xhttp_mode) || 'auto', flow: str(item.flow) || (str(item.protocol) === 'vless-reality' ? 'xtls-rprx-vision' : ''),
      ss_method: str(item.ss_method) || 'aes-256-gcm', ss_server_key: str(item.ss_server_key), fingerprint: str(item.fingerprint) || 'chrome',
      reality_dest: str(item.reality_dest), reality_short_id: str(item.reality_short_id), regenerate_reality: false,
      service_user: str(item.service_user), service_password: str(item.service_password),
    };
  }
  const node = nodes[0];
  return {
    node_id: node?.id || '', name: '', protocol: 'vless', network: 'tcp', security: 'reality',
    listen: '', port: suggestPort(443, node?.id || '', inbounds), enabled: true,
    domain: defaultRealityHost, path: '', host: '', service_name: '', xhttp_mode: 'auto',
    flow: 'xtls-rprx-vision', ss_method: '2022-blake3-aes-128-gcm', ss_server_key: '', fingerprint: 'chrome',
    reality_dest: `${defaultRealityHost}:443`, reality_short_id: '', regenerate_reality: false,
    service_user: '', service_password: '',
  };
}

function Row({ label, hint, children, htmlFor }: { label: string; hint?: string; children: ReactNode; htmlFor?: string }) {
  return <div className="ib-row"><label htmlFor={htmlFor}>{label}</label><div className="ib-control">{children}{hint && <small>{hint}</small>}</div></div>;
}
function Segmented<T extends string>({ value, options, onChange, disabled }: { value: T; options: { value: T; label: string; disabled?: boolean }[]; onChange: (v: T) => void; disabled?: boolean }) {
  return <div className="ib-segmented" role="radiogroup">{options.map(o => <button type="button" role="radio" aria-checked={value === o.value} key={o.value} className={value === o.value ? 'selected' : ''} disabled={disabled || o.disabled} onClick={() => onChange(o.value)}>{o.label}</button>)}</div>;
}

export default function InboundEditor({ item, nodes, inbounds, onClose, onSave, busy, error }: {
  item?: Item; nodes: Item[]; inbounds: Item[]; onClose: () => void;
  onSave: (body: Record<string, unknown>) => void; busy: boolean; error: string;
}) {
  const [form, setForm] = useState<Draft>(() => initialDraft(item, nodes, inbounds));
  const [validation, setValidation] = useState('');
  const spec = protocols.find(p => p.id === form.protocol)!;
  const node = nodes.find(n => n.id === form.node_id);
  const isLanding = !!spec.landing;
  const hasStream = !isLanding && form.protocol !== 'shadowsocks';
  const visionAllowed = form.protocol === 'vless' && form.network === 'tcp' && form.security !== 'none';
  const proposedName = `${str(node?.name) || '节点'} · ${inboundLabel(form)}`;

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => { setValidation(''); setForm(p => ({ ...p, [key]: value })); };
  // Keeps network/security/flow inside what the chosen protocol supports.
  const coerce = (d: Draft): Draft => {
    const s = protocols.find(p => p.id === d.protocol)!;
    const network = s.networks.includes(d.network) ? d.network : s.networks[0];
    let security = s.securities.includes(d.security) ? d.security : s.securities[0];
    if (security === 'reality' && !realityNetworks.includes(network)) security = s.securities.includes('tls') ? 'tls' : 'none';
    const next = { ...d, network, security };
    if (!(next.protocol === 'vless' && next.network === 'tcp' && next.security !== 'none')) next.flow = '';
    if ((network === 'ws' || network === 'httpupgrade' || network === 'xhttp') && !next.path) next.path = network === 'xhttp' ? '/xhttp' : randomPath();
    if (network === 'grpc' && !next.service_name) next.service_name = 'grpc';
    if (security === 'tls' && (!next.domain || next.domain === defaultRealityHost)) next.domain = str(node?.domain);
    if (security === 'reality' && (!next.domain || next.domain === str(node?.domain))) next.domain = defaultRealityHost;
    if (security === 'reality' && !next.reality_dest) next.reality_dest = `${next.domain}:443`;
    return next;
  };
  const update = (patch: Partial<Draft>) => { setValidation(''); setForm(p => coerce({ ...p, ...patch })); };
  const chooseProtocol = (protocol: Protocol) => {
    const s = protocols.find(p => p.id === protocol)!;
    const preferred = protocol === 'shadowsocks' ? 8388 : s.landing ? (protocol === 'socks' ? 10808 : 18080) : 443;
    update({ protocol, port: item ? form.port : suggestPort(preferred, form.node_id, inbounds), listen: s.landing ? str(node?.private_ip) : '',
      security: protocol === 'vmess' ? 'tls' : form.security, flow: protocol === 'vless' ? 'xtls-rprx-vision' : '' });
  };
  const chooseNode = (nodeID: string) => {
    const next = nodes.find(n => n.id === nodeID);
    setValidation('');
    setForm(p => ({ ...p, node_id: nodeID, port: item ? p.port : suggestPort(Number(p.port) || 443, nodeID, inbounds),
      listen: isLanding ? str(next?.private_ip) : p.listen,
      domain: p.security === 'tls' && (!p.domain || p.domain === str(node?.domain)) ? str(next?.domain) : p.domain }));
  };
  const changeRealityHost = (value: string) => {
    setValidation('');
    setForm(p => ({ ...p, domain: value, reality_dest: p.reality_dest === `${p.domain}:443` || !p.reality_dest ? `${value}:443` : p.reality_dest }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!node) return setValidation('先选择一台 VPS 节点。');
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 80 || port === 10085) return setValidation('请输入可用端口；80 用于证书验证，10085 为 Xray 内部 API。');
    if (inbounds.some(x => x.node_id === node.id && x.id !== item?.id && Number(x.port) === port)) return setValidation('这台节点已有入站使用该端口，请换一个。');
    if (isLanding && !node.private_ip) return setValidation('请先在 VPS 节点中填写私网 / 隧道 IP。');
    if (hasStream && form.security !== 'none' && !validDomain(form.domain.trim())) return setValidation(form.security === 'reality' ? '请填写有效的 REALITY 伪装域名（SNI）。' : '请填写有效的证书域名。');
    if (form.security === 'reality' && !/^([a-zA-Z0-9.-]+):([0-9]{1,5})$/.test(form.reality_dest.trim())) return setValidation('REALITY 目标应为「域名:端口」，例如 www.microsoft.com:443。');
    if (form.security === 'reality' && form.reality_short_id && !/^([0-9a-fA-F]{2}){1,8}$/.test(form.reality_short_id)) return setValidation('Short ID 应为 2～16 位偶数长度的十六进制。');
    if (hasStream && ['ws', 'httpupgrade', 'xhttp'].includes(form.network) && !form.path.startsWith('/')) return setValidation('路径必须以 / 开头。');
    const keepKeys = form.security === 'reality' && !form.regenerate_reality;
    const payload: Record<string, unknown> = {
      node_id: node.id, name: form.name.trim() || proposedName, protocol: form.protocol,
      network: form.network, security: form.security,
      listen: isLanding ? str(node.private_ip) : form.listen.trim(), port, enabled: form.enabled,
      domain: hasStream && form.security !== 'none' ? form.domain.trim() : '',
      path: hasStream && ['ws', 'httpupgrade', 'xhttp'].includes(form.network) ? form.path.trim() : '',
      host: hasStream && ['ws', 'httpupgrade', 'xhttp'].includes(form.network) ? form.host.trim() : '',
      service_name: hasStream && form.network === 'grpc' ? form.service_name.trim() : '',
      xhttp_mode: hasStream && form.network === 'xhttp' ? form.xhttp_mode : '',
      flow: visionAllowed ? form.flow : '',
      ss_method: form.protocol === 'shadowsocks' ? form.ss_method : '',
      ss_server_key: form.protocol === 'shadowsocks' ? form.ss_server_key : '',
      fingerprint: form.security === 'reality' ? form.fingerprint : '',
      reality_dest: form.security === 'reality' ? form.reality_dest.trim() : '',
      reality_private_key: keepKeys ? str(item?.reality_private_key) : '',
      reality_public_key: keepKeys ? str(item?.reality_public_key) : '',
      reality_short_id: form.security === 'reality' && !form.regenerate_reality ? form.reality_short_id.trim().toLowerCase() : '',
      service_user: isLanding ? form.service_user.trim() : '',
      service_password: isLanding ? form.service_password : '',
    };
    onSave(payload);
  };

  const securityOptions = (['none', 'tls', 'reality'] as Security[]).filter(s => spec.securities.includes(s))
    .map(s => ({ value: s, label: securityLabels[s], disabled: s === 'reality' && !realityNetworks.includes(form.network) }));
  const hadReality = !!item && str(item.reality_public_key) !== '';

  return <div className="overlay" onMouseDown={onClose}>
    <div className="modal inbound-modal" onMouseDown={e => e.stopPropagation()}>
      <div className="modal-head inbound-head"><div><p className="eyebrow">INBOUND</p><h2>{item ? '编辑入站' : '添加入站'}</h2></div><button className="icon" onClick={onClose} aria-label="关闭"><X size={20}/></button></div>
      <form onSubmit={submit}>
        <div className="inbound-scroll">
          <section className="ib-section">
            <h3>基本设置</h3>
            <Row label="启用"><label className="ib-switch"><input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)}/><span/></label></Row>
            <Row label="备注" htmlFor="ib-name"><input id="ib-name" value={form.name} placeholder={proposedName} onChange={e => set('name', e.target.value)}/></Row>
            <Row label="节点" htmlFor="ib-node" hint={item ? '已有入站不可迁移节点；请在目标节点新建。' : undefined}>
              <select id="ib-node" value={form.node_id} disabled={!!item} onChange={e => chooseNode(e.target.value)}><option value="">选择节点</option>{nodes.map(n => <option key={n.id} value={n.id}>{str(n.name)} · {str(n.domain)}</option>)}</select>
            </Row>
            <Row label="协议" htmlFor="ib-protocol" hint={item ? '已有用户凭据与协议绑定，不能切换协议。' : spec.landing ? '仅监听节点私网 IP，供其他节点的出口使用，不进入订阅。' : undefined}>
              <select id="ib-protocol" value={form.protocol} disabled={!!item} onChange={e => chooseProtocol(e.target.value as Protocol)}>
                <optgroup label="客户端入口">{protocols.filter(p => !p.landing).map(p => <option key={p.id} value={p.id}>{p.label}</option>)}</optgroup>
                <optgroup label="私网落地">{protocols.filter(p => p.landing).map(p => <option key={p.id} value={p.id}>{p.label}</option>)}</optgroup>
              </select>
            </Row>
            <Row label="监听 IP" htmlFor="ib-listen" hint={isLanding ? '落地入口固定监听节点私网 IP。' : '留空监听所有地址。'}>
              <input id="ib-listen" value={isLanding ? str(node?.private_ip) || '尚未配置私网 IP' : form.listen} disabled={isLanding} placeholder="0.0.0.0" onChange={e => set('listen', e.target.value)}/>
            </Row>
            <Row label="端口" htmlFor="ib-port">
              <div className="ib-inline"><input id="ib-port" type="number" min="1" max="65535" value={form.port} onChange={e => set('port', e.target.value)}/><button type="button" className="secondary" onClick={() => set('port', randomPort(form.node_id, inbounds, item?.id))}><Dices size={14}/>随机</button></div>
            </Row>
          </section>

          {(form.protocol === 'vless' || form.protocol === 'shadowsocks' || isLanding) && <section className="ib-section">
            <h3>协议设置</h3>
            {form.protocol === 'vless' && <Row label="Flow" htmlFor="ib-flow" hint={visionAllowed ? 'Vision 需要客户端支持；旧版客户端选「无」。' : '仅 TCP + TLS/REALITY 可用 Vision。'}>
              <select id="ib-flow" value={form.flow} disabled={!visionAllowed} onChange={e => set('flow', e.target.value)}><option value="">无</option><option value="xtls-rprx-vision">xtls-rprx-vision</option></select>
            </Row>}
            {form.protocol === 'shadowsocks' && <>
              <Row label="加密方式" htmlFor="ib-method" hint={item ? '2022 与传统加密的密钥格式不同，不能互相切换。' : '2022 系列更安全；老客户端不支持时选 aes-256-gcm。'}>
                <select id="ib-method" value={form.ss_method} onChange={e => set('ss_method', e.target.value)}>{ssMethods.filter(m => !item || m.value.startsWith('2022-') === str(item.ss_method || 'aes').startsWith('2022-')).map(m => <option key={m.value} value={m.value}>{m.label}</option>)}</select>
              </Row>
              <Row label="服务密码" htmlFor="ib-ss-key" hint="留空自动生成；每个人员另有独立凭据。"><input id="ib-ss-key" value={form.ss_server_key} placeholder="自动生成" onChange={e => set('ss_server_key', e.target.value)}/></Row>
            </>}
            {isLanding && <>
              <Row label="账号" htmlFor="ib-user"><input id="ib-user" value={form.service_user} placeholder="留空自动生成 relay" onChange={e => set('service_user', e.target.value)}/></Row>
              <Row label="密码" htmlFor="ib-pass"><input id="ib-pass" type="password" value={form.service_password} placeholder="留空自动生成" onChange={e => set('service_password', e.target.value)}/></Row>
            </>}
          </section>}

          {hasStream && <section className="ib-section">
            <h3>传输</h3>
            <Row label="传输协议"><Segmented value={form.network} options={spec.networks.map(n => ({ value: n, label: networkLabels[n] }))} onChange={v => update({ network: v })}/></Row>
            {['ws', 'httpupgrade', 'xhttp'].includes(form.network) && <>
              <Row label="路径" htmlFor="ib-path"><div className="ib-inline"><input id="ib-path" value={form.path} placeholder="/path" onChange={e => set('path', e.target.value)}/><button type="button" className="secondary" onClick={() => set('path', randomPath())}><RefreshCw size={14}/>随机</button></div></Row>
              <Row label="Host" htmlFor="ib-host" hint="可留空；套 CDN 时填写 CDN 回源域名。"><input id="ib-host" value={form.host} placeholder="可选" onChange={e => set('host', e.target.value)}/></Row>
            </>}
            {form.network === 'xhttp' && <Row label="模式" htmlFor="ib-xmode"><select id="ib-xmode" value={form.xhttp_mode} onChange={e => set('xhttp_mode', e.target.value)}>{xhttpModes.map(m => <option key={m} value={m}>{m}</option>)}</select></Row>}
            {form.network === 'grpc' && <Row label="ServiceName" htmlFor="ib-svc"><input id="ib-svc" value={form.service_name} placeholder="grpc" onChange={e => set('service_name', e.target.value)}/></Row>}
            {form.network === 'xhttp' && <p className="ib-note">XHTTP 只出现在通用订阅链接中，Mihomo（Clash）订阅会跳过它。</p>}
          </section>}

          {hasStream && <section className="ib-section">
            <h3>安全</h3>
            <Row label="安全层"><Segmented value={form.security} options={securityOptions} onChange={v => update({ security: v })}/></Row>
            {form.security === 'none' && <p className="ib-note warn">未加密传输，容易被识别。仅在前面有 CDN/反向代理做 TLS 时使用。</p>}
            {form.security === 'tls' && <Row label="证书域名" htmlFor="ib-domain" hint="需解析到该 VPS；Agent 通过 80 端口自动申请证书。">
              <input id="ib-domain" value={form.domain} placeholder={str(node?.domain) || 'node.example.com'} onChange={e => set('domain', e.target.value)}/>
            </Row>}
            {form.security === 'reality' && <>
              <Row label="目标 (dest)" htmlFor="ib-dest" hint="被伪装的真实 TLS 站点，需支持 TLS 1.3 和 H2。"><input id="ib-dest" value={form.reality_dest} placeholder="www.microsoft.com:443" onChange={e => set('reality_dest', e.target.value)}/></Row>
              <Row label="SNI" htmlFor="ib-sni" hint="目标站点证书里的域名，不是你的 VPS 域名。"><input id="ib-sni" value={form.domain} placeholder={defaultRealityHost} onChange={e => changeRealityHost(e.target.value)}/></Row>
              <Row label="uTLS 指纹" htmlFor="ib-fp"><select id="ib-fp" value={form.fingerprint} onChange={e => set('fingerprint', e.target.value)}>{fingerprints.map(f => <option key={f} value={f}>{f}</option>)}</select></Row>
              <Row label="Short ID" htmlFor="ib-sid"><input id="ib-sid" value={form.regenerate_reality ? '' : form.reality_short_id} disabled={form.regenerate_reality} placeholder="留空自动生成" onChange={e => set('reality_short_id', e.target.value)}/></Row>
              <Row label="密钥对" hint={hadReality ? (form.regenerate_reality ? '保存后重新生成；所有人需要更新订阅。' : '私钥只保存在面板和节点。') : '保存时自动生成 X25519 密钥对。'}>
                {hadReality ? <div className="ib-inline"><code className="ib-key">{form.regenerate_reality ? '将重新生成' : str(item?.reality_public_key)}</code><button type="button" className="secondary" onClick={() => set('regenerate_reality', !form.regenerate_reality)}><RefreshCw size={14}/>{form.regenerate_reality ? '撤销' : '重新生成'}</button></div> : <span className="ib-muted">自动生成</span>}
              </Row>
            </>}
          </section>}

          <div className="ib-summary"><span className="badge neutral">{inboundLabel(form)}</span><span>{str(node?.domain) || '—'}:{form.port || '—'}</span>{!isLanding && <span className="ib-muted">保存后在「订阅分配」把它分配给人员。</span>}</div>
          {(validation || error) && <div className="error inbound-error">{validation || error}</div>}
        </div>
        <div className="modal-actions inbound-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" disabled={busy || nodes.length === 0}><Check size={16}/>{busy ? '正在保存…' : item ? '保存修改' : '添加入站'}</button></div>
      </form>
    </div>
  </div>;
}
