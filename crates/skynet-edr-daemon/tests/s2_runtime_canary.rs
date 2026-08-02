//! Hermetic S2 canary: registered plugin hooks -> live `AF_UNIX` ACK -> `SQLite` -> loopback Risk API.

use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use skynet_edr_core::LocalStore;

#[derive(Debug)]
struct CanaryAccounting {
    generated: u64,
    enqueued: u64,
    terminal_acks: u64,
    receipts: u64,
    drops: u64,
    fallback_records: u64,
    socket_failures: u64,
    collisions: u64,
    truncations: u64,
    backlog: u64,
}

impl CanaryAccounting {
    #[allow(clippy::too_many_arguments)]
    const fn from_observed(
        generated: u64,
        enqueued: u64,
        terminal_acks: u64,
        receipts: u64,
        drops: u64,
        fallback_records: u64,
        socket_failures: u64,
        collisions: u64,
        truncations: u64,
        backlog: u64,
    ) -> Self {
        Self {
            generated,
            enqueued,
            terminal_acks,
            receipts,
            drops,
            fallback_records,
            socket_failures,
            collisions,
            truncations,
            backlog,
        }
    }
}

fn root() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("skynet-s2-runtime-canary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("private canary root created");
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback port allocated")
        .local_addr()
        .expect("loopback address available")
        .port()
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[allow(clippy::too_many_lines)]
fn registered_hooks_traverse_live_socket_and_risk_projection_for_all_live_rules() {
    let root = root();
    let socket = root.join("ingest.sock");
    let db = root.join("skynet.sqlite");
    let config = root.join("config.toml");
    let plugin_state = root.join("plugin-state");
    fs::create_dir_all(&plugin_state).unwrap();
    let port = free_port();
    let uid = nix::unistd::Uid::effective().as_raw();
    fs::write(
        &config,
        format!(
            r#"mode = "passive"
data_dir = "{}"
log_dir = "{}"
[http_api]
enabled = true
bind = "127.0.0.1:{}"
read_only = true
[sensors]
linux_privileged = false
[ingest]
enabled = true
socket = "{}"
allow_root = {}
allowed_uids = [{}]
max_frame_bytes = 262144
read_timeout_ms = 1000
write_timeout_ms = 1000
candidate_limit = 10000
"#,
            root.display(),
            root.display(),
            port,
            socket.display(),
            uid == 0,
            if uid == 0 {
                String::new()
            } else {
                uid.to_string()
            }
        ),
    )
    .unwrap();

    let log = fs::File::create(root.join("daemon.log")).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("child daemon starts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while (!socket.exists() || TcpStream::connect(("127.0.0.1", port)).is_err())
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(socket.exists(), "live AF_UNIX socket exists");

    let runner = root.join("producer_canary.py");
    fs::write(&runner, PYTHON_CANARY).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output_path = root.join("producer-result.json");
    let output = Command::new("python3")
        .arg(&runner)
        .arg(&repository)
        .arg(&socket)
        .arg(&plugin_state)
        .arg(port.to_string())
        .arg(&output_path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python producer canary runs");
    if !output.status.success() {
        stop(&mut daemon);
        panic!(
            "producer canary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let producer: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    let projection_runner = root.join("desktop_projection_canary.mjs");
    fs::write(&projection_runner, DESKTOP_PROJECTION_CANARY).unwrap();
    let projection = Command::new("node")
        .arg(&projection_runner)
        .arg(&repository)
        .arg(&output_path)
        .output()
        .expect("shipped Desktop projection validator runs");
    assert!(
        projection.status.success(),
        "Desktop projection rejected live Risk response: {}",
        String::from_utf8_lossy(&projection.stderr)
    );
    assert_eq!(producer["secret_input_markers"], 2);
    assert!(producer["generated"].as_u64().unwrap() > 0);
    assert_eq!(
        producer["enqueued"].as_u64().unwrap() + producer["queue_drops"].as_u64().unwrap(),
        producer["generated"].as_u64().unwrap()
    );
    assert_eq!(producer["generated"], producer["terminal_acks"]);
    assert_eq!(producer["generated"], producer["persisted_or_duplicate"]);
    assert_eq!(producer["fallback_records"], 0);
    assert_eq!(producer["queue_drops"], 0);
    assert_eq!(producer["socket_failures"], 0);
    assert_eq!(producer["real_hermes_runtime"], false);
    let store = LocalStore::open_read_only(&db).expect("durable store opens read-only");
    assert_eq!(
        store.count_events().unwrap(),
        usize::try_from(producer["generated"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        store.count_ingest_receipts().unwrap(),
        store.count_events().unwrap()
    );
    let incidents = store.list_incidents().unwrap();
    let expected = [
        "EDR-EXFIL-001",
        "EDR-MCP-001",
        "EDR-PI-001",
        "EDR-MSG-001",
        "EDR-NET-001",
        "EDR-CRON-001",
        "EDR-MALWARE-001",
    ];
    for rule in expected {
        let expected_count = if rule == "EDR-EXFIL-001" {
            3
        } else if rule == "EDR-MSG-001" {
            2
        } else {
            1
        };
        assert_eq!(
            incidents
                .iter()
                .filter(|incident| incident.id.as_str().contains(rule))
                .count(),
            expected_count,
            "{rule}"
        );
    }
    assert_eq!(incidents.len(), 10);

    let connection =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let collisions = connection
        .query_row("SELECT COUNT(*) FROM ingest_collisions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        .cast_unsigned();
    let truncations = incidents
        .iter()
        .filter(|incident| {
            incident
                .id
                .as_str()
                .contains("continuous-correlation-degraded")
        })
        .count() as u64;
    let accounting = CanaryAccounting::from_observed(
        producer["generated"].as_u64().unwrap(),
        producer["enqueued"].as_u64().unwrap(),
        producer["terminal_acks"].as_u64().unwrap(),
        store.count_ingest_receipts().unwrap() as u64,
        producer["queue_drops"].as_u64().unwrap(),
        producer["fallback_records"].as_u64().unwrap(),
        producer["socket_failures"].as_u64().unwrap(),
        collisions,
        truncations,
        producer["backlog"].as_u64().unwrap(),
    );
    println!(
        "S2_CANARY_METRICS={}",
        serde_json::json!({
            "generated": accounting.generated,
            "enqueued": accounting.enqueued,
            "terminal_acks": accounting.terminal_acks,
            "receipts": accounting.receipts,
            "store_growth_bytes": fs::metadata(&db).unwrap().len(),
            "drops": accounting.drops,
            "fallback_records": accounting.fallback_records,
            "socket_failures": accounting.socket_failures,
            "backlog": accounting.backlog,
            "collisions": accounting.collisions,
            "truncations": accounting.truncations,
            "callback_ms": producer["callback_stats"],
            "event_to_ack_ms": producer["ack_stats"],
            "ack_to_api_visible_ms": producer["ack_to_api_stats"]
        })
    );

    let producer_serialized = producer.to_string();
    for marker in [
        "S2_FAKE_HONEYTOKEN_EXFIL_7Q9X",
        "S2_FAKE_HONEYTOKEN_MSG_4M2P",
    ] {
        assert!(
            !producer_serialized.contains(marker),
            "raw marker leaked into API projection"
        );
    }

    let risks = &producer["risk_response"];
    assert_eq!(risks["schema_version"], "skynet.risk.v1");
    assert_eq!(risks["read_only"], true);
    assert_eq!(producer["baseline_risk_count"], 7);
    assert_eq!(producer["synthetic_secret_incident_count"], 3);
    assert_eq!(risks["items"].as_array().unwrap().len(), 10);
    assert_eq!(producer["dashboard_risk_count"], 10);
    assert_eq!(producer["risk_details"].as_array().unwrap().len(), 10);
    for item in risks["items"].as_array().unwrap() {
        assert!(item["title"]
            .as_str()
            .is_some_and(|title| !title.is_empty()));
        assert!(item["summary"]
            .as_str()
            .is_some_and(|summary| summary.starts_with("Read-only projection")));
    }

    stop(&mut daemon);
    drop(store);
    let mut scanned = Vec::new();
    for path in [
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
        root.join("daemon.log"),
        plugin_state.join("skynet-edr-plugin.log"),
        plugin_state.join("events-v1.jsonl"),
    ] {
        if path.exists() {
            scanned.extend(fs::read(path).unwrap());
        }
    }
    let scanned = String::from_utf8_lossy(&scanned);
    for marker in [
        "S2_FAKE_HONEYTOKEN_EXFIL_7Q9X",
        "S2_FAKE_HONEYTOKEN_MSG_4M2P",
    ] {
        assert!(
            !scanned.contains(marker),
            "raw marker leaked across canary artifacts"
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn observed_accounting_preserves_nonzero_fault_evidence() {
    let accounting = CanaryAccounting::from_observed(9, 8, 7, 6, 1, 2, 3, 4, 5, 6);
    assert_eq!(accounting.collisions, 4);
    assert_eq!(accounting.truncations, 5);
    assert_eq!(accounting.drops, 1);
    assert_eq!(accounting.backlog, 6);
}

const PYTHON_CANARY: &str = r"
import collections,importlib.util,json,os,sys,time,types,urllib.parse
from pathlib import Path
repo,socket,state,port,out=Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),sys.argv[4],Path(sys.argv[5])
os.environ.update(SKYNET_EDR_STATE_DIR=str(state),SKYNET_EDR_INGEST_SOCKET=socket,SKYNET_EDR_API_PORT=port,SKYNET_EDR_SOCKET_TIMEOUT_MS='1000')
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
plugin=load('skynet_s2_runtime_plugin',repo/'integrations/hermes/skynet-edr/__init__.py')
manifest=json.loads((repo/'crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json').read_text())
class C:
 def __init__(self):self.hooks={}
 def register_hook(self,n,c):self.hooks[n]=c
ctx=C();acks=[];ack_ms=[];ack_at=[];canonical=[];generated=0;callback_ms=[];secret_input_markers=0
orig_send=plugin._send_frame;orig_write=plugin._write_event
def observed_send(line):
 started=time.monotonic();status=orig_send(line);ack_ms.append((time.monotonic()-started)*1000);ack_at.append(time.monotonic());acks.append(status);canonical.append(json.loads(line));return status
def observed_write(**kwargs):
 global generated
 generated+=1
 return orig_write(**kwargs)
plugin._send_frame=observed_send;plugin._write_event=observed_write;plugin.register(ctx)
for case in manifest['cases']:
 if case['category'] not in {'malicious','near_miss'}:continue
 plugin._session_trace_id='s2-runtime-'+case['case_id']
 for call in case['producer_calls']:
  started=time.monotonic();ctx.hooks[call['hook']](*call['args'],**call['kwargs']);callback_ms.append((time.monotonic()-started)*1000)
 plugin._event_queue.join()
class Router:
 def get(self,path):return lambda f:f
fast=types.ModuleType('fastapi');fast.APIRouter=Router;fast.Query=lambda default,**kw:default
class HTTPException(Exception):
 def __init__(self,status_code,detail):self.status_code=status_code;self.detail=detail
fast.HTTPException=HTTPException;sys.modules['fastapi']=fast
api=load('skynet_s2_dashboard_api',repo/'integrations/hermes/skynet-edr/dashboard/plugin_api.py')
baseline_risks=api._upstream('/api/v1/risks',{'limit':50,'offset':0})
assert len(baseline_risks['items'])==7,baseline_risks
for case in manifest['cases']:
 if case['category']!='synthetic_secret':continue
 callback_input=json.dumps(case['producer_calls'],sort_keys=True)
 assert all(marker in callback_input for marker in case['forbidden_markers']),case['case_id']
 secret_input_markers+=len(case['forbidden_markers'])
 plugin._session_trace_id='s2-runtime-'+case['case_id']
 for call in case['producer_calls']:
  started=time.monotonic();ctx.hooks[call['hook']](*call['args'],**call['kwargs']);callback_ms.append((time.monotonic()-started)*1000)
 plugin._event_queue.join()
plugin._worker_stop.set();plugin._worker_thread.join(timeout=2)
deadline=time.monotonic()+2
while True:
 risks=api._upstream('/api/v1/risks',{'limit':50,'offset':0})
 if len(risks['items'])==10:break
 assert time.monotonic()<deadline,risks
 time.sleep(.01)
ack_to_api_ms=(time.monotonic()-ack_at[-1])*1000
risk_details=[api._upstream('/api/v1/risks/'+urllib.parse.quote(item['id'],safe=''),{}) for item in risks['items']]
def stats(values):
 values=sorted(values);n=len(values);return {'sample_count':n,'p50':values[(n-1)//2],'p95':values[max(0,(95*n+99)//100-1)],'max':values[-1]}
status_histogram=dict(collections.Counter(acks));drops=plugin._transport_counters['queue_drops']
result={'generated':generated,'enqueued':generated-drops,'terminal_acks':len(acks),'ack_status_histogram':status_histogram,'persisted_or_duplicate':sum(x in {'persisted','duplicate'} for x in acks),'fallback_records':plugin._transport_counters['fallback_records'],'queue_drops':drops,'socket_failures':plugin._transport_counters['socket_failures'],'backlog':plugin._event_queue.qsize(),'max_callback_ms':max(callback_ms),'callback_stats':stats(callback_ms),'ack_stats':stats(ack_ms),'ack_to_api_stats':stats([ack_to_api_ms]),'baseline_risk_count':len(baseline_risks['items']),'synthetic_secret_incident_count':len(risks['items'])-len(baseline_risks['items']),'dashboard_risk_count':len(risks['items']),'risk_response':risks,'risk_details':risk_details,'canonical_events':canonical,'secret_input_markers':secret_input_markers,'real_hermes_runtime':False,'package_install_runtime':False}
assert result['max_callback_ms']<50,out
out.write_text(json.dumps(result,sort_keys=True))
";

const DESKTOP_PROJECTION_CANARY: &str = r#"
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const [repo, resultPath] = process.argv.slice(2);
let source = readFileSync(repo + '/integrations/hermes/skynet-edr/desktop/plugin.js', 'utf8');
source = source.replace(/^import React from 'react';\n/, "const React = { useState(initial) { return [initial, () => {}]; } };\n");
source = source.replace(/^import \{[\s\S]*?\} from '@hermes\/plugin-sdk';\n/m, "const jsx = (...args) => ({ jsx: args }); const jsxs = jsx; const Badge = Button = EmptyState = ErrorState = ScrollArea = SearchField = Skeleton = function Stub() {}; const PALETTE_AREA = ROUTES_AREA = SIDEBAR_NAV_AREA = 'area'; const fmtDateTime = (value) => String(value); const host = { navigate() {} }; const useQuery = () => ({});\n");
source = source.replace(/export default \{[\s\S]*?\n\};\s*$/m, '');
source = source.replace(/export const __desktopTest = /, 'globalThis.__desktopTest = ');
const context = { globalThis: {}, console };
vm.createContext(context);
vm.runInContext(source, context, { filename: 'plugin.js' });
const result = JSON.parse(readFileSync(resultPath, 'utf8'));
const projected = context.globalThis.__desktopTest.validateRiskPage(result.risk_response, 0);
assert.equal(projected.items.length, result.dashboard_risk_count);
"#;
