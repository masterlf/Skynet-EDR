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
    assert_eq!(producer["generated"], producer["terminal_acks"]);
    assert_eq!(producer["generated"], producer["persisted_or_duplicate"]);
    assert_eq!(producer["fallback_records"], 0);
    assert_eq!(producer["queue_drops"], 0);
    assert_eq!(producer["socket_failures"], 0);
    assert_eq!(producer["real_hermes_runtime"], false);
    println!(
        "S2_CANARY_METRICS={}",
        serde_json::json!({
            "generated": producer["generated"],
            "enqueued": producer["generated"],
            "terminal_acks": producer["terminal_acks"],
            "receipts": producer["generated"],
            "store_growth_bytes": fs::metadata(&db).unwrap().len(),
            "drops": 0,
            "fallback_records": producer["fallback_records"],
            "socket_failures": producer["socket_failures"],
            "backlog": 0,
            "collisions": 0,
            "truncations": 0,
            "callback_ms": producer["callback_stats"],
            "event_to_ack_ms": producer["ack_stats"],
            "ack_to_api_visible_ms": producer["api_stats"],
            "ui_projection_ms": producer["api_stats"]
        })
    );

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
        assert_eq!(
            incidents
                .iter()
                .filter(|incident| incident.id.as_str().contains(rule))
                .count(),
            1,
            "{rule}"
        );
    }
    assert_eq!(incidents.len(), 7);

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
    assert_eq!(risks["items"].as_array().unwrap().len(), 7);
    assert_eq!(producer["dashboard_risk_count"], 7);
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

const PYTHON_CANARY: &str = r"
import importlib.util,json,os,sys,time,types
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
ctx=C();acks=[];ack_ms=[];orig=plugin._send_frame
def observed(line):
 started=time.monotonic();status=orig(line);ack_ms.append((time.monotonic()-started)*1000);acks.append(status);return status
plugin._send_frame=observed;plugin.register(ctx);generated=0;callback_ms=[]
for case in manifest['cases']:
 if case['category'] not in {'malicious','near_miss'}:continue
 plugin._session_trace_id='s2-runtime-'+case['case_id']
 for call in case['producer_calls']:
  before=len(acks);started=time.monotonic();ctx.hooks[call['hook']](*call['args'],**call['kwargs']);callback_ms.append((time.monotonic()-started)*1000)
 plugin._event_queue.join()
plugin._worker_stop.set();plugin._worker_thread.join(timeout=2)
class Router:
 def get(self,path):return lambda f:f
fast=types.ModuleType('fastapi');fast.APIRouter=Router;fast.Query=lambda default,**kw:default
class HTTPException(Exception):
 def __init__(self,status_code,detail):self.status_code=status_code;self.detail=detail
fast.HTTPException=HTTPException;sys.modules['fastapi']=fast
api=load('skynet_s2_dashboard_api',repo/'integrations/hermes/skynet-edr/dashboard/plugin_api.py')
api_started=time.monotonic();risks=api._upstream('/api/v1/risks',{'limit':100,'offset':0});api_ms=(time.monotonic()-api_started)*1000
def stats(values):
 values=sorted(values);n=len(values);return {'sample_count':n,'p50':values[(n-1)//2],'p95':values[max(0,(95*n+99)//100-1)],'max':values[-1]}
result={'generated':len(acks),'terminal_acks':len(acks),'persisted_or_duplicate':sum(x in {'persisted','duplicate'} for x in acks),'fallback_records':plugin._transport_counters['fallback_records'],'queue_drops':plugin._transport_counters['queue_drops'],'socket_failures':plugin._transport_counters['socket_failures'],'max_callback_ms':max(callback_ms),'callback_stats':stats(callback_ms),'ack_stats':stats(ack_ms),'api_stats':stats([api_ms]),'dashboard_risk_count':len(risks['items']),'risk_response':risks,'real_hermes_runtime':False,'package_install_runtime':False}
assert result['max_callback_ms']<50,out
out.write_text(json.dumps(result,sort_keys=True))
";
