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
use skynet_edr_core::{built_in_ai_agent_sequence_rules, parse_canonical_event_json, LocalStore};

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
    let synthetic_root = root.join("synthetic-secret-daemon");
    let synthetic_socket = synthetic_root.join("ingest.sock");
    let synthetic_db = synthetic_root.join("skynet.sqlite");
    let synthetic_config = root.join("synthetic-secret-config.toml");
    let synthetic_plugin_state = root.join("synthetic-secret-plugin-state");
    let fault_root = root.join("fault-daemon");
    let fault_socket = fault_root.join("ingest.sock");
    let fault_db = fault_root.join("skynet.sqlite");
    let fault_config = root.join("fault-config.toml");
    let fault_plugin_state = root.join("fault-plugin-state");
    fs::create_dir_all(&plugin_state).unwrap();
    fs::create_dir_all(&synthetic_plugin_state).unwrap();
    fs::create_dir_all(&synthetic_root).unwrap();
    fs::create_dir_all(&fault_plugin_state).unwrap();
    fs::create_dir_all(&fault_root).unwrap();
    let port = free_port();
    let synthetic_port = free_port();
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

    fs::write(
        &synthetic_config,
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
            synthetic_root.display(),
            synthetic_root.display(),
            synthetic_port,
            synthetic_socket.display(),
            uid == 0,
            if uid == 0 {
                String::new()
            } else {
                uid.to_string()
            }
        ),
    )
    .unwrap();
    let synthetic_log = fs::File::create(root.join("synthetic-secret-daemon.log")).unwrap();
    let mut synthetic_daemon = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .args(["run", "--config"])
        .arg(&synthetic_config)
        .stdout(Stdio::from(synthetic_log.try_clone().unwrap()))
        .stderr(Stdio::from(synthetic_log))
        .spawn()
        .expect("isolated synthetic-secret daemon starts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while (!synthetic_socket.exists() || TcpStream::connect(("127.0.0.1", synthetic_port)).is_err())
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        synthetic_socket.exists(),
        "isolated synthetic-secret socket exists"
    );

    fs::write(
        &fault_config,
        format!(
            r#"mode = "passive"
data_dir = "{}"
log_dir = "{}"
[http_api]
enabled = false
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
            fault_root.display(),
            fault_root.display(),
            fault_socket.display(),
            uid == 0,
            if uid == 0 {
                String::new()
            } else {
                uid.to_string()
            }
        ),
    )
    .unwrap();
    let fault_log = fs::File::create(root.join("fault-daemon.log")).unwrap();
    let mut fault_daemon = Command::new(env!("CARGO_BIN_EXE_skynet-edr-daemon"))
        .args(["run", "--config"])
        .arg(&fault_config)
        .stdout(Stdio::from(fault_log.try_clone().unwrap()))
        .stderr(Stdio::from(fault_log))
        .spawn()
        .expect("isolated fault daemon starts");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fault_socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(fault_socket.exists(), "isolated fault socket exists");

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
        .arg(&synthetic_socket)
        .arg(&synthetic_plugin_state)
        .arg(synthetic_port.to_string())
        .arg(&fault_socket)
        .arg(&fault_plugin_state)
        .arg(&output_path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python producer canary runs");
    if !output.status.success() {
        stop(&mut daemon);
        stop(&mut synthetic_daemon);
        stop(&mut fault_daemon);
        panic!(
            "producer canary failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let producer: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    let projection_runner = root.join("desktop_projection_canary.mjs");
    fs::write(&projection_runner, DESKTOP_PROJECTION_CANARY).unwrap();
    let projection_started = Instant::now();
    let projection = Command::new("node")
        .arg(&projection_runner)
        .arg(&repository)
        .arg(&output_path)
        .output()
        .expect("shipped Desktop projection validator runs");
    let desktop_projection_contract_ms = projection_started.elapsed().as_secs_f64() * 1_000.0;
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
    assert_eq!(
        producer["ack_status_histogram"]["persisted"],
        producer["terminal_acks"]
    );
    assert!(producer["ack_to_corresponding_risk_stats"]["sample_count"]
        .as_u64()
        .is_some_and(|count| count >= 7));
    assert_eq!(
        producer["risk_visibility_samples"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert!(producer["fault_evidence"]["queue_drops"].as_u64().unwrap() > 0);
    assert!(
        producer["fault_evidence"]["socket_failures"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        producer["fault_evidence"]["fallback_records"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(producer["fault_evidence"]["collision_ack"], "collision");
    assert!(
        producer["fault_evidence"]["backlog_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(producer["real_hermes_runtime"], false);
    let store = LocalStore::open_read_only(&db).expect("durable store opens read-only");
    let synthetic_store =
        LocalStore::open_read_only(&synthetic_db).expect("synthetic-secret store opens read-only");
    assert_eq!(
        store.count_events().unwrap() + synthetic_store.count_events().unwrap(),
        usize::try_from(producer["generated"].as_u64().unwrap()).unwrap()
    );
    for phase_store in [&store, &synthetic_store] {
        assert_eq!(
            phase_store.count_ingest_receipts().unwrap(),
            phase_store.count_events().unwrap()
        );
    }
    let baseline_incidents = store.list_incidents().unwrap();
    let synthetic_incidents = synthetic_store.list_incidents().unwrap();
    for (phase, incidents, expected) in [
        (
            "baseline",
            &baseline_incidents,
            producer["expected_baseline_by_rule"].as_object().unwrap(),
        ),
        (
            "synthetic-secret",
            &synthetic_incidents,
            producer["expected_synthetic_by_rule"].as_object().unwrap(),
        ),
    ] {
        assert_eq!(
            incidents.len(),
            expected
                .values()
                .map(|count| usize::try_from(count.as_u64().unwrap()).unwrap())
                .sum::<usize>(),
            "{phase} incident cardinality"
        );
        for (rule, count) in expected {
            assert_eq!(
                incidents
                    .iter()
                    .filter(|incident| incident.id.as_str().contains(rule))
                    .count(),
                usize::try_from(count.as_u64().unwrap()).unwrap(),
                "{phase} {rule}"
            );
        }
    }
    assert_eq!(baseline_incidents.len() + synthetic_incidents.len(), 9);

    let fault_store = LocalStore::open(root.join("fault-correlation.sqlite"))
        .expect("isolated correlation fault store opens");
    let corpus: Value = serde_json::from_slice(
        &fs::read(
            repository.join("crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mcp_events = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["case_id"] == "malicious_mcp")
        .unwrap()["events"]
        .as_array()
        .unwrap();
    let rules = built_in_ai_agent_sequence_rules();
    for (index, source) in [0_usize, 0, 1].into_iter().enumerate() {
        let mut event = mcp_events[source].clone();
        let event_id = format!("evt_s2_truncation_{index}");
        event["event_id"] = Value::String(event_id.clone());
        event["provenance"]["source_event_id"] = Value::String(event_id.clone());
        event["provenance"]["span_id"] = Value::String(event_id);
        event["provenance"]["trace_id"] = Value::String("s2-fault-truncation".into());
        let parsed = parse_canonical_event_json(&event.to_string()).unwrap();
        fault_store
            .commit_continuous_event("uid:4242", &parsed, &rules, 1)
            .unwrap();
    }
    let truncations = fault_store
        .list_incidents()
        .unwrap()
        .iter()
        .filter(|incident| {
            incident
                .id
                .as_str()
                .contains("continuous-correlation-degraded")
        })
        .count() as u64;
    assert!(truncations > 0, "real bounded correlation fault is durable");

    let connection = rusqlite::Connection::open_with_flags(
        &fault_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let collisions = connection
        .query_row("SELECT COUNT(*) FROM ingest_collisions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        .cast_unsigned();
    assert!(collisions > 0, "real AF_UNIX collision evidence is durable");
    let accounting = CanaryAccounting::from_observed(
        producer["generated"].as_u64().unwrap(),
        producer["enqueued"].as_u64().unwrap(),
        producer["terminal_acks"].as_u64().unwrap(),
        (store.count_ingest_receipts().unwrap() + synthetic_store.count_ingest_receipts().unwrap())
            as u64,
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
            "ack_to_corresponding_risk_ms": producer["ack_to_corresponding_risk_stats"],
            "dashboard_fetch_contract_ms": producer["dashboard_fetch_contract_stats"],
            "desktop_projection_contract_ms": desktop_projection_contract_ms,
            "ack_status_histogram": producer["ack_status_histogram"],
            "path_accounting": producer["path_accounting"],
            "risk_visibility_samples": producer["risk_visibility_samples"],
            "expected_baseline_by_rule": producer["expected_baseline_by_rule"],
            "expected_synthetic_by_rule": producer["expected_synthetic_by_rule"],
            "baseline_risk_count": producer["baseline_risk_count"],
            "synthetic_secret_incident_count": producer["synthetic_secret_incident_count"],
            "dashboard_risk_count": producer["dashboard_risk_count"],
            "fault_evidence": producer["fault_evidence"]
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
    assert_eq!(producer["synthetic_secret_incident_count"], 2);
    assert_eq!(risks["items"].as_array().unwrap().len(), 9);
    assert_eq!(producer["dashboard_risk_count"], 9);
    assert_eq!(producer["risk_details"].as_array().unwrap().len(), 9);
    for item in risks["items"].as_array().unwrap() {
        assert!(item["title"]
            .as_str()
            .is_some_and(|title| !title.is_empty()));
        assert!(item["summary"]
            .as_str()
            .is_some_and(|summary| summary.starts_with("Read-only projection")));
    }

    stop(&mut daemon);
    stop(&mut synthetic_daemon);
    stop(&mut fault_daemon);
    drop(store);
    drop(synthetic_store);
    let mut scanned = Vec::new();
    for path in [
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
        synthetic_db.clone(),
        PathBuf::from(format!("{}-wal", synthetic_db.display())),
        PathBuf::from(format!("{}-shm", synthetic_db.display())),
        fault_db.clone(),
        root.join("daemon.log"),
        root.join("synthetic-secret-daemon.log"),
        root.join("fault-daemon.log"),
        plugin_state.join("skynet-edr-plugin.log"),
        plugin_state.join("events-v1.jsonl"),
        synthetic_plugin_state.join("skynet-edr-plugin.log"),
        synthetic_plugin_state.join("events-v1.jsonl"),
        fault_plugin_state.join("skynet-edr-plugin.log"),
        fault_plugin_state.join("events-v1.jsonl"),
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
import collections,copy,importlib.util,json,os,queue,sys,time,types,urllib.parse
from pathlib import Path
repo,socket,state,port,synthetic_socket,synthetic_state,synthetic_port,fault_socket,fault_state,out=Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),sys.argv[4],sys.argv[5],Path(sys.argv[6]),sys.argv[7],sys.argv[8],Path(sys.argv[9]),Path(sys.argv[10])
os.environ.pop('HERMES_SESSION_ID',None);os.environ.pop('HERMES_SESSION',None)
os.environ.update(SKYNET_EDR_STATE_DIR=str(state),SKYNET_EDR_INGEST_SOCKET=socket,SKYNET_EDR_API_PORT=port,SKYNET_EDR_SOCKET_TIMEOUT_MS='1000')
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
plugin=load('skynet_s2_runtime_plugin',repo/'integrations/hermes/skynet-edr/__init__.py')
manifest=json.loads((repo/'crates/skynet-edr-core/tests/fixtures/detections/v1/manifest.json').read_text())
baseline_cases=[case for case in manifest['cases'] if case['category']=='malicious']
synthetic_cases=[case for case in manifest['cases'] if case['category']=='synthetic_secret']
expected_baseline_by_rule=dict(collections.Counter(case['rule_id'] for case in baseline_cases))
expected_synthetic_by_rule=dict(collections.Counter(case['rule_id'] for case in synthetic_cases))
assert len(expected_baseline_by_rule)==7 and set(expected_baseline_by_rule.values())=={1},expected_baseline_by_rule
expected_risk_count=sum(expected_baseline_by_rule.values())+sum(expected_synthetic_by_rule.values())
class C:
 def __init__(self):self.hooks={}
 def register_hook(self,n,c):self.hooks[n]=c
class Router:
 def get(self,path):return lambda f:f
fast=types.ModuleType('fastapi');fast.APIRouter=Router;fast.Query=lambda default,**kw:default
class HTTPException(Exception):
 def __init__(self,status_code,detail):self.status_code=status_code;self.detail=detail
fast.HTTPException=HTTPException;sys.modules['fastapi']=fast
api=load('skynet_s2_dashboard_api',repo/'integrations/hermes/skynet-edr/dashboard/plugin_api.py')
ctx=C();acks=[];ack_ms=[];ack_at_by_event={};canonical=[];generated=0;enqueued=[0];callback_ms=[];secret_input_markers=0;visibility=[];fetch_ms=[]
orig_send=plugin._send_frame;orig_write=plugin._write_event
def observed_send(line):
 event=json.loads(line);started=time.monotonic();status=orig_send(line);finished=time.monotonic();ack_ms.append((finished-started)*1000);ack_at_by_event[event['event_id']]=finished;acks.append(status);canonical.append(event);return status
def observed_write(**kwargs):
 global generated
 generated+=1
 return orig_write(**kwargs)
class ObservedQueue:
 def __init__(self,inner):self.inner=inner
 def put_nowait(self,item):self.inner.put_nowait(item);enqueued[0]+=1
 def __getattr__(self,name):return getattr(self.inner,name)
plugin._event_queue=ObservedQueue(plugin._event_queue);plugin._send_frame=observed_send;plugin._write_event=observed_write;plugin.register(ctx)
def fetch_risks():
 started=time.monotonic();value=api._upstream('/api/v1/risks',{'limit':50,'offset':0});fetch_ms.append((time.monotonic()-started)*1000);return value
for case in manifest['cases']:
 if case['category'] not in {'malicious','near_miss'}:continue
 plugin._session_trace_id='s2-runtime-'+case['case_id']
 start=len(canonical)
 for call in case['producer_calls']:
  started=time.monotonic();ctx.hooks[call['hook']](*call['args'],**call['kwargs']);callback_ms.append((time.monotonic()-started)*1000)
 plugin._event_queue.join()
 if case['category']=='malicious':
  trigger=canonical[-1]['event_id'];deadline=time.monotonic()+2
  while True:
   visible_at=time.monotonic();page=fetch_risks();risk=next((item for item in page['items'] if case['rule_id'] in item['id']),None)
   if risk is not None:break
   assert time.monotonic()<deadline,(case['case_id'],page)
   time.sleep(.01)
  visibility.append({'event_id':trigger,'rule_id':case['rule_id'],'risk_id':risk['id'],'latency_ms':(visible_at-ack_at_by_event[trigger])*1000})
baseline_risks=fetch_risks()
assert len(baseline_risks['items'])==sum(expected_baseline_by_rule.values()),baseline_risks
baseline_details=[api._upstream('/api/v1/risks/'+urllib.parse.quote(item['id'],safe=''),{}) for item in baseline_risks['items']]
os.environ.update(SKYNET_EDR_STATE_DIR=str(synthetic_state),SKYNET_EDR_INGEST_SOCKET=synthetic_socket,SKYNET_EDR_API_PORT=synthetic_port)
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
 synthetic_risks=fetch_risks()
 if len(synthetic_risks['items'])==sum(expected_synthetic_by_rule.values()):break
 assert time.monotonic()<deadline,synthetic_risks
 time.sleep(.01)
synthetic_details=[api._upstream('/api/v1/risks/'+urllib.parse.quote(item['id'],safe=''),{}) for item in synthetic_risks['items']]
risks=copy.deepcopy(baseline_risks);risks['items']+=synthetic_risks['items'];risks['page'].update(returned=expected_risk_count,total=expected_risk_count)
risk_details=baseline_details+synthetic_details
def stats(values):
 values=sorted(values);n=len(values);return {'sample_count':n,'p50':values[(n-1)//2],'p95':values[max(0,(95*n+99)//100-1)],'max':values[-1]}
status_histogram=dict(collections.Counter(acks));normal_generated=generated;normal_enqueued=enqueued[0];normal_counters=dict(plugin._transport_counters);normal_backlog=plugin._event_queue.qsize()
os.environ.update(SKYNET_EDR_STATE_DIR=str(fault_state),SKYNET_EDR_INGEST_SOCKET=fault_socket)
plugin._ensure_worker=lambda:None;plugin._event_queue=queue.Queue(maxsize=1)
fault_args={'event_type':'agent.session.started','source_kind':'sensor','trust_level':'sensor_observation','severity':'informational','title':'S2 fault queue probe','attributes':{'fault_probe':True}}
orig_write(**fault_args);orig_write(**fault_args);plugin._event_queue.get_nowait()
probe=copy.deepcopy(canonical[0]);probe_id='evt_s2_fault_collision';probe['event_id']=probe_id;probe['provenance']['source_event_id']=probe_id;probe['provenance']['span_id']=probe_id;probe['provenance']['trace_id']='s2-fault-collision';fault_line=json.dumps(probe,separators=(',',':'),sort_keys=True)
os.environ['SKYNET_EDR_INGEST_SOCKET']=str(fault_state/'missing.sock');socket_status=orig_send(fault_line);plugin._append_fallback(fault_line);os.environ['SKYNET_EDR_INGEST_SOCKET']=fault_socket
fault_persist_ack=orig_send(fault_line);collision=json.loads(fault_line);collision['observed_at_unix_ms']+=1;collision['received_at_unix_ms']+=1;collision_ack=orig_send(json.dumps(collision,separators=(',',':'),sort_keys=True))
fault_counters={key:plugin._transport_counters[key]-normal_counters[key] for key in normal_counters};backlog_bytes=plugin._spool_path().stat().st_size-plugin._read_checkpoint(plugin._checkpoint_path())
fault={'queue_drops':fault_counters['queue_drops'],'socket_failures':fault_counters['socket_failures'],'fallback_records':fault_counters['fallback_records'],'backlog_bytes':backlog_bytes,'fault_persist_ack':fault_persist_ack,'collision_ack':collision_ack}
result={'generated':normal_generated,'enqueued':normal_enqueued,'terminal_acks':len(acks),'ack_status_histogram':status_histogram,'persisted_or_duplicate':sum(x in {'persisted','duplicate'} for x in acks),'fallback_records':normal_counters['fallback_records'],'queue_drops':normal_counters['queue_drops'],'socket_failures':normal_counters['socket_failures'],'backlog':normal_backlog,'path_accounting':{'enqueue':{'numerator':normal_enqueued,'denominator':normal_generated},'terminal_ack':{'numerator':len(acks),'denominator':normal_enqueued},'durable_ack':{'numerator':sum(x in {'persisted','duplicate'} for x in acks),'denominator':len(acks)}},'fault_evidence':fault,'max_callback_ms':max(callback_ms),'callback_stats':stats(callback_ms),'ack_stats':stats(ack_ms),'ack_to_corresponding_risk_stats':stats([item['latency_ms'] for item in visibility]),'risk_visibility_samples':visibility,'dashboard_fetch_contract_stats':stats(fetch_ms),'expected_baseline_by_rule':expected_baseline_by_rule,'expected_synthetic_by_rule':expected_synthetic_by_rule,'baseline_risk_count':len(baseline_risks['items']),'synthetic_secret_incident_count':len(synthetic_risks['items']),'dashboard_risk_count':len(risks['items']),'risk_response':risks,'risk_details':risk_details,'canonical_events':canonical,'secret_input_markers':secret_input_markers,'real_hermes_runtime':False,'package_install_runtime':False}
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
