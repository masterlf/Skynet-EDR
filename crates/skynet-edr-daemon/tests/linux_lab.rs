//! Linux lab safety-plan tests. These never require a privileged runner.

use skynet_edr_daemon::{build_manual_linux_lab_workflow, validate_linux_lab_plan, LinuxLabPlan};

#[test]
fn lab_plan_without_frederic_vm_details_is_blocked_fail_closed() {
    let plan = LinuxLabPlan::default();

    let error = validate_linux_lab_plan(&plan).expect_err("missing VM details must block");

    assert!(error.to_string().contains("disposable VM details"));
    assert!(error.to_string().contains("controlled sink"));
}

#[test]
fn lab_plan_requires_fake_honeytokens_and_manual_approval() {
    let plan = LinuxLabPlan {
        disposable_vm_label: Some("frederic-lab-vm-01".to_owned()),
        controlled_sink_label: Some("sinkhole-127.0.0.1".to_owned()),
        fake_honeytoken_labels: vec!["fake_aws_key".to_owned()],
        manual_approval_reference: None,
        allow_privileged_sensor_start: false,
    };

    let error = validate_linux_lab_plan(&plan).expect_err("manual approval is mandatory");

    assert!(error.to_string().contains("manual approval"));
}

#[test]
fn lab_plan_rejects_external_sink_labels_and_non_fake_honeytokens() {
    let plan = LinuxLabPlan {
        disposable_vm_label: Some("frederic-lab-vm-01".to_owned()),
        controlled_sink_label: Some("https://webhook.site/not-controlled".to_owned()),
        fake_honeytoken_labels: vec!["aws_key".to_owned()],
        manual_approval_reference: Some("discord-thread-approval".to_owned()),
        allow_privileged_sensor_start: false,
    };

    let error = validate_linux_lab_plan(&plan)
        .expect_err("external sinks and non-fake honeytokens are unsafe");

    assert!(error
        .to_string()
        .contains("controlled sink must be local or allowlisted"));
    assert!(error.to_string().contains("fake honeytoken labels"));
}

#[test]
fn accepted_lab_plan_is_manual_only_and_renders_no_real_secret_or_endpoint() {
    let plan = LinuxLabPlan {
        disposable_vm_label: Some("frederic-lab-vm-01".to_owned()),
        controlled_sink_label: Some("sinkhole-127.0.0.1".to_owned()),
        fake_honeytoken_labels: vec!["fake_aws_key".to_owned(), "fake_hermes_token".to_owned()],
        manual_approval_reference: Some("discord-thread-approval".to_owned()),
        allow_privileged_sensor_start: false,
    };

    validate_linux_lab_plan(&plan).expect("complete manual plan validates");
    let workflow = build_manual_linux_lab_workflow(&plan).expect("workflow renders");

    assert!(workflow.contains("manual-only"));
    assert!(workflow.contains("frederic-lab-vm-01"));
    assert!(workflow.contains("sinkhole-127.0.0.1"));
    assert!(workflow.contains("fake_aws_key"));
    assert!(!workflow.contains("sk-"));
    assert!(!workflow.contains("BEGIN PRIVATE KEY"));
    assert!(!workflow.contains("curl https://"));
}

#[test]
fn privileged_sensor_start_is_rejected_until_explicit_future_design() {
    let plan = LinuxLabPlan {
        disposable_vm_label: Some("frederic-lab-vm-01".to_owned()),
        controlled_sink_label: Some("sinkhole-127.0.0.1".to_owned()),
        fake_honeytoken_labels: vec!["fake_aws_key".to_owned()],
        manual_approval_reference: Some("discord-thread-approval".to_owned()),
        allow_privileged_sensor_start: true,
    };

    let error =
        validate_linux_lab_plan(&plan).expect_err("privileged startup is not permitted yet");

    assert!(error
        .to_string()
        .contains("privileged sensor start is not implemented"));
}
