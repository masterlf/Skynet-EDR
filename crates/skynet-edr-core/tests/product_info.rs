use skynet_edr_core::{ProductInfo, RunMode};

#[test]
fn product_info_identifies_the_security_runtime() {
    let info = ProductInfo::default();

    assert_eq!(info.name, "Skynet-EDR");
    assert_eq!(info.binary_name, "skynet-edr");
    assert_eq!(info.run_mode, RunMode::Passive);
}

#[test]
fn run_mode_labels_are_stable_for_operator_facing_output() {
    assert_eq!(RunMode::Passive.as_str(), "passive");
    assert_eq!(RunMode::Guard.as_str(), "guard");
    assert_eq!(RunMode::Enforcement.as_str(), "enforcement");
}
