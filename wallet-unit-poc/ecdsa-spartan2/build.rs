use std::path::Path;

#[cfg(feature = "cert_chain_rs2048")]
const CERT_CHAIN_RS2048_CIRCUIT_NAME: &str = "certChainRS2048";
#[cfg(feature = "cert_chain_rs4096")]
const CERT_CHAIN_RS4096_CIRCUIT_NAME: &str = "certChainRS4096";
#[cfg(feature = "user_sig_rs2048")]
const USER_SIG_RS2048_CIRCUIT_NAME: &str = "userSigRS2048";

fn is_ios_target(target: &str) -> bool {
    matches!(
        target,
        "aarch64-apple-ios-sim" | "aarch64-apple-ios" | "x86_64-apple-ios"
    )
}

#[allow(unused_variables)]
fn main() {
    chkstk_stub::build();

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circom_build_dir = std::path::PathBuf::from(&manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .join("circom/build/cpp");
    let local_circuits_dir = std::path::PathBuf::from(&manifest_dir).join("circuits");
    let circuits_dir = if circom_build_dir.exists() {
        println!(
            "cargo:warning=Using compiled circuits from: {}",
            circom_build_dir.display()
        );
        circom_build_dir
    } else {
        println!(
            "cargo:warning=circom build not found; falling back to local circuits dir: {}",
            local_circuits_dir.display()
        );
        local_circuits_dir
    };

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    if let Ok(witnesscalc_cache) = std::env::var("WITNESSCALC_PREBUILD_CACHE") {
        let target = std::env::var("TARGET").unwrap_or_default();

        if is_ios_target(target.as_str()) {
            let cache_src = Path::new(&witnesscalc_cache);
            let target_witnesscalc = Path::new(&out_dir).join("witnesscalc");

            if cache_src.exists() && !target_witnesscalc.exists() {
                #[cfg(unix)]
                {
                    println!(
                        "cargo:warning=Using cached witnesscalc from: {}",
                        cache_src.display()
                    );
                    std::os::unix::fs::symlink(&cache_src, &target_witnesscalc).ok();
                }
            }
        }
    }

    let staging_dir = Path::new(&out_dir).join("circuit_staging");
    std::fs::create_dir_all(&staging_dir).expect("Failed to create staging directory");

    #[cfg(feature = "cert_chain_rs2048")]
    stage_circuit(&circuits_dir, &staging_dir, CERT_CHAIN_RS2048_CIRCUIT_NAME);
    #[cfg(feature = "cert_chain_rs4096")]
    stage_circuit(&circuits_dir, &staging_dir, CERT_CHAIN_RS4096_CIRCUIT_NAME);
    #[cfg(feature = "user_sig_rs2048")]
    stage_circuit(&circuits_dir, &staging_dir, USER_SIG_RS2048_CIRCUIT_NAME);

    witnesscalc_adapter::build_and_link(staging_dir.to_str().unwrap());

    if let Ok(entries) = std::fs::read_dir(&circuits_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map_or(false, |ext| ext == "cpp" || ext == "dat")
            {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

#[allow(unused)]
fn stage_circuit(circuits_dir: &Path, staging_dir: &Path, circuit_name: &str) {
    for ext in &["cpp", "dat"] {
        let src = circuits_dir.join(format!("{}.{}", circuit_name, ext));
        let dst = staging_dir.join(format!("{}.{}", circuit_name, ext));
        if src.exists() {
            std::fs::copy(&src, &dst).unwrap_or_else(|e| {
                panic!(
                    "Failed to copy {} to {}: {}",
                    src.display(),
                    dst.display(),
                    e
                )
            });
        } else {
            panic!(
                "Required circuit file not found: {}. Either run `yarn compile:{}` in the circom directory, or add the file to the local circuits/ folder.",
                src.display(),
                circuit_name
            );
        }
    }
}
