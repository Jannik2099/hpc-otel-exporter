use libbpf_cargo::SkeletonBuilder;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// One standalone BPF object per collected signal, each compiled into its own
/// skeleton (`<name>.skel.rs`), so a signal's programs/maps only exist when the
/// signal is enabled at runtime.
const BPF_SRCS: &[&str] = &[
    "src/bpf/io.bpf.c",
    "src/bpf/metadata.bpf.c",
    "src/bpf/profiling.bpf.c",
];
/// Bindgen entry point: aggregates every per-feature shared-type header so all
/// shared structs/enums/constants land in one `crate::bindings` module.
const SHARED_HEADER: &str = "src/bpf/shared.h";
/// Headers `#include`d into the [`BPF_SRCS`] objects. Changing any of them must
/// retrigger the skeleton + bindgen build, but only the sources are compiled.
const BPF_HEADERS: &[&str] = &[
    "src/bpf/io.h",
    "src/bpf/metadata.h",
    "src/bpf/vfs_types.h",
    "src/bpf/vfs_common.bpf.h",
    "src/bpf/profiling.h",
    "src/bpf/cgroup_id.bpf.h",
    "src/bpf/numa_ringbuf.bpf.h",
    "src/bpf/prelude.h",
];
const PPROF_PROTO: &str = "profile.proto";
const PUSH_PROTO: &str = "pyroscope_push.proto";

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    // Get the stable target directory (not profile-specific OUT_DIR)
    let target_dir = get_target_dir();

    // Create a stable subdirectory for generated BPF headers in target/
    let bpf_headers_dir = target_dir.join("bpf_headers");
    fs::create_dir_all(&bpf_headers_dir).expect("Failed to create bpf_headers directory");

    // Generate vmlinux.h in the stable location
    let vmlinux_path = bpf_headers_dir.join("vmlinux.h");

    // Only regenerate vmlinux.h if it doesn't exist
    if !vmlinux_path.exists() {
        let status = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to execute bpftool - ensure it's installed");

        if !status.status.success() {
            panic!(
                "bpftool failed: {}",
                String::from_utf8_lossy(&status.stderr)
            );
        }

        fs::write(&vmlinux_path, status.stdout).expect("Failed to write vmlinux.h");

        println!("Generated vmlinux.h at {:?}", vmlinux_path);
    } else {
        println!("Using existing vmlinux.h at {:?}", vmlinux_path);
    }

    let extra_clang_args = vec![
        // generated vmlinux.h is incompatible with C23 native bool as of 2026 :(
        "-std=gnu17",
        "-Wno-c23-extensions",
        "-Wall",
        "-Werror",
        "-isystem",
        bpf_headers_dir.to_str().unwrap(),
        "-mcpu=v3",
        // bpf_tracing.h's PT_REGS_* macros need the target arch spelled out
        // this is just for compile_commands.json
        "-D__TARGET_ARCH_x86",
    ];
    generate_compile_commands(&extra_clang_args);

    // Generate Rust bindings from common_shared.h
    generate_bindings(&bpf_headers_dir, &out_dir);

    // Build one BPF skeleton per signal object.
    for src in BPF_SRCS {
        let stem = Path::new(src)
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".bpf.c"))
            .expect("BPF source named <name>.bpf.c");
        let skel_path = out_dir.join(format!("{stem}.skel.rs"));

        SkeletonBuilder::new()
            .source(src)
            .clang_args(&extra_clang_args)
            .build_and_generate(&skel_path)
            .unwrap_or_else(|e| panic!("bpf compilation of {src} failed: {e}"));
    }

    let perf_bindings = bindgen::Builder::default()
        .header("bindgen/perf_event.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate perf_event bindings");

    perf_bindings
        .write_to_file(out_dir.join("perf_event_bindings.rs"))
        .expect("Couldn't write perf_event bindings!");

    // Compile the protobuf definitions:
    // pprof (package google.v1 -> google.v1.rs)
    // Pyroscope push API (package push.v1 -> push.v1.rs).
    if env::var_os("PROTOC").is_none()
        && let Ok(protoc) = protoc_bin_vendored::protoc_bin_path()
    {
        unsafe { env::set_var("PROTOC", protoc) };
    }
    prost_build::compile_protos(&[PPROF_PROTO, PUSH_PROTO], &["."])
        .expect("failed to compile protobuf definitions");
    println!("cargo:rerun-if-changed={}", PPROF_PROTO);
    println!("cargo:rerun-if-changed={}", PUSH_PROTO);

    println!("cargo:rerun-if-changed={}", SHARED_HEADER);
    for path in BPF_SRCS.iter().chain(BPF_HEADERS) {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn get_target_dir() -> PathBuf {
    // Try CARGO_TARGET_DIR first (if user has set it)
    if let Ok(target) = env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target);
    }

    // Otherwise, derive from CARGO_MANIFEST_DIR
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir).join("target")
}

fn generate_compile_commands(extra_clang_args: &Vec<&str>) {
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let compile_commands_path = PathBuf::from(&project_root)
        .join("target")
        .join("compile_commands.json");

    // One entry per BPF object, each matching the clang command libbpf-cargo uses.
    let entries: Vec<serde_json::Value> = BPF_SRCS
        .iter()
        .map(|src| {
            let src_file = PathBuf::from(&project_root).join(src);
            let mut args = vec!["clang", "-target", "bpf", "-g", "-O2"];
            args.extend(extra_clang_args.iter().cloned());
            args.extend(["-c", src_file.to_str().unwrap()]);
            serde_json::json!({
                "directory": project_root,
                "file": src_file,
                "arguments": args,
            })
        })
        .collect();

    fs::write(
        &compile_commands_path,
        serde_json::to_string_pretty(&entries).unwrap(),
    )
    .expect("Failed to write compile_commands.json");

    println!(
        "Generated compile_commands.json at {:?}",
        compile_commands_path
    );
}

fn generate_bindings(bpf_headers_dir: &Path, out_dir: &Path) {
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let header_path = PathBuf::from(&project_root).join(SHARED_HEADER);
    let bindings_path = out_dir.join("bindings.rs");

    println!("Generating Rust bindings from {:?}", header_path);

    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .clang_args(["-target", "bpf"])
        // Add the bpf_headers directory to the include path
        .clang_arg(format!("-I{}", bpf_headers_dir.to_str().unwrap()))
        // Derive useful traits
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_partialeq(true)
        // Generate bindings for the types we care about
        .allowlist_type("FsMagic")
        .allowlist_type("TimeInfo")
        .allowlist_type("IOType")
        .rustified_enum("IOType")
        .allowlist_type("IOEvent")
        // VFS metadata shared types (src/bpf/metadata.h).
        .allowlist_type("MetadataEvent")
        .allowlist_type("MetadataOp")
        .rustified_enum("MetadataOp")
        .allowlist_type("StackKey")
        // Native-unwinder shared types (src/bpf/common_shared.h).
        .allowlist_type("UnwindRow")
        .allowlist_type("UnwindMiss")
        .allowlist_type("MappingEntry")
        .allowlist_type("ProcessMappings")
        .allowlist_type("ExecInfo")
        .allowlist_type("Stack")
        .allowlist_type("CfaType")
        .allowlist_type("RbpRule")
        .allowlist_var("MAX_STACK_DEPTH")
        .allowlist_var("MAX_ROWS_PER_EXEC")
        .allowlist_var("MAX_EXECUTABLES")
        .allowlist_var("MAX_MAPPINGS_PER_PROC")
        .rustified_enum("CfaType")
        .rustified_enum("RbpRule")
        // Make the enum a proper Rust enum with variants
        .rustified_non_exhaustive_enum("FsMagic")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!("Generated Rust bindings at {:?}", bindings_path);
}
