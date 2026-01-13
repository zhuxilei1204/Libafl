//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
use core::time::Duration;
use std::{
    collections::VecDeque,
    env,
    fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use libc;

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig, SimpleEventManager},
    executors::{ExitKind, Executor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    AsSlice,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    breakpoint::Breakpoint,
    command::{EndCommand, StartCommand},
    elf::EasyElf,
    emu::Emulator,
    executor::QemuExecutor,
    modules::edges::StdEdgeCoverageModule,
    EmulatorExitResult, GuestPhysAddr, GuestReg, InputLocation, QemuMemoryChunk,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
// (unused imports removed)
// use libafl_qemu::QemuSnapshotBuilder; // for normal qemu snapshot
use libafl_qemu::sys::TCGTemp;
use libafl_qemu::qemu::MemAccessInfo;
use libafl_qemu::GuestAddr;
pub static mut MAX_INPUT_SIZE: usize =1024;
const REPRO_RING_SIZE: u64 = 64;

#[cfg(target_os = "linux")]
fn install_parent_death_sigkill() {
    // If our parent (for example `just`/shell) goes away, we want the whole
    // fuzzing process tree to die instead of becoming orphaned.
    // This is especially important because the launcher forks broker/clients.
    unsafe {
        // Best-effort: ignore failures (non-Linux kernels, seccomp, etc.).
        let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        // If parent already died between fork/exec and prctl, avoid running as an orphan.
        if libc::getppid() == 1 {
            process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn install_parent_death_sigkill() {}

#[derive(Debug, Clone, Copy)]
struct FuzzLastOp {
    step: u32,
    action: u32,
    slot: u32,
    size: u32,
    aux: u32,
    ptr: u32,
}

fn parse_fuzz_last_op(buf: &[u8]) -> Option<FuzzLastOp> {
    if buf.len() < 24 {
        return None;
    }
    let u32_le = |off: usize| u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    Some(FuzzLastOp {
        step: u32_le(0),
        action: u32_le(4),
        slot: u32_le(8),
        size: u32_le(12),
        aux: u32_le(16),
        ptr: u32_le(20),
    })
}

fn pad_input_to_max(input: &[u8], max: usize) -> BytesInput {
    let mut padded = vec![0u8; max];
    let copy_len = core::cmp::min(input.len(), max);
    padded[..copy_len].copy_from_slice(&input[..copy_len]);
    BytesInput::new(padded)
}

fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn dump_recent_inputs(recent: &VecDeque<Vec<u8>>, out_dir: &Path) -> std::io::Result<PathBuf> {
    fs::create_dir_all(out_dir)?;
    let seq_dir = out_dir.join(format!("seq_{}", now_unix_millis()));
    fs::create_dir_all(&seq_dir)?;

    let mut manifest = String::new();
    for (i, bytes) in recent.iter().enumerate() {
        let name = format!("{:03}.bin", i);
        let path = seq_dir.join(&name);
        fs::write(&path, bytes)?;
        manifest.push_str(&format!("{} {}\n", name, bytes.len()));
    }
    fs::write(seq_dir.join("manifest.txt"), manifest)?;
    Ok(seq_dir)
}

fn list_sequence_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    // If cursor.txt exists, treat this as a ring buffer directory and replay in logical order.
    let cursor_path = dir.join("cursor.txt");
    if cursor_path.is_file() {
        let s = fs::read_to_string(&cursor_path)?;
        let mut cursor: Option<u64> = None;
        let mut count: Option<u64> = None;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("cursor=") {
                cursor = v.trim().parse::<u64>().ok();
            } else if let Some(v) = line.strip_prefix("count=") {
                count = v.trim().parse::<u64>().ok();
            }
        }
        let cursor = cursor.unwrap_or(0);
        let count = count.unwrap_or(REPRO_RING_SIZE).min(REPRO_RING_SIZE);
        let start_abs = cursor.saturating_add(1).saturating_sub(count);
        let mut ordered = Vec::with_capacity(count as usize);
        for abs in start_abs..=cursor {
            let slot = (abs % REPRO_RING_SIZE) as usize;
            ordered.push(dir.join(format!("{:03}.bin", slot)));
        }
        // Only keep existing *.bin files.
        ordered.retain(|p| p.is_file());
        return Ok(ordered);
    }

    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            if !p.is_file() {
                return false;
            }
            // Only accept the binary inputs we generate (000.bin .. 063.bin).
            match (p.file_name().and_then(|s| s.to_str()), p.extension().and_then(|s| s.to_str())) {
                (Some(name), Some("bin")) => name.len() == 7 && name.as_bytes()[3] == b'.',
                _ => false,
            }
        })
        .collect();
    files.sort();
    Ok(files)
}


// 定义在 run_client 外部，或者 main 函数之前
unsafe extern "C" fn magic_write_gen(
    _data: u64,
    _pc: GuestAddr,
    _addr: *mut TCGTemp,
    _info: MemAccessInfo,
) -> u64 {
    1 // 返回非0值，表示需要对该指令进行插桩（即调用 exec 函数）
}

unsafe extern "C" fn magic_write_exec(
    target_addr: u64,
    _id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) {
    // 修复点：将 32位的 addr 转换为 64位后再进行比较
    if (addr as u64) == target_addr {
        println!("[!] Magic MMIO Write Detected at {:#x}! Triggering Crash...", addr);
        panic!("Magic Crash Triggered!");
    }
}

fn parse_u64_env(name: &str) -> Option<u64> {
    let s = env::var(name).ok()?;
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}
pub fn fuzz() {
    env_logger::init();
    install_parent_death_sigkill();

    // If set, run exactly one input and exit (useful for deterministic replay/debugging).
    // The run still uses the same breakpoint-based StartCommand/EndCommand flow.
    let replay_input = env::var_os("REPLAY_INPUT").map(PathBuf::from);
    let replay_seq_dir = env::var_os("REPLAY_SEQ_DIR").map(PathBuf::from);

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };
    // Hardcoded parameters
    let timeout = Duration::from_secs(3);
    let broker_port = 1330;
    let cores = Cores::from_cmdline("1").unwrap();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(
        env::var("KERNEL").expect("KERNEL env not set"),
        &mut elf_buffer,
    )
    .unwrap();

    let input_addr = elf
        .resolve_symbol(
            &env::var("FUZZ_INPUT").unwrap_or_else(|_| "FUZZ_INPUT".to_owned()),
            0,
        )
        .expect("Symbol or env FUZZ_INPUT not found") as GuestPhysAddr;
    println!("FUZZ_INPUT @ {input_addr:#x}");

    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("Symbol main not found");
    println!("main address = {main_addr:#x}");

    let breakpoint = elf
        .resolve_symbol(
            &env::var("BREAKPOINT").unwrap_or_else(|_| "BREAKPOINT".to_owned()),
            0,
        )
        .expect("Symbol or env BREAKPOINT not found");
    println!("Breakpoint address = {breakpoint:#x}");

    let last_op_addr = elf
        .resolve_symbol(
            &env::var("FUZZ_LAST_OP").unwrap_or_else(|_| "FUZZ_LAST_OP".to_owned()),
            0,
        )
        .map(|a| a as GuestPhysAddr);
    if let Some(addr) = last_op_addr {
        println!("FUZZ_LAST_OP @ {addr:#x}");
    } else {
        println!("FUZZ_LAST_OP symbol not found (skipping last-op printing)");
    }

    if replay_input.is_some() || replay_seq_dir.is_some() {
        let args: Vec<String> = env::args().collect();
        let max = unsafe { MAX_INPUT_SIZE };
        let mut inputs: Vec<(String, BytesInput)> = Vec::new();

        if let Some(dir) = replay_seq_dir.clone() {
            let files = list_sequence_files(&dir)
                .unwrap_or_else(|e| panic!("Failed to list REPLAY_SEQ_DIR {}: {e}", dir.display()));
            if files.is_empty() {
                panic!("REPLAY_SEQ_DIR {} contains no files", dir.display());
            }
            println!("[REPLAY_SEQ] dir={} files={} padded_to={}", dir.display(), files.len(), max);
            for p in files {
                let bytes = fs::read(&p)
                    .unwrap_or_else(|e| panic!("Failed to read {}: {e}", p.display()));
                inputs.push((p.display().to_string(), pad_input_to_max(&bytes, max)));
            }
        } else {
            let path = replay_input.clone().unwrap();
            let input_bytes = fs::read(&path)
                .unwrap_or_else(|e| panic!("Failed to read REPLAY_INPUT {}: {e}", path.display()));
            println!(
                "[REPLAY] input={} ({} bytes, padded to {})",
                path.display(),
                input_bytes.len(),
                max
            );
            inputs.push((path.display().to_string(), pad_input_to_max(&input_bytes, max)));
        }

        // Minimal local manager (no Launcher) for single-run replay.
        let monitor = MultiMonitor::new(|s| println!("{s}"));
        let mut mgr = SimpleEventManager::new(monitor);

        // Harness: run once. In replay mode we stop at the BREAKPOINT address without EndCommand,
        // so we can read FUZZ_LAST_OP before any snapshot restore.
        let last_op_addr_copy = last_op_addr;
        let mut harness = move |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                _state: &mut _,
                                input: &BytesInput| unsafe {
            let padded_input = pad_input_to_max(input.target_bytes().as_slice(), max);

            let (exit_kind, stopped_at_breakpoint): (ExitKind, bool) = match emulator.run(&padded_input) {
                Ok(r) => match r {
                    libafl_qemu::emu::EmulatorDriverResult::ReturnToClient(EmulatorExitResult::Breakpoint(_)) => {
                        (ExitKind::Ok, true)
                    }
                    libafl_qemu::emu::EmulatorDriverResult::EndOfRun(k) => (k, false),
                    libafl_qemu::emu::EmulatorDriverResult::ReturnToClient(EmulatorExitResult::Timeout) => {
                        (ExitKind::Timeout, false)
                    }
                    libafl_qemu::emu::EmulatorDriverResult::ReturnToClient(EmulatorExitResult::Crash) => {
                        (ExitKind::Crash, false)
                    }
                    _ => (ExitKind::Crash, false),
                },
                Err(e) => {
                    eprintln!("[REPLAY] emulator.run error: {e:?}");
                    (ExitKind::Crash, false)
                }
            };

            if let Some(addr) = last_op_addr_copy {
                let mut buf = [0u8; 24];
                emulator.qemu().read_phys_mem(addr, &mut buf);
                if let Some(op) = parse_fuzz_last_op(&buf) {
                    println!(
                        "[REPLAY] exit={:?} breakpoint_stop={} last_op: step={} action={} slot={} size={} aux={} ptr=0x{:08x}",
                        exit_kind,
                        stopped_at_breakpoint,
                        op.step,
                        op.action,
                        op.slot,
                        op.size,
                        op.aux,
                        op.ptr
                    );
                } else {
                    println!(
                        "[REPLAY] exit={:?} breakpoint_stop={} last_op: failed to parse",
                        exit_kind, stopped_at_breakpoint
                    );
                }
            }

            exit_kind
        };

        // Observers/modules.
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };
        let time_observer = TimeObserver::new("time");
        let modules = tuple_list!(StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()
            .unwrap());

        // Initialize QEMU Emulator.
        let mut emu = Emulator::builder()
            .qemu_parameters(args)
            .modules(modules)
            .build()
            .expect("Failed to build Emulator");

        let qemu = emu.qemu();
        emu.add_breakpoint(
            Breakpoint::with_command(
                main_addr,
                StartCommand::new(InputLocation::new(
                    qemu,
                    &QemuMemoryChunk::phys(
                        input_addr,
                        max as GuestReg,
                        qemu.cpu_from_index(0).unwrap(),
                    ),
                    None,
                ))
                .into(),
                true,
            ),
            true,
        );
        // In replay mode we still want the *same* end-of-iteration semantics as normal fuzzing,
        // otherwise only the first input runs and the VM remains stuck in BREAKPOINT().
        // NOTE: This may restore a snapshot before we can read FUZZ_LAST_OP; for now, correctness
        // of sequence execution takes priority.
        emu.add_breakpoint(
            Breakpoint::with_command(
                breakpoint,
                EndCommand::new(Some(ExitKind::Ok)).into(),
                false,
            ),
            true,
        );

        // Start QEMU until the "fuzzing starts" event.
        unsafe {
            emu.start().unwrap();
        }

        // Minimal fuzzer/state just to satisfy QemuExecutor::run_target.
        let mut feedback = feedback_or!(MaxMapFeedback::new(&edges_observer), TimeFeedback::new(&time_observer));
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::new(),
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        // Put the first replay input into the corpus and mark it as current.
        let first_input = inputs[0].1.clone();
        let corpus_id = state
            .corpus_mut()
            .add(libafl::corpus::Testcase::new(first_input.clone()))
            .unwrap();
        state.set_corpus_id(corpus_id).unwrap();

        let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor = QemuExecutor::new(
            emu,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        executor.break_on_timeout();
        let mut final_exit = ExitKind::Ok;
        for (idx, (label, input)) in inputs.iter().enumerate() {
            if inputs.len() > 1 {
                println!("[REPLAY_SEQ] step={} file={}", idx, label);
            }
            let exit_kind = executor
                .run_target(&mut fuzzer, &mut state, &mut mgr, input)
                .unwrap_or(ExitKind::Crash);
            final_exit = exit_kind;
            if !matches!(exit_kind, ExitKind::Ok) {
                println!("[REPLAY] non-ok exit at step {}: {:?}", idx, exit_kind);
                break;
            }
        }

        println!("[REPLAY] exit={final_exit:?}");
        process::exit(if matches!(final_exit, ExitKind::Ok) { 0 } else { 1 });
    }

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        let args: Vec<String> = env::args().collect();

        // Keep a small ring buffer of recent inputs; stateful crashes may require a sequence.
        let mut recent_inputs: VecDeque<Vec<u8>> = VecDeque::with_capacity(64);
        let repro_ring_dir = env::var_os("REPRO_RING_DIR").map(PathBuf::from);
        let mut repro_ring_cursor: u64 = 0;
        if let Some(dir) = &repro_ring_dir {
            let _ = fs::create_dir_all(dir);
            println!("[REPRO_RING] enabled: dir={} size={}", dir.display(), REPRO_RING_SIZE);
        }

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           _state: &mut _,
                           input: &BytesInput| unsafe {
            // Important: Systemmode InputLocation writes only `input.len()` bytes.
            // If we pass a short input, the remaining bytes in FUZZ_INPUT keep
            // their previous values (stale tail), making crashes hard to replay.
            // Pad to MAX_INPUT_SIZE so FUZZ_INPUT is fully overwritten each run.
            let max = MAX_INPUT_SIZE;
            let bytes = input.target_bytes();
            let padded_input = pad_input_to_max(bytes.as_slice(), max);

            // Persist a rolling window of inputs to disk so we can reproduce even if QEMU aborts.
            if let Some(dir) = &repro_ring_dir {
                let slot = (repro_ring_cursor % REPRO_RING_SIZE) as usize;
                let p = dir.join(format!("{:03}.bin", slot));
                let _ = fs::write(&p, padded_input.target_bytes().as_slice());
                let count = core::cmp::min(repro_ring_cursor + 1, REPRO_RING_SIZE);
                let _ = fs::write(
                    dir.join("cursor.txt"),
                    format!("cursor={}\ncount={}\n", repro_ring_cursor, count),
                );
                repro_ring_cursor = repro_ring_cursor.wrapping_add(1);
            }
            // Record the padded bytes so we can dump a sequence on crash.
            if recent_inputs.len() == 64 {
                recent_inputs.pop_front();
            }
            recent_inputs.push_back(padded_input.target_bytes().as_slice().to_vec());

            let exit_kind: ExitKind = emulator.run(&padded_input).unwrap().try_into().unwrap();
            if matches!(exit_kind, ExitKind::Crash | ExitKind::Timeout) {
                if let Ok(dir) = dump_recent_inputs(&recent_inputs, Path::new("./repro_seqs")) {
                    println!("[REPRO_SEQ] dumped last {} inputs to {}", recent_inputs.len(), dir.display());
                }
            }
            exit_kind
        };

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Choose modules to use
        let modules = tuple_list!(StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?);

        // Initialize QEMU Emulator
        let mut emu = Emulator::builder()
            .qemu_parameters(args)
            .modules(modules)
            .build()?;

        let qemu = emu.qemu();

        // Set breakpoints of interest with corresponding commands.
        emu.add_breakpoint(
            Breakpoint::with_command(
                main_addr,
                StartCommand::new(InputLocation::new(
                    qemu,
                    &QemuMemoryChunk::phys(
                        input_addr,
                        unsafe { MAX_INPUT_SIZE } as GuestReg,
                        qemu.cpu_from_index(0).unwrap(),
                    ),
                    None,
                ))
                .into(),
                true,
            ),
            true,
        );
        emu.add_breakpoint(
            Breakpoint::with_command(
                breakpoint,
                EndCommand::new(Some(ExitKind::Ok)).into(),
                false,
            ),
            true,
        );
        // Optional debug hook: crash if the guest writes to a "magic" MMIO address.
        // This MUST be opt-in, otherwise writing FUZZ_INPUT at 0x20000000 will
        // inevitably touch 0x20000004 and crash immediately.
        if env::var_os("ENABLE_MAGIC_MMIO").is_some() {
            // IMPORTANT:
            // - Do NOT place this inside the FUZZ_INPUT range. We pad inputs to MAX_INPUT_SIZE
            //   and the StartCommand writes the whole chunk, so overlaps will trigger instantly.
            // - You can override via MAGIC_MMIO_ADDR (decimal or 0x... hex).
            let magic_crash_addr: u64 = parse_u64_env("MAGIC_MMIO_ADDR").unwrap_or(0x2000_1004);
            println!("[MAGIC_MMIO] enabled for addr {:#x} (override with MAGIC_MMIO_ADDR)", magic_crash_addr);
            emu.qemu().hooks().add_write_hooks(
                magic_crash_addr,       // data: passed as first arg to gen/exec
                Some(magic_write_gen),  // generator: decide whether to instrument
                None,                   // exec1 (1 byte)
                None,                   // exec2 (2 bytes)
                Some(magic_write_exec), // exec4 (4 bytes)
                None,                   // exec8 (8 bytes)
                None,                   // exec_n (other sizes)
            );
        }

        let devices = emu.list_devices();
        println!("Devices = {:?}", devices);

        unsafe {
            emu.start().unwrap();
        }

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Setup an havoc mutator with a mutational stage
        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator),
            CalibrationStage::new(&calibration_feedback)
        );

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emu,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    // let mut mgr = SimpleEventManager::new(monitor);
    // run_client(None, mgr, 0);

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        // .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
