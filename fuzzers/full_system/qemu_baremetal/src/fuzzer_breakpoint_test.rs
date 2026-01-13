//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
use core::time::Duration;
use std::{env, path::PathBuf};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput},
    inputs::HasTargetBytes,
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
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{
    breakpoint::Breakpoint,
    command::{EndCommand, StartCommand},
    elf::EasyElf,
    emu::Emulator,
    executor::QemuExecutor,
    modules::edges::StdEdgeCoverageModule,
    GuestPhysAddr, GuestReg, InputLocation, QemuMemoryChunk,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
// use libafl_qemu::QemuSnapshotBuilder; // for normal qemu snapshot
use libafl_qemu::sys::TCGTemp;
use libafl_qemu::qemu::MemAccessInfo;
use libafl_qemu::GuestAddr;
pub static mut MAX_INPUT_SIZE: usize = 50;

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

// 生成初始语料库的函数
fn generate_initial_corpus() -> Vec<BytesInput> {
    println!("[语料库] 生成初始测试用例...");
    
    let mut corpus = Vec::new();
    // 测试用例2: 奇数输入 (触发安全操作)
    let even_input = vec![1u8, 0, 0, 0]; // 小端序的1 
    corpus.push(BytesInput::new(even_input));

    println!("[语料库] 共生成 {} 个初始测试用例", corpus.len());
    corpus
}

// 检查并创建语料库目录
fn ensure_corpus_dirs(corpus_dirs: &[PathBuf]) {
    for dir in corpus_dirs {
        if !dir.exists() {
            println!("[语料库] 创建目录: {:?}", dir);
            std::fs::create_dir_all(dir).expect("Failed to create corpus directory");
        }
    }
}

// 保存初始语料库到磁盘
fn save_initial_corpus_to_disk(corpus_dirs: &[PathBuf], corpus: &[BytesInput]) -> Result<(), Error> {
    ensure_corpus_dirs(corpus_dirs);
    
    for (i, input) in corpus.iter().enumerate() {
        let filename = format!("testcase_{:04}", i);
        let path = corpus_dirs[0].join(filename);
        
        // 将输入保存到文件 - 将 OwnedSlice 转换为 Vec<u8>
        let bytes: Vec<u8> = input.target_bytes().as_slice().to_vec();
        std::fs::write(&path, bytes)
            .map_err(|e| Error::illegal_argument(format!("Failed to write file: {}", e)))?;
        
        if i < 5 { // 只打印前几个文件的路径，避免输出太多
            println!("[语料库] 保存测试用例 {} 到: {:?}", i, path);
        }
    }
    
    println!("[语料库] 所有 {} 个测试用例已保存到磁盘", corpus.len());
    Ok(())
}

pub fn fuzz() {
    env_logger::init();
    println!("=== 启动 fuzzing 调试版本 ===");

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };
    // Hardcoded parameters
    let timeout = Duration::from_secs(10);
    let broker_port = 1336;
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
    
    println!("[DEBUG] 在生成语料库之前检查覆盖率映射");
    unsafe {
        let edges_ptr = edges_map_mut_ptr();
        println!("[DEBUG] edges_map_mut_ptr = {:p}", edges_ptr);
        
        // 检查前几个字节
        for i in 0..10 {
            println!("[DEBUG] edges_map[{}] = {}", i, *edges_ptr.add(i));
        }
    }
    // 在闭包外部生成初始语料库
    let initial_corpus = generate_initial_corpus();
    println!("[DEBUG] 在创建状态之前检查覆盖率映射");
    unsafe {
        let edges_ptr = edges_map_mut_ptr();
        let mut non_zero = 0;
        for i in 0..EDGES_MAP_DEFAULT_SIZE {
            if *edges_ptr.add(i) > 0 {
                non_zero += 1;
            }
        }
        println!("[DEBUG] 非零条目: {}/{}", non_zero, EDGES_MAP_DEFAULT_SIZE);
    }
    // 确保语料库目录存在
    ensure_corpus_dirs(&corpus_dirs);
    
    // 保存初始语料库到磁盘（可选，用于调试）
    if let Err(e) = save_initial_corpus_to_disk(&corpus_dirs, &initial_corpus) {
        println!("[警告] 无法保存初始语料库到磁盘: {:?}", e);
    }

    let mut run_client = |state: Option<_>, mut mgr, client_id| {
        println!("=== 进入客户端运行函数 === 客户端ID: {:?}", client_id);

        let args: Vec<String> = env::args().collect();
        println!("111111111111111111111111111111111111111111111");
        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           _state: &mut _,
                           input: &BytesInput| unsafe {
            println!("22222222222222222222222222222222222222222222222");
            let input_bytes = input.target_bytes();
            println!("[执行] 开始执行输入，长度: {}", input_bytes.len());
            
            // 调试：检查输入内容
            if !input_bytes.is_empty() {
                // 直接使用切片，避免类型问题
                let sample_len = input_bytes.len().min(8);
                println!("[调试] 输入前{}字节: {:02x?}", sample_len, &input_bytes[0..sample_len]);
                
                // 检查是否为偶数输入
                if input_bytes.len() >= 4 {
                    let first_value = u32::from_le_bytes([input_bytes[0], input_bytes[1], input_bytes[2], input_bytes[3]]);
                    println!("[调试] 输入第一个值: {} ({})", first_value, if first_value % 2 == 0 { "偶数" } else { "奇数" });
                }
            }
            
            // Systemmode InputLocation writes only `input.len()` bytes.
            // Pad to MAX_INPUT_SIZE so FUZZ_INPUT is fully overwritten each run.
            let max = unsafe { MAX_INPUT_SIZE };
            let mut padded = vec![0u8; max];
            let copy_len = core::cmp::min(input_bytes.len(), max);
            padded[..copy_len].copy_from_slice(&input_bytes[..copy_len]);
            let padded_input = BytesInput::new(padded);

            let start_time = std::time::Instant::now();
            let result = emulator.run(&padded_input);
            let elapsed = start_time.elapsed();
            
            match result {
                Ok(exit_kind) => {
                    let kind: ExitKind = exit_kind.try_into().unwrap();
                    println!("[执行] 执行完成，耗时: {:?}, 结果: {:?}", elapsed, kind);
                    kind
                }
                Err(e) => {
                    println!("[错误] emulator.run 失败: {:?}, 耗时: {:?}", e, elapsed);
                    ExitKind::Crash
                }
            }
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
        println!("[初始化] 创建 QEMU Emulator...");
        let mut emu = Emulator::builder()
            .qemu_parameters(args)
            .modules(modules)
            .build()?;

        let qemu = emu.qemu();

        // Set breakpoints of interest with corresponding commands.
        println!("[断点] 设置主断点 @ {main_addr:#x}");
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
        
        println!("[断点] 设置结束断点 @ {breakpoint:#x}");
        emu.add_breakpoint(
            Breakpoint::with_command(
                breakpoint,
                EndCommand::new(Some(ExitKind::Ok)).into(),
                false,
            ),
            true,
        );

        let magic_crash_addr: u64 = 0x20000004;
        // 使用底层的 add_write_hooks API
        emu.qemu().hooks().add_write_hooks(
            magic_crash_addr,       // data: 会被传递给 gen 和 exec 函数的第一个参数
            Some(magic_write_gen),  // generator: 决定是否插桩
            None,                   // exec1 (1字节写): 不关心
            None,                   // exec2 (2字节写): 不关心
            Some(magic_write_exec), // exec4 (4字节写): 我们的 int *ptr = val 通常是 4 字节
            None,                   // exec8 (8字节写): 不关心
            None,                   // exec_n (其他大小): 不关心
        );
        
        let devices = emu.list_devices();
        println!("Devices = {:?}", devices);

        println!("[QEMU] 启动 QEMU...");
        unsafe {
            emu.start().unwrap();
        }
        println!("[QEMU] QEMU 启动完成");

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
            println!("[状态] 创建新状态");
            let mut new_state = StdState::new(
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
            .unwrap();
            
            // 添加初始语料库到状态 - 使用闭包外部的 initial_corpus 的克隆
            println!("[语料库] 添加初始测试用例到状态...");
            for input in initial_corpus.clone() {
                // 将 BytesInput 转换为 Testcase
                let testcase = Testcase::new(input);
                let _ = new_state.corpus_mut().add(testcase);
            }
            println!("[语料库] 初始语料库大小: {}", new_state.corpus().count());
            
            new_state
        });

        println!("[状态] 当前语料库大小: {}", state.corpus().count());

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Setup an havoc mutator with a mutational stage
        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            CalibrationStage::new(&calibration_feedback),
            StdMutationalStage::new(mutator)
        );

        // Create a QEMU in-process executor
        println!("[执行器] 创建 QEMU 执行器...");
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
        println!("[执行器] 设置超时断点");
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            println!("[语料库] 从磁盘加载初始输入...");
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    // 如果从磁盘加载失败，使用我们生成的初始语料库
                    println!("使用内存中的初始语料库");
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        println!("[Fuzzer] 开始 fuzz_loop");
        
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
            
        println!("=== fuzz_loop 结束 ===");
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    println!("=== 启动 Launcher ===");
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => {
            println!("=== Launcher 正常结束 ===");
        },
        Err(Error::ShuttingDown) => {
            println!("=== Launcher 收到停止信号 ===");
            println!("Fuzzing stopped by user. Good bye.");
        }
        Err(err) => {
            println!("=== Launcher 错误: {:?} ===", err);
            panic!("Failed to run launcher: {err:?}");
        }
    }
    
    println!("=== fuzzing 完全结束 ===");
}