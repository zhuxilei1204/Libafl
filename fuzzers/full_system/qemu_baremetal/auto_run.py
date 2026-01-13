import os
import time
import subprocess
import shutil
import re
import signal

# ================= 配置区域 =================

# 1. Fuzzer 的工作目录
FUZZER_WORK_DIR = "/home/zwz/Libafl/fuzzers/full_system/qemu_baremetal"

# 2. Harness 的根目录
HARNESS_ROOT_DIR = "/home/zwz/FreeRTOS/FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/harness/harness_gemini-3-flash-preview-2"

# 3. Justfile 的路径
JUSTFILE_PATH = os.path.join(FUZZER_WORK_DIR, "Justfile")

# 4. 历史记录文件路径 (新功能)
HISTORY_FILE = os.path.join(FUZZER_WORK_DIR, "fuzz_history.txt")

# 5. 单个程序 Fuzzing 时长 (秒), 360秒 = 6分钟
FUZZ_DURATION = 360

# 6. 日志文件名
LOG_FILENAME = "freertos_run.debug.log"

# ================= 功能函数 =================

def load_history():
    """读取已完成的任务列表"""
    completed = set()
    if os.path.exists(HISTORY_FILE):
        print(f"[*] 发现历史记录文件: {HISTORY_FILE}")
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if path:
                    completed.add(path)
    else:
        print("[*] 未发现历史记录，将从头开始。")
    return completed

def mark_task_completed(harness_dir):
    """将完成的任务写入历史文件"""
    with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
        f.write(harness_dir + "\n")
    print(f"[记录] 已将 {os.path.basename(harness_dir)} 标记为完成。")

def find_elf_files(root_dir):
    """遍历目录寻找 RTOSDemo.out"""
    tasks = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if "RTOSDemo.out" in filenames:
            elf_full_path = os.path.join(dirpath, "RTOSDemo.out")
            tasks.append({
                "elf_path": elf_full_path,
                "harness_dir": dirpath 
            })
    return tasks

def update_justfile(justfile_path, new_elf_path):
    """使用正则修改 justfile 中的 FreeRTOS_ELF 变量"""
    if not os.path.exists(justfile_path):
        raise FileNotFoundError(f"找不到 Justfile: {justfile_path}")

    with open(justfile_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 正则匹配：找到 FreeRTOS_ELF := "..." 并替换
    # 注意：确保你的 Justfile 里变量名确实是 FreeRTOS_ELF
    pattern = r'(FreeRTOS_ELF\s*:=\s*").*?(")'
    replacement = f'\\1{new_elf_path}\\2'
    
    new_content = re.sub(pattern, replacement, content)

    with open(justfile_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"[配置] Justfile 已更新指向: {new_elf_path}")

def clean_environment():
    """清理环境：删除旧文件 + 强制杀掉占用端口的进程"""
    # 1. 清理文件
    crashes_dir = os.path.join(FUZZER_WORK_DIR, "crashes")
    log_file = os.path.join(FUZZER_WORK_DIR, LOG_FILENAME)
    
    if os.path.exists(crashes_dir):
        shutil.rmtree(crashes_dir)
    if os.path.exists(log_file):
        os.remove(log_file)

    # 2. 强制杀掉占用端口的旧进程 (防止 Address already in use)
    try:
        subprocess.run(["killall", "-9", "qemu_baremetal"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("fuser -k 1337/tcp", shell=True, 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def save_artifacts(target_harness_dir):
    """将 crashes 和 log 移动回 harness 目录"""
    src_crashes = os.path.join(FUZZER_WORK_DIR, "crashes")
    src_log = os.path.join(FUZZER_WORK_DIR, LOG_FILENAME)
    
    dst_crashes = os.path.join(target_harness_dir, "crashes")
    dst_log = os.path.join(target_harness_dir, LOG_FILENAME)

    print(f"[保存] 正在收集结果到: {target_harness_dir}")

    if os.path.exists(src_crashes):
        if os.path.exists(dst_crashes):
            shutil.rmtree(dst_crashes)
        shutil.move(src_crashes, dst_crashes)
    else:
        print("[注意] 本次运行没有生成 crashes 目录")

    if os.path.exists(src_log):
        if os.path.exists(dst_log):
            os.remove(dst_log)
        shutil.move(src_log, dst_log)
    else:
        print(f"[警告] 未找到日志文件 {src_log}")

# ================= 主程序 =================

def main():
    # 1. 扫描所有任务
    print(f"[*] 开始扫描 harness 目录: {HARNESS_ROOT_DIR}")
    tasks = find_elf_files(HARNESS_ROOT_DIR)
    print(f"[*] 共发现 {len(tasks)} 个目标 ELF 文件。")

    # 2. 加载历史记录
    completed_tasks = load_history()
    print(f"[*] 历史记录中已完成 {len(completed_tasks)} 个任务。\n")

    if len(tasks) == 0:
        print("未找到 RTOSDemo.out，请检查路径配置。")
        return

    # 3. 循环执行任务
    for index, task in enumerate(tasks):
        elf_path = task['elf_path']
        harness_dir = task['harness_dir']
        task_name = os.path.basename(harness_dir)
        
        print(f"========================================")
        print(f"进度 ({index+1}/{len(tasks)}): {task_name}")

        # --- 断点续传核心逻辑 ---
        if harness_dir in completed_tasks:
            print(f"[跳过] 该任务已在历史记录中，不再重复执行。")
            print(f"========================================\n")
            continue
        # ---------------------

        print(f"目标 ELF: {elf_path}")
        print(f"========================================")

        # 3.1 修改 Justfile
        try:
            update_justfile(JUSTFILE_PATH, elf_path)
        except Exception as e:
            print(f"[错误] 修改 Justfile 失败: {e}")
            continue

        # 3.2 清理环境 (杀进程 + 删文件)
        clean_environment()

        # 3.3 启动 Fuzzing
        print(f"[运行] 启动 Fuzzer，倒计时 {FUZZ_DURATION} 秒...")
        
        try:
            # 开启 stdout=None 以便看到 QEMU/LibAFL 的实时输出
            proc = subprocess.Popen(
                ["just", "run"], 
                cwd=FUZZER_WORK_DIR,
                stdout=None, 
                stderr=None,
                preexec_fn=os.setsid 
            )

            # 3.4 等待超时
            try:
                proc.wait(timeout=FUZZ_DURATION)
            except subprocess.TimeoutExpired:
                print("\n[时间到] 停止 Fuzzing...")
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(2)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except:
                    pass
        except Exception as e:
            print(f"[错误] 运行过程出错: {e}")

        # 再次清理进程，防止僵尸进程
        subprocess.run(["killall", "-9", "qemu_baremetal"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3.5 保存结果
        save_artifacts(harness_dir)

        # 3.6 写入历史记录 (关键)
        mark_task_completed(harness_dir)
        
        print(f"[完成] 任务结束。\n")

    print("[*] 所有 Fuzzing 任务已完成。")

if __name__ == "__main__":
    main()