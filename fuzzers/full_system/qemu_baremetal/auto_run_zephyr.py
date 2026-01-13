import os
import time
import subprocess
import shutil
import re
import signal
import glob  # 新增：用于查找共享内存文件

# ================= 配置区域 =================

# 1. Fuzzer 的工作目录 (Justfile 所在位置)
FUZZER_WORK_DIR = "/home/zwz/Libafl/fuzzers/full_system/qemu_baremetal"

# 2. Harness 的根目录 (存放 zephyr.elf 的上级目录)
HARNESS_ROOT_DIR = "/home/zwz/zephyr/samples/fuzz/harness/harness_fuzz"

# 3. Justfile 的路径
JUSTFILE_PATH = os.path.join(FUZZER_WORK_DIR, "Justfile")

# 4. 历史记录文件路径
HISTORY_FILE = os.path.join(FUZZER_WORK_DIR, "fuzz_history_zephyr.txt")

# 5. 单个程序 Fuzzing 时长 (秒), 360秒 = 6分钟
FUZZ_DURATION = 360

# 6. 日志文件名
LOG_FILENAME = "rtos_fuzz_run.debug.log"

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
    """遍历目录寻找 zephyr.elf"""
    tasks = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if "zephyr.elf" in filenames:
            elf_full_path = os.path.join(dirpath, "zephyr.elf")
            tasks.append({
                "elf_path": elf_full_path,
                "harness_dir": dirpath 
            })
    return tasks

def update_justfile(justfile_path, new_elf_path):
    """使用正则修改 justfile 中的 kernel_ELF 变量"""
    if not os.path.exists(justfile_path):
        raise FileNotFoundError(f"找不到 Justfile: {justfile_path}")

    with open(justfile_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 正则匹配：找到 kernel_ELF := "..." 并替换
    # 确保 Justfile 里的变量名是 kernel_ELF (如果是 FreeRTOS_ELF 请自行修改正则)
    pattern = r'(kernel_ELF\s*:=\s*").*?(")'
    replacement = f'\\1{new_elf_path}\\2'
    
    new_content = re.sub(pattern, replacement, content)

    with open(justfile_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"[配置] Justfile 已更新指向: {new_elf_path}")

def clean_environment():
    """清理环境：删除旧文件 + 强制杀掉占用端口的进程 + 清理共享内存"""
    # 1. 清理工作目录下的旧结果
    crashes_dir = os.path.join(FUZZER_WORK_DIR, "crashes")
    log_file = os.path.join(FUZZER_WORK_DIR, LOG_FILENAME)
    
    if os.path.exists(crashes_dir):
        try:
            shutil.rmtree(crashes_dir)
        except OSError:
            pass
    if os.path.exists(log_file):
        try:
            os.remove(log_file)
        except OSError:
            pass

    # 2. 强制杀掉占用端口的旧进程 (防止 Address already in use)
    # 使用 killall -9 确保彻底杀死 QEMU 和 Fuzzer 进程
    try:
        subprocess.run(["killall", "-9", "qemu_baremetal"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("fuser -k 1337/tcp", shell=True, 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # 3. [新增] 清理 LibAFL/QEMU 残留的共享内存 (/dev/shm)
    # 警告：这会删除 /dev/shm 下匹配的文件，确保机器上没有其他重要的 LibAFL 任务在跑
    try:
        # LibAFL 默认生成的 shm 文件名通常包含 libafl 或 qemu 字段
        shm_patterns = ["/dev/shm/libafl_*", "/dev/shm/qemu_*"] 
        cleaned_count = 0
        for pattern in shm_patterns:
            for shm_file in glob.glob(pattern):
                try:
                    os.remove(shm_file)
                    cleaned_count += 1
                except OSError:
                    pass # 忽略权限错误或文件已消失
        if cleaned_count > 0:
            print(f"[清理] 已清理 {cleaned_count} 个残留的共享内存段")
    except Exception as e:
        print(f"[警告] 共享内存清理失败: {e}")

def save_artifacts(target_harness_dir):
    """将 crashes 和 log 移动回 harness 目录"""
    src_crashes = os.path.join(FUZZER_WORK_DIR, "crashes")
    src_log = os.path.join(FUZZER_WORK_DIR, LOG_FILENAME)
    
    dst_crashes = os.path.join(target_harness_dir, "crashes")
    dst_log = os.path.join(target_harness_dir, LOG_FILENAME)

    print(f"[保存] 正在收集结果到: {target_harness_dir}")

    # 移动 Crashes 文件夹
    if os.path.exists(src_crashes):
        if os.path.exists(dst_crashes):
            shutil.rmtree(dst_crashes)
        try:
            shutil.move(src_crashes, dst_crashes)
        except Exception as e:
            print(f"[错误] 移动 crashes 失败: {e}")
    else:
        print("[注意] 本次运行没有生成 crashes 目录")

    # 移动日志文件
    if os.path.exists(src_log):
        if os.path.exists(dst_log):
            os.remove(dst_log)
        try:
            shutil.move(src_log, dst_log)
        except Exception as e:
            print(f"[错误] 移动日志失败: {e}")
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
        print("未找到 zephyr.elf，请检查路径配置。")
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

        # 3.2 清理环境 (杀进程 + 删文件 + 清内存)
        clean_environment()

        # 3.3 启动 Fuzzing
        print(f"[运行] 启动 Fuzzer，倒计时 {FUZZ_DURATION} 秒...")
        
        proc = None
        try:
            # 开启 stdout=None 以便看到 QEMU/LibAFL 的实时输出
            # preexec_fn=os.setsid 创建新的进程组，方便后续一锅端
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
                # 发送 SIGTERM 给进程组
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                
                # 给一点时间让进程退出
                time.sleep(2)
                
                # 如果还在，发送 SIGKILL
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
        except Exception as e:
            print(f"[错误] 运行过程出错: {e}")
            # 确保出错也能尝试清理
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except:
                    pass

        # 再次强制清理所有相关进程，防止僵尸进程
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