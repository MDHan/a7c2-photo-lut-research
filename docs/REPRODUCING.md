# 离线复现

本仓库提供两个层次。所有命令只操作本地文件／进程，不连接、枚举或写入相机。

## 1. 无需固件的入门检查

需要 Python 3.10+ 和 `cc`。从仓库根目录运行：

```sh
python3 -m unittest discover -s tests -v
```

测试在临时目录编译原研究的 AP/CP C 状态机和照片完成状态机，再用 ctypes 调用。覆盖读者阻止写入、匹配许可／提交、取消与晚到许可、失效缓冲、DMA 故障保留、会话不重置读者、坏回复以及旧照片回调。另有公开文件检查器测试，共 12 项。

这不是原厂机器码回归，不涉及像素、ARM ABI、硬件或固件安装。公开 CI 也只运行这一层和 Git 索引检查。

## 2. 需要精确输入的原厂机器码回归

研究输入是已经存在的精确 FL2/FL3 AP/CP 基线，**不是任意 Sony 官方更新包、原版 2.01 程序，也不是其他改装或集成升级版本**。本项目不下载、不分发、不提供提取设备输入的命令。请自行提供有权使用的两个本地文件，命名为 `appFw.so` 和 `cpapp-b.bin`。

输入必须匹配 [指纹清单](../evidence/input-fingerprints.json)。不同输入会在复制和构建前拒绝；不要删除哈希检查尝试套用其他版本。

完整路径当前按 macOS、Python 3.12、Apple `/usr/bin/clang` 和 [固定 Python 依赖](../requirements-research.txt) 复现。Linux CI 的主机状态机测试不等于 Linux 已能复现相同镜像。

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-research.txt
.venv/bin/python tools/replay_offline.py --baseline /path/to/your/private/baseline
```

本地流程：

1. 核对两个输入的完整 SHA-256。只复制这两个文件，不复制备份、身份或设置。
2. 将私有输入放入被 Git 忽略的历史兼容位置 `install-20261018-085012/candidate/`。保留原研究源码不改路径，以保持源码快照可核对。
3. 重建 dev-menu-02、dev-menu-03 与 upload 阶段头文件，满足旧构建器的实际依赖。已有不匹配文件会拒绝，不自动覆盖。
4. 运行 `verify_lut_events_integration.py`、`verify_lut_menu_events.py`、`verify_lut_events_readers.py`、`verify_lut_events_photo.py`。
5. 运行 `build_lut_events_candidate.py`，核对源／报告绑定与精确逆修改，并检查完整候选上的菜单组件。
6. 比对历史 dev-events-05 候选指纹。生成 `local-validation.json` 记录本次工具链和结果；状态仍为 `NOT_READY_TO_FLASH`。

第一次运行需要数分钟及数百 MB 的本地空间。输出位于被忽略的候选／组件目录，包含私有镜像、派生机器码和逐字节配方，**不应提交 Git**。公开仓库中不附带这些输出。

工具链变化可能改变生成指令及候选指纹。脚本遇到差异会停止；保留结果、记录工具链并调查，不要把历史报告直接换个哈希继续使用。原始源码快照指纹见 [source-snapshot.json](../evidence/source-snapshot.json)。

## 提交前检查

```sh
git add <明确要公开的源码或文档>
python3 tools/check_public_tree.py --tracked
git diff --cached --stat
```

检查器读取 Git 索引中的实际字节，核对文本类型、禁止的产物路径、个人路径／凭据模式和源码快照；并非完整版权或秘密识别证明。原源码如需修改，请同时更新快照记录并解释变化，勿悄悄绕过检查。不要用 `git add -f` 加入被忽略的固件或报告。

文件级重建和逆修改不能证明设备恢复能力。本仓库没有相机安装入口；完整 UI、共享资源所有权、硬件恢复、WBI 和真实成片的后续工作见 [OPEN_TASKS.md](OPEN_TASKS.md)。
