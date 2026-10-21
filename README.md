# A7C II Photo LUT Research

研究 Sony A7C II（ILCE-7CM2，2.01）将自定义 LUT 用于照片机内直出的路径。欢迎熟悉 ARM/AArch64、嵌入式图像管线或相机 UI 的开发者继续推进。

**当前状态：`NOT_READY_TO_FLASH`。这是研究代码和交接仓库，没有可安装固件、刷机工具或真机成片验证。** 维护者近期时间有限，希望以可复现的代码、证据和具体任务支持后续协作。

> Research handoff for custom LUT processing in still-photo output on the Sony A7C II. Offline candidate `dev-events-05` exists locally. Hardware JPEG output, complete UI integration and safe installation remain unverified. Firmware and personal backups are not distributed.

## 已做到哪里

截至 2026-10-21 核对，最新照片 LUT 研究候选是 **dev-events-05**；对应离线验证来自 2026-10-19。

| 部分 | 当前证据 | 仍缺什么 |
|---|---|---|
| 照片菜单 | PPLUT1–4 资格、P/A/S/M 约束、确认到设置消息的原厂机器码检查 | 完整 UI 按键／弹窗、导入覆盖、模式切换、保存与 MR |
| 真实上传任务 | 原厂队列 → 会话 → 写入许可 → 文件／共享复制 → 完成 → CP 提交确认 | 真实 OSAL、驱动完成约定与进程重启 |
| 取消／删除 | 原厂取消虚调用、LUT/CUBE 删除入口和选择性重置 helper | UI 事件生产者、外围 model 记账及失败反馈 |
| 共享缓冲 | 缓存／普通／附加参数加载器和消息构造器的入口保护 | 外部缓冲所有权与其他读者的完整排查 |
| 超时恢复 | 匹配晚到完成后收尾；旧回调不能完成新事务 | 永久缺失完成和 CP DMA 故障的硬件中止／恢复依据 |
| 照片处理 | CP 照片/VFX 路径、排队读者、错误与回调的离线执行 | 真实 LUT 像素、完整 JPEG/HEIF 成片与性能 |
| 安装 | 有旧事务核心和文件副本测试源码 | 新版 AP 大小变化后的安装同步、加载、WBI 与恢复 |

离线报告包含 14 组菜单后端／恢复、3 种取消装载偏移、50 组照片正常流程各两次、9 类照片错误，以及菜单 64 组资格／960 组上下文／256 组任务构造。**OS、文件、消息、DMA、寄存器和部分框架服务使用明确替身；这些数字不代表相机已经验证成功。** 精确范围和原报告指纹见 [证据摘要](evidence/dev-events-05-summary.json) 与 [状态说明](docs/STATUS.md)。

## 接手从这里开始

1. 读 [START_HERE.md](START_HERE.md)，选择一个有验收条件的任务。
2. 运行不依赖固件的入门测试：`python3 -m unittest discover -s tests -v`。需要 Python 3.10+ 和可用的 C 编译器；测试只执行主机状态机，不连接相机。
3. 读 [架构和源码地图](docs/ARCHITECTURE.md)，从最新的 `lut_events_*` 和 `verify_lut_events_*` 开始。
4. 有自己匹配的程序输入时，按 [离线复现](docs/REPRODUCING.md) 重建和运行原厂机器码测试。首次复现需要本地工具链和精确基线，不需要连接相机。
5. 提交包含问题、修改、服务替身边界和验证结果的 PR，参见 [贡献说明](CONTRIBUTING.md)。

## 仓库结构

- `custom-lut-research/route-a/offline-v0.5/`：原研究源码快照，保留构建依赖与历史命名；当前入口见源码地图。
- `tests/`：无需固件的主机状态机测试。
- `tools/`：本地复现入口与公开文件检查。
- `evidence/`：输入／候选指纹、源码清单和脱敏统计；不包含镜像、原始反汇编或逐字节补丁表。
- `docs/`：状态、开放任务、复现要求和发布边界。

原 `dev-menu-01/02/03`、`dev-upload-04`、`dev-events-05` 文件夹是本地构建产物，未随仓库分发。构建器仍保留这些历史名称；早期脚本或注释的“尚未接入”只描述对应阶段，当前范围以本 README 和状态说明为准。

本仓库与 [a7c2-fl23-macos](https://github.com/MDHan/a7c2-fl23-macos) 分开维护。FL2/FL3 安装或其他补丁的成功结果，不能作为照片 LUT 候选的硬件证据。感谢前期协议、固件分析与 FL2/FL3 研究，见 [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md)。源码授权与固件权利边界见 [LICENSE](LICENSE) 和 [NOTICE.md](NOTICE.md)。
