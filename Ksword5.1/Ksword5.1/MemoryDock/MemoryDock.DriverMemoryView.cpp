#include "MemoryDock.Internal.h"
#include "../UI/KernelDisassemblyDialog.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"

// ============================================================
// MemoryDock.DriverMemoryView.cpp
// 作用：
// - 承载“驱动内存读写”页的多视图呈现：十六进制、反汇编、文本；
// - 提供快照转存到文件与字符串写入编辑缓存两个便捷入口；
// - 只消费 MemoryDock 已缓存的快照字节，自身不发起任何 IOCTL。
// ============================================================

using namespace ksword::memory_dock_internal;

namespace
{
    // driverMemoryBytesText 作用：
    // - 把一段原始字节渲染成反汇编表格里的“原始字节”列文本；
    // - 输入 bytes：单条指令的字节序列；
    // - 处理：逐字节转两位大写十六进制并以空格分隔；
    // - 返回：形如 "48 8B 05 A1" 的文本，空输入返回空串。
    QString driverMemoryBytesText(const QByteArray& bytes)
    {
        QStringList byteTextList;
        byteTextList.reserve(static_cast<int>(bytes.size()));
        for (const char rawByte : bytes)
        {
            // 先转成无符号再格式化，避免 char 为负时补出 FFFFFF 前缀。
            const std::uint8_t byteValue = static_cast<std::uint8_t>(rawByte);
            byteTextList.push_back(
                QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper());
        }
        return byteTextList.join(QLatin1Char(' '));
    }

    // driverMemoryHexAddressText 作用：
    // - 统一反汇编表格的地址列文本格式；
    // - 输入 address：指令绝对虚拟地址；
    // - 处理：按 16 位定宽补零并转大写，前缀保持小写 0x 以便与本页其它地址一致；
    // - 返回：形如 "0xFFFFF8034A1B2C00" 的文本。
    QString driverMemoryHexAddressText(const std::uint64_t address)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // driverMemoryOffsetText 作用：
    // - 统一反汇编表格的偏移列文本格式；
    // - 输入 byteOffset：指令相对快照起点的字节偏移；
    // - 处理：按 8 位定宽补零转大写；
    // - 返回：形如 "0x00000010" 的文本。
    QString driverMemoryOffsetText(const std::uint32_t byteOffset)
    {
        return QStringLiteral("0x%1")
            .arg(byteOffset, 8, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // driverMemoryReadOnlyItem 作用：
    // - 生成反汇编表格用的只读单元格；
    // - 输入 text：单元格显示文本；
    // - 处理：新建 QTableWidgetItem 并去掉可编辑标志；
    // - 返回：调用方接管所有权的表格项指针。
    QTableWidgetItem* driverMemoryReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // driverMemoryPrintableText 作用：
    // - 把原始字节渲染成文本视图里的可打印字符串；
    // - 输入 bytes：快照字节；useUtf16：true 时按 UTF-16LE 解释，否则按单字节 ASCII；
    // - 处理：不可打印字符统一替换为点号，保留换行以外的排版稳定性；
    // - 返回：可直接塞进只读编辑器的文本。
    QString driverMemoryPrintableText(const QByteArray& bytes, const bool useUtf16)
    {
        QString resultText;
        if (useUtf16)
        {
            // UTF-16LE：每两字节一个码元，尾部落单字节直接丢弃。
            const qsizetype unitCount = bytes.size() / 2;
            resultText.reserve(static_cast<int>(unitCount));
            for (qsizetype unitIndex = 0; unitIndex < unitCount; ++unitIndex)
            {
                const std::uint16_t codeUnit = static_cast<std::uint16_t>(
                    static_cast<std::uint8_t>(bytes.at(unitIndex * 2))
                    | (static_cast<std::uint16_t>(
                        static_cast<std::uint8_t>(bytes.at(unitIndex * 2 + 1))) << 8));
                const QChar unitChar(codeUnit);
                resultText.append(unitChar.isPrint() ? unitChar : QChar(QLatin1Char('.')));
            }
            return resultText;
        }

        // 单字节路径：只放行可打印 ASCII，其余一律点号，保证列对齐。
        resultText.reserve(static_cast<int>(bytes.size()));
        for (const char rawByte : bytes)
        {
            const std::uint8_t byteValue = static_cast<std::uint8_t>(rawByte);
            const bool printable = (byteValue >= 0x20U && byteValue <= 0x7EU);
            resultText.append(printable ? QChar(QLatin1Char(static_cast<char>(byteValue)))
                                        : QChar(QLatin1Char('.')));
        }
        return resultText;
    }

    // driverMemoryTextViewLineWidth：文本视图每行渲染的字节数，与十六进制视图保持一致。
    constexpr int kDriverMemoryTextViewLineWidth = 16;

    // driverMemoryMaxDisassemblyBytes：单次反汇编消费的最大字节数。
    // 快照最大 1MB，全量解码会产生几十万行且拖垮 UI，这里按 64KB 截断并在界面上说明。
    constexpr int kDriverMemoryMaxDisassemblyBytes = 64 * 1024;
}

ks::ui::DisassemblyArchitecture MemoryDock::currentDriverMemoryArchitecture() const
{
    // 内核虚拟地址与物理内存快照一律按 x64 解码：本工程只支持 64 位内核。
    if (m_driverMemorySnapshotIsPhysical
        || m_driverMemoryBaseAddress >= 0xFFFF000000000000ULL
        || m_driverMemorySnapshotPid == 0U)
    {
        return ks::ui::DisassemblyArchitecture::X64;
    }

    // 用户态快照跟随目标进程位数：WOW64 进程里的代码是 32 位指令。
    const HANDLE processHandle = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        toDwordPid(m_driverMemorySnapshotPid));
    if (processHandle == nullptr)
    {
        // 拿不到句柄时保守按 x64，与本页读取路径的默认假设一致。
        return ks::ui::DisassemblyArchitecture::X64;
    }

    BOOL isWow64Process = FALSE;
    const BOOL queryOk = ::IsWow64Process(processHandle, &isWow64Process);
    ::CloseHandle(processHandle);
    if (queryOk == FALSE)
    {
        return ks::ui::DisassemblyArchitecture::X64;
    }
    return (isWow64Process != FALSE) ? ks::ui::DisassemblyArchitecture::X86
                                     : ks::ui::DisassemblyArchitecture::X64;
}

void MemoryDock::applyDriverMemoryViewMode(const DriverMemoryViewMode viewMode)
{
    // 记录视图切换日志：便于回溯用户在哪个视图下做的操作。
    kLogEvent viewModeEvent;
    dbg << viewModeEvent
        << "[MemoryDock] applyDriverMemoryViewMode: 切换驱动内存读写页视图。"
        << eol;

    m_driverMemoryViewMode = viewMode;
    if (m_driverMemoryViewStack == nullptr)
    {
        return;
    }

    // 三个视图按固定顺序压栈，这里用枚举值直接定位页索引。
    m_driverMemoryViewStack->setCurrentIndex(static_cast<int>(viewMode));

    // 同步分段按钮的选中态，保证从右键菜单等其它入口切换时按钮也跟着变。
    const auto syncToggle = [](QToolButton* button, const bool checked) {
        if (button == nullptr)
        {
            return;
        }
        const QSignalBlocker blocker(button);
        button->setChecked(checked);
    };
    syncToggle(m_driverMemoryHexViewButton, viewMode == DriverMemoryViewMode::Hex);
    syncToggle(m_driverMemoryDisasmViewButton, viewMode == DriverMemoryViewMode::Disassembly);
    syncToggle(m_driverMemoryTextViewButton, viewMode == DriverMemoryViewMode::Text);

    // 反汇编与文本视图是惰性渲染：切过去才真正解码，避免每次读取都付出全量成本。
    if (viewMode == DriverMemoryViewMode::Disassembly)
    {
        rebuildDriverMemoryDisassemblyView();
    }
    else if (viewMode == DriverMemoryViewMode::Text)
    {
        rebuildDriverMemoryTextView();
    }
}

void MemoryDock::refreshDriverMemoryViewsFromSnapshot()
{
    // 快照变化后统一入口：十六进制视图由调用方负责，这里刷新另外两个派生视图。
    if (m_driverMemoryViewMode == DriverMemoryViewMode::Disassembly)
    {
        rebuildDriverMemoryDisassemblyView();
    }
    else if (m_driverMemoryViewMode == DriverMemoryViewMode::Text)
    {
        rebuildDriverMemoryTextView();
    }
    else
    {
        // 停留在十六进制视图时把另外两个视图标记为待重建，避免展示上一轮的陈旧内容。
        if (m_driverMemoryDisasmTable != nullptr)
        {
            m_driverMemoryDisasmTable->setRowCount(0);
        }
        m_driverMemoryDisasmRows.clear();
        if (m_driverMemoryTextView != nullptr)
        {
            m_driverMemoryTextView->setRawText(QString());
        }
    }
}

void MemoryDock::rebuildDriverMemoryDisassemblyView()
{
    if (m_driverMemoryDisasmTable == nullptr)
    {
        return;
    }

    // 无快照时清表并给出引导文案，不做任何解码。
    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        m_driverMemoryDisasmTable->setRowCount(0);
        m_driverMemoryDisasmRows.clear();
        if (m_driverMemoryDisasmBackendLabel != nullptr)
        {
            m_driverMemoryDisasmBackendLabel->setText(
                QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
        }
        return;
    }

    // 反汇编始终针对“当前编辑缓存”，这样改完字节能立刻看到指令变化。
    QByteArray decodeBytes = m_driverMemoryEditedBytes;
    bool truncatedByBudget = false;
    if (decodeBytes.size() > kDriverMemoryMaxDisassemblyBytes)
    {
        decodeBytes = decodeBytes.left(kDriverMemoryMaxDisassemblyBytes);
        truncatedByBudget = true;
    }

    // 解码是纯函数，不读内存也不碰 UI，可以直接在主线程跑 64KB 预算。
    const ks::ui::DisassemblyArchitecture architecture = currentDriverMemoryArchitecture();
    const ks::ui::DisassemblyResult decodeResult = ks::ui::InstructionDecoder::decode(
        decodeBytes,
        m_driverMemoryBaseAddress,
        architecture);
    m_driverMemoryDisasmRows = decodeResult.rows;

    // 后端与截断说明合并成一行状态文本，避免再占一行界面高度。
    if (m_driverMemoryDisasmBackendLabel != nullptr)
    {
        QString backendText = QStringLiteral("解码后端: %1 | 架构: %2 | 指令: %3 条")
            .arg(decodeResult.backendName)
            .arg(architecture == ks::ui::DisassemblyArchitecture::X64
                ? QStringLiteral("x64")
                : QStringLiteral("x86"))
            .arg(m_driverMemoryDisasmRows.size());
        if (truncatedByBudget)
        {
            backendText += QStringLiteral(" | 已按 %1 KB 预算截断")
                .arg(kDriverMemoryMaxDisassemblyBytes / 1024);
        }
        if (!decodeResult.diagnosticText.isEmpty())
        {
            backendText += QStringLiteral(" | ") + decodeResult.diagnosticText;
        }
        m_driverMemoryDisasmBackendLabel->setText(backendText);
    }

    // 批量填表前后关排序，避免逐行插入时反复重排。
    const bool sortingWasEnabled = m_driverMemoryDisasmTable->isSortingEnabled();
    m_driverMemoryDisasmTable->setSortingEnabled(false);
    m_driverMemoryDisasmTable->setRowCount(static_cast<int>(m_driverMemoryDisasmRows.size()));

    // 未成功解码的字节用语义色标出来，方便一眼区分真实指令与 db 占位。
    const QColor undecodedColor = KswordTheme::TextSecondaryColor();
    for (qsizetype rowIndex = 0; rowIndex < m_driverMemoryDisasmRows.size(); ++rowIndex)
    {
        const ks::ui::DisassemblyRow& disasmRow = m_driverMemoryDisasmRows.at(rowIndex);
        const int tableRow = static_cast<int>(rowIndex);

        // 地址列用数值排序项，保证按地址排序时不会退化成字符串序。
        m_driverMemoryDisasmTable->setItem(
            tableRow,
            0,
            new ks::ui::NumericTableItem(
                driverMemoryHexAddressText(disasmRow.address),
                static_cast<qulonglong>(disasmRow.address)));
        m_driverMemoryDisasmTable->setItem(
            tableRow,
            1,
            new ks::ui::NumericTableItem(
                driverMemoryOffsetText(disasmRow.byteOffset),
                static_cast<qulonglong>(disasmRow.byteOffset)));
        m_driverMemoryDisasmTable->setItem(
            tableRow, 2, driverMemoryReadOnlyItem(driverMemoryBytesText(disasmRow.bytes)));
        m_driverMemoryDisasmTable->setItem(
            tableRow, 3, driverMemoryReadOnlyItem(disasmRow.mnemonic));
        m_driverMemoryDisasmTable->setItem(
            tableRow, 4, driverMemoryReadOnlyItem(disasmRow.operands));

        if (!disasmRow.decoded)
        {
            // db 占位行整行降低对比度，提示这里不是有效指令。
            for (int columnIndex = 0; columnIndex < 5; ++columnIndex)
            {
                QTableWidgetItem* cellItem = m_driverMemoryDisasmTable->item(tableRow, columnIndex);
                if (cellItem != nullptr)
                {
                    cellItem->setForeground(undecodedColor);
                }
            }
        }
    }
    m_driverMemoryDisasmTable->setSortingEnabled(sortingWasEnabled);

    // 数据换了一批，请全局列宽自适应重新量一次。
    ks::ui::RequestTableColumnAutoFit(m_driverMemoryDisasmTable);
}

void MemoryDock::rebuildDriverMemoryTextView()
{
    if (m_driverMemoryTextView == nullptr)
    {
        return;
    }

    // 无快照时给出与反汇编视图一致的引导文案。
    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        m_driverMemoryTextView->setRawText(
            QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
        return;
    }

    // 文本视图按行渲染：左侧地址、右侧该行字节对应的可打印字符。
    const bool useUtf16 = (m_driverMemoryTextEncodingCombo != nullptr)
        && (m_driverMemoryTextEncodingCombo->currentIndex() == 1);
    QString renderedText;
    renderedText.reserve(static_cast<int>(m_driverMemoryEditedBytes.size() * 2));

    const qsizetype totalBytes = m_driverMemoryEditedBytes.size();
    for (qsizetype lineStart = 0; lineStart < totalBytes; lineStart += kDriverMemoryTextViewLineWidth)
    {
        const qsizetype lineBytes =
            std::min<qsizetype>(kDriverMemoryTextViewLineWidth, totalBytes - lineStart);
        const QByteArray lineSlice = m_driverMemoryEditedBytes.mid(lineStart, lineBytes);
        const std::uint64_t lineAddress =
            m_driverMemoryBaseAddress + static_cast<std::uint64_t>(lineStart);
        renderedText += QStringLiteral("%1  %2\n")
            .arg(driverMemoryHexAddressText(lineAddress))
            .arg(driverMemoryPrintableText(lineSlice, useUtf16));
    }

    // 必须用 setRawText：这是目标内存的原始内容，绝不能被语言包按行翻译。
    m_driverMemoryTextView->setRawText(renderedText);
}

void MemoryDock::dumpDriverMemorySnapshotToFile()
{
    // 记录转存日志：这是一条会在磁盘留下目标内存内容的路径，必须可追溯。
    kLogEvent dumpEvent;
    info << dumpEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 请求把当前快照写入文件。"
        << eol;

    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // 默认文件名带上地址与长度，便于多次转存后区分。
    const QString defaultName = QStringLiteral("memory_%1_%2bytes.bin")
        .arg(formatAddress(m_driverMemoryBaseAddress))
        .arg(m_driverMemoryEditedBytes.size());
    const QString selectedPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("把当前内存快照转存到文件"),
        defaultName,
        QStringLiteral("二进制文件 (*.bin);;十六进制文本 (*.txt);;所有文件 (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(selectedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("无法写入文件: %1").arg(outputFile.errorString()));
        return;
    }

    // 按扩展名决定落盘格式：.txt 走可读的十六进制转储，其余一律原始字节。
    const bool asHexText = selectedPath.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive);
    qint64 writtenBytes = 0;
    if (asHexText)
    {
        // 十六进制文本格式与十六进制视图保持一致：地址 + 16 字节 + ASCII。
        QString dumpText;
        const qsizetype totalBytes = m_driverMemoryEditedBytes.size();
        for (qsizetype lineStart = 0; lineStart < totalBytes; lineStart += kDriverMemoryTextViewLineWidth)
        {
            const qsizetype lineBytes =
                std::min<qsizetype>(kDriverMemoryTextViewLineWidth, totalBytes - lineStart);
            const QByteArray lineSlice = m_driverMemoryEditedBytes.mid(lineStart, lineBytes);
            dumpText += QStringLiteral("%1  %2  %3\n")
                .arg(driverMemoryHexAddressText(
                    m_driverMemoryBaseAddress + static_cast<std::uint64_t>(lineStart)))
                .arg(driverMemoryBytesText(lineSlice), -47)
                .arg(driverMemoryPrintableText(lineSlice, false));
        }
        const QByteArray encodedText = dumpText.toUtf8();
        writtenBytes = outputFile.write(encodedText);
    }
    else
    {
        writtenBytes = outputFile.write(m_driverMemoryEditedBytes);
    }
    outputFile.close();

    if (writtenBytes < 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("写入过程中失败: %1").arg(outputFile.errorString()));
        return;
    }

    // 成功后把结果写进状态标签，避免再弹一个模态框打断操作。
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(
            QStringLiteral("已转存 %1 字节到 %2").arg(writtenBytes).arg(selectedPath));
    }

    kLogEvent dumpDoneEvent;
    info << dumpDoneEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 转存完成。"
        << eol;
}

void MemoryDock::writeStringIntoDriverMemoryBuffer()
{
    // 记录字符串写入日志：它会改动编辑缓存，属于会影响后续写回的操作。
    kLogEvent writeStringEvent;
    info << writeStringEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 打开字符串写入对话框。"
        << eol;

    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // 对话框结构：目标地址、编码、是否补结尾 0、字符串内容。
    QDialog stringDialog(this);
    stringDialog.setWindowTitle(QStringLiteral("字符串写入"));
    stringDialog.setModal(true);
    QVBoxLayout* dialogLayout = new QVBoxLayout(&stringDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);

    // 默认地址取十六进制视图当前光标位置，符合“选中哪里就写哪里”的直觉。
    const std::uint64_t defaultAddress = (m_driverMemoryHexEditor != nullptr)
        ? m_driverMemoryHexEditor->selectedAbsoluteAddress()
        : m_driverMemoryBaseAddress;
    QLineEdit* addressEdit = new QLineEdit(&stringDialog);
    addressEdit->setText(QStringLiteral("0x%1").arg(formatAddress(defaultAddress)));
    addressEdit->setToolTip(QStringLiteral("字符串写入的起始地址，必须落在当前快照范围内。"));

    QComboBox* encodingCombo = new QComboBox(&stringDialog);
    encodingCombo->addItem(QStringLiteral("ANSI / UTF-8 单字节"));
    encodingCombo->addItem(QStringLiteral("UTF-16LE 宽字符"));
    encodingCombo->setToolTip(QStringLiteral("选择字符串在目标内存里的编码方式。"));

    QCheckBox* nullTerminatedCheck = new QCheckBox(
        QStringLiteral("末尾补写结尾 0"), &stringDialog);
    nullTerminatedCheck->setChecked(true);
    nullTerminatedCheck->setToolTip(
        QStringLiteral("勾选后在字符串末尾补一个结尾 0，符合 C 字符串约定。"));

    QLineEdit* contentEdit = new QLineEdit(&stringDialog);
    contentEdit->setPlaceholderText(QStringLiteral("要写入的字符串内容"));
    contentEdit->setToolTip(QStringLiteral("按上面选定的编码转成字节后填入编辑缓存。"));

    formLayout->addWidget(new QLabel(QStringLiteral("起始地址"), &stringDialog), 0, 0);
    formLayout->addWidget(addressEdit, 0, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("编码"), &stringDialog), 1, 0);
    formLayout->addWidget(encodingCombo, 1, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("内容"), &stringDialog), 2, 0);
    formLayout->addWidget(contentEdit, 2, 1);
    formLayout->addWidget(nullTerminatedCheck, 3, 1);
    dialogLayout->addLayout(formLayout);

    // 明确告知：这一步只改编辑缓存，真正写回仍需点“应用差异”。
    QLabel* hintLabel = new QLabel(
        QStringLiteral("字符串只填入本地编辑缓存，确认无误后再点“应用差异到真实内存”。"),
        &stringDialog);
    hintLabel->setWordWrap(true);
    dialogLayout->addWidget(hintLabel);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &stringDialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("填入缓存"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    dialogLayout->addWidget(buttonBox);
    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &stringDialog, &QDialog::accept);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &stringDialog, &QDialog::reject);

    if (stringDialog.exec() != QDialog::Accepted)
    {
        return;
    }

    // 解析起始地址，越界一律拒绝，绝不静默截断。
    std::uint64_t targetAddress = 0ULL;
    if (!parseAddressText(addressEdit->text(), targetAddress))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址解析失败，请填写十六进制地址。"));
        return;
    }
    if (targetAddress < m_driverMemoryBaseAddress)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址在当前快照范围之前，请重新填写。"));
        return;
    }

    // 按选定编码把字符串转成字节序列。
    const QString contentText = contentEdit->text();
    QByteArray payloadBytes;
    if (encodingCombo->currentIndex() == 1)
    {
        // UTF-16LE：逐个码元按小端展开，保持与目标内存布局一致。
        for (const QChar contentChar : contentText)
        {
            const std::uint16_t codeUnit = contentChar.unicode();
            payloadBytes.append(static_cast<char>(codeUnit & 0xFFU));
            payloadBytes.append(static_cast<char>((codeUnit >> 8) & 0xFFU));
        }
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
            payloadBytes.append('\0');
        }
    }
    else
    {
        payloadBytes = contentText.toUtf8();
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
        }
    }

    if (payloadBytes.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("内容为空，没有可写入的字节。"));
        return;
    }

    // 校验整段字节都落在快照内，越界直接拒绝，避免部分写入造成半截字符串。
    const std::uint64_t writeOffset = targetAddress - m_driverMemoryBaseAddress;
    const std::uint64_t snapshotSize = static_cast<std::uint64_t>(m_driverMemoryEditedBytes.size());
    if (writeOffset >= snapshotSize
        || (snapshotSize - writeOffset) < static_cast<std::uint64_t>(payloadBytes.size()))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("字符串长度超出当前快照范围，请扩大读取范围或换一个起始地址。"));
        return;
    }

    // 写入编辑缓存，并同步刷新十六进制视图，让改动立刻可见。
    for (qsizetype byteIndex = 0; byteIndex < payloadBytes.size(); ++byteIndex)
    {
        m_driverMemoryEditedBytes[static_cast<qsizetype>(writeOffset) + byteIndex] =
            payloadBytes.at(byteIndex);
    }
    if (m_driverMemoryHexEditor != nullptr)
    {
        m_driverMemoryHexEditor->setByteArray(m_driverMemoryEditedBytes, m_driverMemoryBaseAddress);
        m_driverMemoryHexEditor->jumpToAbsoluteAddress(targetAddress);
    }
    refreshDriverMemoryViewsFromSnapshot();

    // 重新统计差异块并据此决定“应用差异”按钮是否可用。
    std::vector<DriverDiffBlock> diffBlocks;
    collectDriverMemoryDiffBlocks(diffBlocks);
    if (m_driverMemoryApplyButton != nullptr)
    {
        m_driverMemoryApplyButton->setEnabled(!diffBlocks.empty());
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(
            QStringLiteral("已在 0x%1 填入 %2 字节字符串，当前共 %3 处差异待应用。")
                .arg(formatAddress(targetAddress))
                .arg(payloadBytes.size())
                .arg(diffBlocks.size()));
    }

    kLogEvent writeStringDoneEvent;
    info << writeStringDoneEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 字符串已填入编辑缓存。"
        << eol;
}

void MemoryDock::showDriverMemoryDisassemblyContextMenu(const QPoint& localPosition)
{
    if (m_driverMemoryDisasmTable == nullptr)
    {
        return;
    }

    // 右键先把点击行设为当前行，保证复制动作严格针对用户看到的那一行。
    const QModelIndex clickedIndex = m_driverMemoryDisasmTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_driverMemoryDisasmTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
    }

    const int currentRow = m_driverMemoryDisasmTable->currentRow();
    const bool hasRow = (currentRow >= 0 && currentRow < m_driverMemoryDisasmRows.size());

    QMenu menu(m_driverMemoryDisasmTable);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyAddressAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")), QStringLiteral("复制地址"));
    QAction* copyBytesAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")), QStringLiteral("复制原始字节"));
    QAction* copyLineAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制整条指令"));
    menu.addSeparator();
    QAction* jumpHexAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), QStringLiteral("在十六进制视图中定位"));
    copyAddressAction->setEnabled(hasRow);
    copyBytesAction->setEnabled(hasRow);
    copyLineAction->setEnabled(hasRow);
    jumpHexAction->setEnabled(hasRow);

    QAction* selectedAction = menu.exec(
        m_driverMemoryDisasmTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr || !hasRow)
    {
        return;
    }

    const ks::ui::DisassemblyRow& disasmRow = m_driverMemoryDisasmRows.at(currentRow);
    QClipboard* clipboard = QApplication::clipboard();
    if (selectedAction == copyAddressAction && clipboard != nullptr)
    {
        clipboard->setText(driverMemoryHexAddressText(disasmRow.address));
    }
    else if (selectedAction == copyBytesAction && clipboard != nullptr)
    {
        clipboard->setText(driverMemoryBytesText(disasmRow.bytes));
    }
    else if (selectedAction == copyLineAction && clipboard != nullptr)
    {
        // 整条指令按“地址 字节 助记符 操作数”拼成一行，方便贴进笔记。
        clipboard->setText(QStringLiteral("%1  %2  %3 %4")
            .arg(driverMemoryHexAddressText(disasmRow.address))
            .arg(driverMemoryBytesText(disasmRow.bytes))
            .arg(disasmRow.mnemonic)
            .arg(disasmRow.operands));
    }
    else if (selectedAction == jumpHexAction)
    {
        // 切回十六进制视图并把光标停在该指令首字节上。
        applyDriverMemoryViewMode(DriverMemoryViewMode::Hex);
        if (m_driverMemoryHexEditor != nullptr)
        {
            m_driverMemoryHexEditor->jumpToAbsoluteAddress(disasmRow.address);
        }
    }
}
