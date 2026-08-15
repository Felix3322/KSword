#include "./HandleFilterConfig.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QUuid>

#include <limits>

namespace
{
    QString enumModeToText(const ks::handle::FilterEnumMode mode)
    {
        switch (mode)
        {
        case ks::handle::FilterEnumMode::UserSnapshot:
            return QStringLiteral("user_snapshot");
        case ks::handle::FilterEnumMode::KernelHandleTable:
            return QStringLiteral("kernel_handle_table");
        case ks::handle::FilterEnumMode::DuplicateHandle:
        default:
            return QStringLiteral("duplicate_handle");
        }
    }

    bool enumModeFromText(
        const QString& sourceText,
        ks::handle::FilterEnumMode* modeOut)
    {
        if (modeOut == nullptr)
        {
            return false;
        }
        const QString normalizedText = sourceText.trimmed().toLower();
        if (normalizedText == QStringLiteral("user_snapshot"))
        {
            *modeOut = ks::handle::FilterEnumMode::UserSnapshot;
            return true;
        }
        if (normalizedText == QStringLiteral("duplicate_handle"))
        {
            *modeOut = ks::handle::FilterEnumMode::DuplicateHandle;
            return true;
        }
        if (normalizedText == QStringLiteral("kernel_handle_table"))
        {
            *modeOut = ks::handle::FilterEnumMode::KernelHandleTable;
            return true;
        }
        return false;
    }

    QString diffStatusToText(const ks::handle::FilterDiffStatus status)
    {
        switch (status)
        {
        case ks::handle::FilterDiffStatus::UserOnly:
            return QStringLiteral("user_only");
        case ks::handle::FilterDiffStatus::KernelOnly:
            return QStringLiteral("kernel_only");
        case ks::handle::FilterDiffStatus::Both:
            return QStringLiteral("both");
        case ks::handle::FilterDiffStatus::Any:
        default:
            return QStringLiteral("any");
        }
    }

    bool diffStatusFromText(
        const QString& sourceText,
        ks::handle::FilterDiffStatus* statusOut)
    {
        if (statusOut == nullptr)
        {
            return false;
        }
        const QString normalizedText = sourceText.trimmed().toLower();
        if (normalizedText == QStringLiteral("any"))
        {
            *statusOut = ks::handle::FilterDiffStatus::Any;
            return true;
        }
        if (normalizedText == QStringLiteral("user_only"))
        {
            *statusOut = ks::handle::FilterDiffStatus::UserOnly;
            return true;
        }
        if (normalizedText == QStringLiteral("kernel_only"))
        {
            *statusOut = ks::handle::FilterDiffStatus::KernelOnly;
            return true;
        }
        if (normalizedText == QStringLiteral("both"))
        {
            *statusOut = ks::handle::FilterDiffStatus::Both;
            return true;
        }
        return false;
    }

    QJsonObject buildRuleObject(const ks::handle::HandleFilterRule& rule)
    {
        QJsonObject ruleObject;
        ruleObject.insert(QStringLiteral("id"), rule.id);
        ruleObject.insert(QStringLiteral("name"), rule.name);
        ruleObject.insert(QStringLiteral("enabled"), rule.enabled);

        QJsonArray processIdArray;
        for (const std::uint32_t processId : rule.processIds)
        {
            processIdArray.push_back(static_cast<qint64>(processId));
        }
        ruleObject.insert(QStringLiteral("processIds"), processIdArray);
        ruleObject.insert(QStringLiteral("keyword"), rule.keyword);
        ruleObject.insert(QStringLiteral("typeName"), rule.typeName);
        ruleObject.insert(QStringLiteral("diffStatus"), diffStatusToText(rule.diffStatus));
        ruleObject.insert(QStringLiteral("onlyNamed"), rule.onlyNamed);
        return ruleObject;
    }
}

namespace ks::handle
{
    QString CreateHandleFilterRuleId()
    {
        return QUuid::createUuid().toString(QUuid::WithoutBraces);
    }

    QString MakeUniqueHandleFilterRuleName(
        const QString& requestedName,
        const QVector<HandleFilterRule>& existingRules,
        const QString& ignoredRuleId)
    {
        const QString baseName = requestedName.trimmed().isEmpty()
            ? QStringLiteral("规则")
            : requestedName.trimmed();
        auto nameExists = [&existingRules, &ignoredRuleId](const QString& candidateName)
        {
            for (const HandleFilterRule& rule : existingRules)
            {
                if (!ignoredRuleId.isEmpty() && rule.id == ignoredRuleId)
                {
                    continue;
                }
                if (rule.name.compare(candidateName, Qt::CaseInsensitive) == 0)
                {
                    return true;
                }
            }
            return false;
        };

        if (!nameExists(baseName))
        {
            return baseName;
        }
        for (int suffixIndex = 1; suffixIndex < 100000; ++suffixIndex)
        {
            const QString candidateName = QStringLiteral("%1（导入 %2）")
                .arg(baseName)
                .arg(suffixIndex);
            if (!nameExists(candidateName))
            {
                return candidateName;
            }
        }
        return baseName + QStringLiteral("（导入）");
    }

    HandleFilterDocument CreateDefaultHandleFilterDocument()
    {
        HandleFilterDocument document;
        HandleFilterRule defaultRule;
        defaultRule.id = CreateHandleFilterRuleId();
        defaultRule.name = QStringLiteral("全部句柄");
        document.rules.push_back(defaultRule);
        return document;
    }

    QByteArray SerializeHandleFilterDocument(
        const HandleFilterDocument& document,
        QString* errorTextOut)
    {
        if (document.schemaVersion != HandleFilterSchemaVersion)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("不支持的筛选器配置版本：%1")
                    .arg(document.schemaVersion);
            }
            return {};
        }

        QJsonObject rootObject;
        rootObject.insert(QStringLiteral("schemaVersion"), document.schemaVersion);
        rootObject.insert(
            QStringLiteral("exportedAtUtc"),
            document.exportedAtUtc.trimmed().isEmpty()
                ? QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)
                : document.exportedAtUtc);

        QJsonObject globalSettingsObject;
        globalSettingsObject.insert(
            QStringLiteral("enumMode"),
            enumModeToText(document.globalSettings.enumMode));
        globalSettingsObject.insert(
            QStringLiteral("resolveObjectName"),
            document.globalSettings.resolveObjectName);
        globalSettingsObject.insert(
            QStringLiteral("nameResolveBudget"),
            document.globalSettings.nameResolveBudget);
        rootObject.insert(QStringLiteral("globalSettings"), globalSettingsObject);

        QJsonArray ruleArray;
        for (const HandleFilterRule& rule : document.rules)
        {
            ruleArray.push_back(buildRuleObject(rule));
        }
        rootObject.insert(QStringLiteral("rules"), ruleArray);
        return QJsonDocument(rootObject).toJson(QJsonDocument::Indented);
    }

    bool DeserializeHandleFilterDocument(
        const QByteArray& jsonBytes,
        HandleFilterDocument* documentOut,
        QStringList* warningListOut,
        QString* errorTextOut)
    {
        if (documentOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置输出对象为空。");
            }
            return false;
        }

        QJsonParseError parseError;
        const QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonBytes, &parseError);
        if (parseError.error != QJsonParseError::NoError || !jsonDocument.isObject())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("JSON 解析失败：%1").arg(parseError.errorString());
            }
            return false;
        }

        const QJsonObject rootObject = jsonDocument.object();
        const QJsonValue schemaVersionValue = rootObject.value(QStringLiteral("schemaVersion"));
        if (!schemaVersionValue.isDouble())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置版本 %1 与当前版本 %2 不兼容。")
                    .arg(0)
                    .arg(HandleFilterSchemaVersion);
            }
            return false;
        }
        const int schemaVersion = schemaVersionValue.toInt(0);
        if (schemaVersionValue.toDouble() != static_cast<double>(schemaVersion))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置格式无效。");
            }
            return false;
        }
        if (schemaVersion != HandleFilterSchemaVersion)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置版本 %1 与当前版本 %2 不兼容。")
                    .arg(schemaVersion)
                    .arg(HandleFilterSchemaVersion);
            }
            return false;
        }
        if (!rootObject.value(QStringLiteral("globalSettings")).isObject()
            || !rootObject.value(QStringLiteral("rules")).isArray())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置缺少 globalSettings 或 rules。");
            }
            return false;
        }

        HandleFilterDocument parsedDocument;
        parsedDocument.schemaVersion = schemaVersion;
        const QJsonValue exportedAtValue = rootObject.value(QStringLiteral("exportedAtUtc"));
        QDateTime exportedAtUtc;
        if (exportedAtValue.isString())
        {
            exportedAtUtc = QDateTime::fromString(exportedAtValue.toString(), Qt::ISODateWithMs);
            if (!exportedAtUtc.isValid())
            {
                exportedAtUtc = QDateTime::fromString(exportedAtValue.toString(), Qt::ISODate);
            }
        }
        if (!exportedAtUtc.isValid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置格式无效。");
            }
            return false;
        }
        parsedDocument.exportedAtUtc = exportedAtValue.toString();

        const QJsonObject globalSettingsObject =
            rootObject.value(QStringLiteral("globalSettings")).toObject();
        const QJsonValue enumModeValue = globalSettingsObject.value(QStringLiteral("enumMode"));
        FilterEnumMode enumMode = FilterEnumMode::DuplicateHandle;
        if (!enumModeValue.isString() || !enumModeFromText(enumModeValue.toString(), &enumMode))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("globalSettings.enumMode 无效。");
            }
            return false;
        }
        parsedDocument.globalSettings.enumMode = enumMode;
        const QJsonValue resolveNameValue =
            globalSettingsObject.value(QStringLiteral("resolveObjectName"));
        const QJsonValue nameBudgetValue =
            globalSettingsObject.value(QStringLiteral("nameResolveBudget"));
        if (!resolveNameValue.isBool() || !nameBudgetValue.isDouble())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }
        const qint64 parsedNameBudget = nameBudgetValue.toInteger(-1);
        if (nameBudgetValue.toDouble() != static_cast<double>(parsedNameBudget))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }
        parsedDocument.globalSettings.resolveObjectName = resolveNameValue.toBool();
        parsedDocument.globalSettings.nameResolveBudget = static_cast<int>(parsedNameBudget);
        if (parsedDocument.globalSettings.nameResolveBudget < 0
            || parsedDocument.globalSettings.nameResolveBudget > 10000)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }

        const QJsonArray ruleArray = rootObject.value(QStringLiteral("rules")).toArray();
        QSet<QString> usedIds;
        for (qsizetype ruleIndex = 0; ruleIndex < ruleArray.size(); ++ruleIndex)
        {
            if (!ruleArray.at(ruleIndex).isObject())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            const QJsonObject ruleObject = ruleArray.at(ruleIndex).toObject();
            HandleFilterRule rule;
            const QJsonValue idValue = ruleObject.value(QStringLiteral("id"));
            const QJsonValue nameValue = ruleObject.value(QStringLiteral("name"));
            const QJsonValue enabledValue = ruleObject.value(QStringLiteral("enabled"));
            const QJsonValue keywordValue = ruleObject.value(QStringLiteral("keyword"));
            const QJsonValue typeNameValue = ruleObject.value(QStringLiteral("typeName"));
            const QJsonValue diffStatusValue = ruleObject.value(QStringLiteral("diffStatus"));
            const QJsonValue onlyNamedValue = ruleObject.value(QStringLiteral("onlyNamed"));
            if (!idValue.isString()
                || !nameValue.isString()
                || !enabledValue.isBool()
                || !keywordValue.isString()
                || !typeNameValue.isString()
                || !diffStatusValue.isString()
                || !onlyNamedValue.isBool())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            rule.id = idValue.toString().trimmed();
            const QUuid parsedId(rule.id);
            if (rule.id.isEmpty() || parsedId.isNull() || usedIds.contains(rule.id))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则的 ID 无效或重复。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            usedIds.insert(rule.id);

            const QString requestedName = nameValue.toString().trimmed();
            if (requestedName.isEmpty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            rule.name = MakeUniqueHandleFilterRuleName(
                requestedName,
                parsedDocument.rules);
            if (rule.name != requestedName.trimmed() && warningListOut != nullptr)
            {
                warningListOut->push_back(
                    QStringLiteral("规则名称“%1”已调整为“%2”。")
                    .arg(requestedName, rule.name));
            }
            rule.enabled = enabledValue.toBool();
            rule.keyword = keywordValue.toString().trimmed();
            rule.typeName = typeNameValue.toString().trimmed();
            rule.onlyNamed = onlyNamedValue.toBool();

            FilterDiffStatus diffStatus = FilterDiffStatus::Any;
            if (!diffStatusFromText(
                diffStatusValue.toString(),
                &diffStatus))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("规则“%1”的 diffStatus 无效。").arg(rule.name);
                }
                return false;
            }
            rule.diffStatus = diffStatus;

            if (!ruleObject.value(QStringLiteral("processIds")).isArray())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("规则“%1”的 processIds 无效。").arg(rule.name);
                }
                return false;
            }
            QSet<std::uint32_t> seenProcessIds;
            const QJsonArray processIdArray = ruleObject.value(QStringLiteral("processIds")).toArray();
            for (const QJsonValue& processIdValue : processIdArray)
            {
                if (!processIdValue.isDouble())
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("规则“%1”包含无效 PID。").arg(rule.name);
                    }
                    return false;
                }
                const qint64 processId = processIdValue.toInteger(-1);
                if (processIdValue.toDouble() != static_cast<double>(processId)
                    || processId <= 0
                    || processId > static_cast<qint64>(std::numeric_limits<std::uint32_t>::max()))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("规则“%1”包含无效 PID。").arg(rule.name);
                    }
                    return false;
                }
                const std::uint32_t normalizedProcessId = static_cast<std::uint32_t>(processId);
                if (!seenProcessIds.contains(normalizedProcessId))
                {
                    seenProcessIds.insert(normalizedProcessId);
                    rule.processIds.push_back(normalizedProcessId);
                }
            }
            parsedDocument.rules.push_back(std::move(rule));
        }

        *documentOut = std::move(parsedDocument);
        return true;
    }
}
