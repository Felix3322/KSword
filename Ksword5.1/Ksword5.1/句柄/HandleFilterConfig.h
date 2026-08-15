#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

#include <cstdint>

namespace ks::handle
{
    constexpr int HandleFilterSchemaVersion = 1;

    enum class FilterEnumMode : int
    {
        UserSnapshot = 0,
        DuplicateHandle,
        KernelHandleTable
    };

    enum class FilterDiffStatus : int
    {
        Any = 0,
        UserOnly,
        KernelOnly,
        Both
    };

    struct HandleFilterGlobalSettings
    {
        FilterEnumMode enumMode = FilterEnumMode::DuplicateHandle;
        bool resolveObjectName = true;
        int nameResolveBudget = 1000;
    };

    struct HandleFilterRule
    {
        QString id;
        QString name;
        bool enabled = true;
        QVector<std::uint32_t> processIds;
        QString keyword;
        QString typeName;
        FilterDiffStatus diffStatus = FilterDiffStatus::Any;
        bool onlyNamed = false;
    };

    struct HandleFilterDocument
    {
        int schemaVersion = HandleFilterSchemaVersion;
        QString exportedAtUtc;
        HandleFilterGlobalSettings globalSettings;
        QVector<HandleFilterRule> rules;
    };

    HandleFilterDocument CreateDefaultHandleFilterDocument();
    QString CreateHandleFilterRuleId();
    QString MakeUniqueHandleFilterRuleName(
        const QString& requestedName,
        const QVector<HandleFilterRule>& existingRules,
        const QString& ignoredRuleId = QString());

    QByteArray SerializeHandleFilterDocument(
        const HandleFilterDocument& document,
        QString* errorTextOut = nullptr);

    bool DeserializeHandleFilterDocument(
        const QByteArray& jsonBytes,
        HandleFilterDocument* documentOut,
        QStringList* warningListOut = nullptr,
        QString* errorTextOut = nullptr);
}
