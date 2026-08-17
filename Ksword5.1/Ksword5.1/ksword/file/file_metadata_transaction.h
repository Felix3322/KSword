#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

#include <Windows.h>
#include <AccCtrl.h>

#include <array>
#include <cstdint>

namespace ks::file::metadata
{
    enum class ChangeState
    {
        Unchanged,
        Disabled,
        Enabled
    };

    enum class BinaryPatchAction
    {
        Replace,
        Remove
    };

    enum class SignatureDisposition
    {
        Preserve,
        RemoveEmbedded
    };

    struct FileIdentity
    {
        bool available = false;
        DWORD volumeSerialNumber = 0U;
        std::uint64_t fileIndex = 0U;
    };

    struct FileSnapshot
    {
        bool ok = false;
        DWORD win32Error = ERROR_SUCCESS;
        FILE_BASIC_INFO basicInfo{};
        FileIdentity identity{};
        bool directory = false;
        bool embeddedSignature = false;
    };

    struct BasicPatch
    {
        std::array<bool, 4> updateTime{};
        std::array<LARGE_INTEGER, 4> timeValue{};
        bool updateAttributes = false;
        DWORD editableAttributes = 0U;
    };

    struct ShellPropertyPatch
    {
        bool updateTitle = false;
        QString title;
        bool updateSubject = false;
        QString subject;
        bool updateAuthors = false;
        QStringList authors;
        bool updateKeywords = false;
        QStringList keywords;
        bool updateComment = false;
        QString comment;
        bool updateCopyright = false;
        QString copyright;
        bool updateRating = false;
        quint32 rating = 0U;

        [[nodiscard]] bool empty() const;
    };

    struct NamedBinaryPatch
    {
        QString name;
        BinaryPatchAction action = BinaryPatchAction::Replace;
        QByteArray data;
        bool needEa = false;
    };

    struct SecurityAcePatch
    {
        QString trustee;
        DWORD accessMode = GRANT_ACCESS;
        DWORD accessMask = 0U;
        DWORD inheritance = NO_INHERITANCE;
    };

    struct SecurityAceRemoval
    {
        BYTE aceType = 0U;
        BYTE aceFlags = 0U;
        DWORD accessMask = 0U;
        QString sid;
    };

    struct SecurityPatch
    {
        bool replaceSddl = false;
        QString sddl;
        SECURITY_INFORMATION securityInformation = 0U;
        QList<SecurityAcePatch> aceChanges;
        QList<SecurityAceRemoval> aceRemovals;

        [[nodiscard]] bool empty() const;
    };

    struct ObjectIdPatch
    {
        bool update = false;
        bool remove = false;
        QByteArray objectId;
    };

    struct ReparsePatch
    {
        bool update = false;
        bool remove = false;
        QByteArray rawBuffer;
    };

    struct PeResourcePatch
    {
        QString type;
        QString name;
        WORD language = 0U;
        BinaryPatchAction action = BinaryPatchAction::Replace;
        QByteArray data;
    };

    struct TargetPatch
    {
        QString originalPath;
        FileSnapshot snapshot;
        BasicPatch basic;

        bool rename = false;
        QString newName;
        bool setShortName = false;
        QString shortName;
        ChangeState caseSensitive = ChangeState::Unchanged;

        ShellPropertyPatch shellProperties;
        QList<NamedBinaryPatch> streams;
        QList<NamedBinaryPatch> extendedAttributes;
        SecurityPatch security;

        ChangeState compression = ChangeState::Unchanged;
        ChangeState sparse = ChangeState::Unchanged;
        ChangeState encryption = ChangeState::Unchanged;
        ChangeState integrityStream = ChangeState::Unchanged;
        ObjectIdPatch objectId;
        QStringList hardLinkPaths;
        ReparsePatch reparse;
        QList<PeResourcePatch> peResources;
        SignatureDisposition signatureDisposition = SignatureDisposition::Preserve;

        [[nodiscard]] bool empty() const;
        [[nodiscard]] bool highRisk() const;
        [[nodiscard]] bool invalidatesAuthenticode() const;
    };

    struct OperationResult
    {
        QString operation;
        bool ok = false;
        bool verified = false;
        DWORD win32Error = ERROR_SUCCESS;
        QString detail;
    };

    struct TargetResult
    {
        QString originalPath;
        QString finalPath;
        QString backupPath;
        bool ok = false;
        bool rollbackAttempted = false;
        bool rollbackOk = false;
        QList<OperationResult> operations;
        FileSnapshot finalSnapshot;
    };

    struct TransactionOptions
    {
        bool createBackup = true;
        QString backupRoot;
    };

    struct TransactionResult
    {
        bool ok = false;
        QString backupRoot;
        QList<TargetResult> targets;
    };

    struct StreamEntry
    {
        QString name;
        quint64 size = 0U;
    };

    struct ExtendedAttributeEntry
    {
        QString name;
        QByteArray value;
        bool needEa = false;
    };

    struct ShellProperties
    {
        bool ok = false;
        DWORD win32Error = ERROR_SUCCESS;
        QString title;
        QString subject;
        QStringList authors;
        QStringList keywords;
        QString comment;
        QString copyright;
        quint32 rating = 0U;
    };

    struct SignatureInspection
    {
        bool embedded = false;
        bool catalog = false;
        LONG trustStatus = TRUST_E_NOSIGNATURE;
        QString catalogPath;
        QString signer;
        QString issuer;
        QString sha256Fingerprint;
        QString validFrom;
        QString validUntil;
        QString timestampSigner;
        QString chainStatus;
    };

    [[nodiscard]] DWORD editableFileAttributeMask();
    [[nodiscard]] const std::array<DWORD, 6>& editableFileAttributeMasks();
    [[nodiscard]] FileSnapshot readFileSnapshot(const QString& filePath);
    [[nodiscard]] QList<StreamEntry> enumerateStreams(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] QByteArray readStream(const QString& filePath, const QString& streamName, DWORD* errorOut = nullptr);
    [[nodiscard]] QList<ExtendedAttributeEntry> enumerateExtendedAttributes(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] ShellProperties readShellProperties(const QString& filePath);
    [[nodiscard]] QString readSecurityDescriptorSddl(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] DWORD queryEffectiveAccessMask(
        const QString& filePath,
        const QString& trustee,
        DWORD* accessMaskOut);
    [[nodiscard]] QByteArray readRawReparseData(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] QByteArray readObjectId(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] QStringList enumerateHardLinks(const QString& filePath, DWORD* errorOut = nullptr);
    [[nodiscard]] QByteArray readPeResource(
        const QString& filePath,
        const QString& type,
        const QString& name,
        WORD language,
        DWORD* errorOut = nullptr);
    [[nodiscard]] SignatureInspection inspectSignature(const QString& filePath);
    [[nodiscard]] TransactionResult executeTransaction(
        const QList<TargetPatch>& patches,
        const TransactionOptions& options);
}
